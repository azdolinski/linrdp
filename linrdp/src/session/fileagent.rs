//! The clipboard's file operations, performed as the session's own user.
//!
//! A worker is root. It has to be: it reads `/etc/shadow`, opens PAM
//! sessions, and forks keepers. But it also handles the clipboard, and the
//! clipboard is the one channel where the *session* — a program running on
//! somebody's desktop — names files for the worker to open, and a remote
//! client names files for the worker to create.
//!
//! Doing either as root is a privilege boundary violation, and both were:
//!
//! - Linux → Windows. A program in the session put a `file://` URI on the X11
//!   clipboard; the poller stat'd it as root, advertised it, and served its
//!   contents to the RDP client from a root `File::open`. The user never
//!   needed read permission on the file — naming it was enough. `/etc/shadow`
//!   was one paste away.
//!
//! - Windows → Linux. Pasted files landed in `/tmp/linrdp-paste-<n>` with `n`
//!   starting at zero in every worker, so two sessions shared a directory and
//!   the same file name in both meant one truncating the other's download. The
//!   directory carried whatever `umask` gave it, and a local user could
//!   pre-create it with symlinks inside — which a textual path check cannot
//!   see through, because the following happens in the kernel at `open`.
//!
//! So the worker stops touching those files. This module starts one helper
//! process per session, running as the session user with the session user's
//! groups, and asks it to do the opening. What comes back is a **file
//! descriptor**, passed over a Unix socket with `SCM_RIGHTS`: the permission
//! check happened at `open`, with the user's credentials, on the path the
//! kernel actually resolved. The worker then reads and writes through that
//! descriptor, which cannot be redirected afterwards — no `access()`-then-
//! `open()` window, because there is no second resolution.
//!
//! Requests that create files go through a private per-session directory the
//! helper makes for itself (`mkdir` with a random name, mode 0700, exclusive),
//! and every path component under it is opened with `O_NOFOLLOW`, so a
//! symlink anywhere along the way is an error rather than a redirection.

use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// The largest frame either side will read.
///
/// A frame is a path or a nine-byte answer; anything larger is a protocol
/// error, not a request to allocate.
const MAX_FRAME: u32 = 64 * 1024;

/// The descriptor the helper finds its socket on.
///
/// 0, 1 and 2 are the standard streams and 3 is where the supervisor puts a
/// worker's accepted connection, so 4 is the first number nothing else claims.
pub(crate) const AGENT_SOCKET_FD: RawFd = 4;

/// What the worker can ask the helper to do.
///
/// Deliberately small. Every operation the clipboard needs on a user's files
/// is one of these, and nothing here takes a path the helper then re-resolves
/// later — the answer to "which file is this" is fixed at the moment of the
/// `open` that produced the descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Op {
    /// Is this an ordinary file, and how large? (absolute path)
    Stat = 1,
    /// Open for reading and hand the descriptor back. (absolute path)
    OpenRead = 2,
    /// Where the private per-session paste directory is. (no payload)
    PasteDir = 3,
    /// Make a directory under the paste directory. (relative path)
    MakeDir = 4,
    /// Create a file under the paste directory and hand the descriptor back.
    /// (relative path)
    CreateFile = 5,
    /// Remove a file under the paste directory. (relative path)
    Remove = 6,
}

impl Op {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Stat,
            2 => Self::OpenRead,
            3 => Self::PasteDir,
            4 => Self::MakeDir,
            5 => Self::CreateFile,
            6 => Self::Remove,
            _ => return None,
        })
    }

    /// Whether a successful reply carries a descriptor.
    fn returns_fd(self) -> bool {
        matches!(self, Self::OpenRead | Self::CreateFile)
    }
}

/// What `Stat` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileFacts {
    pub(crate) is_file: bool,
    pub(crate) size: u64,
}

/// A running helper, and the socket to it.
#[derive(Debug)]
pub(crate) struct FileAgent {
    socket: UnixStream,
    pid: i32,
    /// The account the helper is running as, for the log.
    user: String,
}

impl Drop for FileAgent {
    fn drop(&mut self) {
        // Closing the socket is the helper's cue to exit; the wait keeps it
        // from lingering as a zombie of this worker.
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        if self.pid > 0 {
            let mut status = 0;
            // SAFETY: waiting on a child this process spawned.
            unsafe { libc::waitpid(self.pid, &mut status, 0) };
        }
    }
}

impl FileAgent {
    /// Start a helper running as `user`.
    ///
    /// The helper is a fresh `exec` of this binary rather than a plain `fork`
    /// on purpose: by the time the clipboard channel is ready the worker has a
    /// multi-threaded tokio runtime, and a forked child of that inherits locks
    /// held by threads that no longer exist. `exec` replaces the address space,
    /// so none of that follows it.
    pub(crate) fn start(user: &str) -> anyhow::Result<Self> {
        use std::os::unix::process::CommandExt as _;

        let mut pair = [0i32; 2];
        // SAFETY: a two-element array, which is what socketpair(2) fills in.
        // SOCK_CLOEXEC on both ends. Without it the helper inherits a copy of
        // the *worker's* end, which would keep its own end from ever reporting
        // EOF: a worker that died without running `Drop` would leave a helper
        // waiting for a request that can never come.
        let paired = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        };
        anyhow::ensure!(
            paired == 0,
            "socketpair for the file helper: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a descriptor socketpair just created, owned from here.
        let ours = unsafe { UnixStream::from_raw_fd(pair[0]) };
        // SAFETY: the other end of the same pair, likewise owned from here.
        let theirs = unsafe { UnixStream::from_raw_fd(pair[1]) };
        let theirs_fd = theirs.into_raw_fd();

        let exe = std::env::current_exe().context("locate the linrdp binary")?;
        // SAFETY: `pre_exec` is unsafe because its closure runs between fork
        // and exec; this one calls only dup2 and fcntl, both async-signal-safe,
        // and allocates nothing.
        let spawned = unsafe {
            std::process::Command::new(exe)
                .arg("--file-agent")
                .arg("--file-agent-user")
                .arg(user)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .pre_exec(move || {
                    // SAFETY: between fork and exec; dup2 and fcntl are
                    // async-signal-safe and nothing here allocates.
                    if libc::dup2(theirs_fd, AGENT_SOCKET_FD) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    // dup2 clears FD_CLOEXEC on the copy — except when the two
                    // numbers are equal, where POSIX says it does nothing.
                    if libc::fcntl(AGENT_SOCKET_FD, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                })
                .spawn()
        };
        // SAFETY: this process's copy of the helper's end; the child has its
        // own now, and holding ours open would keep the socket from ever
        // reporting EOF.
        unsafe { libc::close(theirs_fd) };
        let child = spawned.context("spawn the file helper")?;

        let mut agent = Self {
            socket: ours,
            pid: i32::try_from(child.id()).unwrap_or(-1),
            user: user.to_owned(),
        };
        // Prove it came up *and* became the right account before anything
        // relies on it: a helper that failed to drop privileges must never be
        // asked to open a file.
        let dir = agent.paste_dir().context("the file helper did not answer")?;
        tracing::info!(
            user,
            pid = agent.pid,
            dir = %dir.display(),
            "clipboard file helper running as the session user"
        );
        Ok(agent)
    }

    /// Whether `path` is an ordinary file the session user can see, and how
    /// large it is.
    pub(crate) fn stat(&mut self, path: &Path) -> anyhow::Result<FileFacts> {
        let (payload, _fd) = self.ask(Op::Stat, path.as_os_str().as_encoded_bytes())?;
        anyhow::ensure!(payload.len() == 9, "malformed stat reply");
        Ok(FileFacts {
            is_file: payload[0] == 1,
            size: u64::from_le_bytes(payload[1..9].try_into().expect("nine bytes, checked")),
        })
    }

    /// Open `path` for reading **as the session user** and return the file.
    pub(crate) fn open_read(&mut self, path: &Path) -> anyhow::Result<std::fs::File> {
        let (_payload, fd) = self.ask(Op::OpenRead, path.as_os_str().as_encoded_bytes())?;
        let fd = fd.context("the helper returned no descriptor")?;
        // SAFETY: a descriptor received over SCM_RIGHTS, owned from here.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// The private directory pasted files are written into.
    pub(crate) fn paste_dir(&mut self) -> anyhow::Result<PathBuf> {
        let (payload, _fd) = self.ask(Op::PasteDir, &[])?;
        Ok(PathBuf::from(String::from_utf8_lossy(&payload).into_owned()))
    }

    /// Create a directory under the paste directory.
    pub(crate) fn make_dir(&mut self, relative: &Path) -> anyhow::Result<()> {
        self.ask(Op::MakeDir, relative.as_os_str().as_encoded_bytes())?;
        Ok(())
    }

    /// Create a file under the paste directory and return it for writing.
    pub(crate) fn create_file(&mut self, relative: &Path) -> anyhow::Result<std::fs::File> {
        let (_payload, fd) = self.ask(Op::CreateFile, relative.as_os_str().as_encoded_bytes())?;
        let fd = fd.context("the helper returned no descriptor")?;
        // SAFETY: a descriptor received over SCM_RIGHTS, owned from here.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// Remove a file under the paste directory (a partial download).
    pub(crate) fn remove(&mut self, relative: &Path) -> anyhow::Result<()> {
        self.ask(Op::Remove, relative.as_os_str().as_encoded_bytes())?;
        Ok(())
    }

    /// One request, one reply. Synchronous by design: the caller is either the
    /// clipboard poller or the cliprdr callback, and neither has more than one
    /// question in flight.
    fn ask(&mut self, op: Op, payload: &[u8]) -> anyhow::Result<(Vec<u8>, Option<RawFd>)> {
        write_frame(&mut self.socket, op as u8, payload)
            .with_context(|| format!("ask the file helper for {} ({op:?})", self.user))?;
        let (status, body, fd) = read_reply(&mut self.socket, op.returns_fd())?;
        if status != 0 {
            anyhow::bail!("{}", String::from_utf8_lossy(&body));
        }
        Ok((body, fd))
    }
}

// ------------------------------------------------------------ the framing

fn write_frame(sink: &mut UnixStream, tag: u8, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::other("payload too large for one frame"))?;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(tag);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(payload);
    sink.write_all(&frame)
}

fn read_frame(source: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    source.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header[1..5].try_into().expect("four bytes"));
    if len > MAX_FRAME {
        return Err(std::io::Error::other(format!("frame of {len} bytes is beyond the limit")));
    }
    let mut body = vec![0u8; len as usize];
    source.read_exact(&mut body)?;
    Ok((header[0], body))
}

/// Read a reply, collecting a descriptor from its ancillary data when the
/// operation is one that returns one.
fn read_reply(source: &mut UnixStream, expect_fd: bool) -> anyhow::Result<(u8, Vec<u8>, Option<RawFd>)> {
    if !expect_fd {
        let (status, body) = read_frame(source).context("read the helper's reply")?;
        return Ok((status, body, None));
    }
    // The descriptor rides on the FIRST byte of the message, so exactly one
    // byte is taken with `recvmsg` — ancillary data belongs to a message, and
    // a plain read would discard it. One byte also cannot come back short,
    // which a five-byte `recvmsg` on a stream socket could.
    let mut status = [0u8; 1];
    let fd = recv_with_fd(source, &mut status)?;
    let mut len_bytes = [0u8; 4];
    source.read_exact(&mut len_bytes).context("read the helper's reply length")?;
    let len = u32::from_le_bytes(len_bytes);
    anyhow::ensure!(len <= MAX_FRAME, "reply of {len} bytes is beyond the limit");
    let mut body = vec![0u8; len as usize];
    if len > 0 {
        source.read_exact(&mut body).context("read the helper's reply body")?;
    }
    Ok((status[0], body, fd))
}

/// `sendmsg` with `buf` as the payload and `fd`, if given, as `SCM_RIGHTS`.
fn send_with_fd(socket: &UnixStream, buf: &[u8], fd: Option<RawFd>) -> std::io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: buf.len(),
    };
    // CMSG_SPACE for exactly one descriptor, as a suitably aligned buffer.
    let mut control = [0u64; 4];
    // SAFETY: msghdr is a plain C struct of integers and pointers, for which
    // all-zero is the documented "nothing set" state.
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    if let Some(fd) = fd {
        // SAFETY: the CMSG_* macros operate on the msghdr and control buffer
        // below, both of which live for the whole call; the space is
        // CMSG_SPACE(4) rounded up, which four u64s comfortably exceed.
        unsafe {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(4) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
            core::ptr::copy_nonoverlapping(&raw const fd, libc::CMSG_DATA(cmsg).cast::<RawFd>(), 1);
        }
    }
    // SAFETY: a valid msghdr describing buffers that outlive the call.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `recvmsg` filling `buf`, returning a descriptor if one rode along.
fn recv_with_fd(socket: &UnixStream, buf: &mut [u8]) -> anyhow::Result<Option<RawFd>> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    let mut control = [0u64; 4];
    // SAFETY: as above — all-zero is msghdr's "nothing set" state.
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE is a pure computation on a constant.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;

    // SAFETY: a valid msghdr describing buffers that outlive the call.
    let got = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut msg, 0) };
    if got < 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()).context("recvmsg from the file helper"));
    }
    anyhow::ensure!(
        usize::try_from(got).unwrap_or(0) == buf.len(),
        "the file helper's reply header was truncated"
    );

    // SAFETY: the kernel filled msg_control with well-formed cmsg headers.
    let fd = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            None
        } else {
            let mut fd: RawFd = -1;
            core::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg).cast::<RawFd>(), &raw mut fd, 1);
            (fd >= 0).then_some(fd)
        }
    };
    Ok(fd)
}

// -------------------------------------------------------- the helper itself

/// Run as the file helper: become `user`, then answer until the socket closes.
///
/// Never returns to anything that could act as root — the privilege drop is
/// the first thing it does, and a failure there ends the process rather than
/// serving a single request.
pub(crate) fn agent_main(user: &str) -> anyhow::Result<()> {
    let ids = super::privilege::lookup_user(user)?;
    // SAFETY: geteuid is always safe.
    if unsafe { libc::geteuid() } != ids.uid {
        super::privilege::drop_to(&ids)
            .with_context(|| format!("the file helper could not become {user}"))?;
    }

    // SAFETY: a descriptor the parent placed here before exec, owned from now
    // on and used by nothing else in this process.
    let socket = unsafe { UnixStream::from_raw_fd(AGENT_SOCKET_FD) };
    serve(socket, &ids)
}

/// Answer requests on `socket` until it closes.
///
/// Split from [`agent_main`] so the protocol — the framing and the descriptor
/// passing, which is the part with anything to get wrong — can be exercised
/// without a second process to become somebody else in.
fn serve(mut socket: UnixStream, ids: &super::privilege::UserIds) -> anyhow::Result<()> {
    let mut state = AgentState::new(ids);
    state.sweep_old_paste_dirs();

    loop {
        let (tag, payload) = match read_frame(&mut socket) {
            Ok(frame) => frame,
            // EOF: the worker is gone, and so is the reason to exist.
            Err(_) => return Ok(()),
        };
        let Some(op) = Op::from_byte(tag) else {
            reply_error(&mut socket, &format!("unknown operation {tag}"))?;
            continue;
        };
        match state.handle(op, &payload) {
            Ok(Answer::Bytes(body)) => reply_ok(&mut socket, &body, None)?,
            Ok(Answer::Descriptor(file)) => {
                let fd = file.as_raw_fd();
                reply_ok(&mut socket, &[], Some(fd))?;
                drop(file); // the worker owns its own copy now
            }
            Err(error) => reply_error(&mut socket, &format!("{error:#}"))?,
        }
    }
}

/// What one request produced.
enum Answer {
    Bytes(Vec<u8>),
    Descriptor(std::fs::File),
}

fn reply_ok(socket: &mut UnixStream, body: &[u8], fd: Option<RawFd>) -> anyhow::Result<()> {
    // The status byte alone carries the descriptor (see `read_reply`); the
    // length and the body follow as ordinary stream bytes.
    send_with_fd(socket, &[0u8], fd).context("send the reply status")?;
    let len = u32::try_from(body.len()).unwrap_or(0);
    socket.write_all(&len.to_le_bytes()).context("send the reply length")?;
    if !body.is_empty() {
        socket.write_all(body).context("send the reply body")?;
    }
    Ok(())
}

fn reply_error(socket: &mut UnixStream, message: &str) -> anyhow::Result<()> {
    // Errors never carry a descriptor, so the plain framing is enough — and
    // the worker reads it the same way, because the header says so.
    write_frame(socket, 1, message.as_bytes()).context("send the error reply")?;
    Ok(())
}

/// The helper's own state: which private directory it made for this session.
struct AgentState {
    uid: u32,
    /// Created on the first request that needs it, so a session that never
    /// pastes a file never makes a directory.
    paste_dir: Option<PathBuf>,
    prefix: String,
}

impl AgentState {
    fn new(ids: &super::privilege::UserIds) -> Self {
        Self {
            uid: ids.uid,
            paste_dir: None,
            // The account in the name so one user's leftovers are recognisable
            // (and sweepable) without opening them.
            prefix: format!("linrdp-paste-{}-", ids.name),
        }
    }

    fn handle(&mut self, op: Op, payload: &[u8]) -> anyhow::Result<Answer> {
        match op {
            Op::Stat => {
                let path = path_from(payload);
                let meta = std::fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
                let mut body = Vec::with_capacity(9);
                body.push(u8::from(meta.is_file()));
                body.extend_from_slice(&meta.len().to_le_bytes());
                Ok(Answer::Bytes(body))
            }
            Op::OpenRead => {
                let path = path_from(payload);
                let file = std::fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
                Ok(Answer::Descriptor(file))
            }
            Op::PasteDir => {
                let dir = self.ensure_paste_dir()?;
                Ok(Answer::Bytes(dir.as_os_str().as_encoded_bytes().to_vec()))
            }
            Op::MakeDir => {
                let dir = self.ensure_paste_dir()?.clone();
                let relative = checked_relative(payload)?;
                make_dir_below(&dir, &relative)?;
                Ok(Answer::Bytes(Vec::new()))
            }
            Op::CreateFile => {
                let dir = self.ensure_paste_dir()?.clone();
                let relative = checked_relative(payload)?;
                Ok(Answer::Descriptor(create_below(&dir, &relative)?))
            }
            Op::Remove => {
                let dir = self.ensure_paste_dir()?.clone();
                let relative = checked_relative(payload)?;
                let _ = std::fs::remove_file(dir.join(relative));
                Ok(Answer::Bytes(Vec::new()))
            }
        }
    }

    /// Make this session's private paste directory, once.
    ///
    /// A random name and an exclusive `mkdir`: the old scheme numbered them
    /// from zero in every worker, so two sessions shared `linrdp-paste-0` and
    /// a local user could have made it first, with symlinks already inside.
    /// Mode 0700 set at creation rather than by `umask`, which on the usual
    /// 022 left pasted files readable by every account on the machine.
    fn ensure_paste_dir(&mut self) -> anyhow::Result<&PathBuf> {
        if self.paste_dir.is_none() {
            let base = std::env::temp_dir();
            let mut last = None;
            for _ in 0..8 {
                let candidate = base.join(format!("{}{}", self.prefix, random_suffix()?));
                match std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&candidate)
                {
                    Ok(()) => {
                        self.paste_dir = Some(candidate);
                        break;
                    }
                    Err(e) => last = Some((candidate, e)),
                }
            }
            if self.paste_dir.is_none() {
                let (path, error) = last.expect("at least one attempt");
                return Err(anyhow::Error::from(error).context(format!("create {}", path.display())));
            }
        }
        Ok(self.paste_dir.as_ref().expect("just created"))
    }

    /// Remove this account's paste directories from previous sessions.
    ///
    /// Only directories this user owns, and only ones a day old: the sweep
    /// runs as the user, so it has no power over anybody else's leftovers and
    /// cannot be steered into removing them.
    fn sweep_old_paste_dirs(&self) {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        let cutoff = std::time::SystemTime::now() - core::time::Duration::from_secs(24 * 60 * 60);
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.starts_with(&self.prefix) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_dir() {
                continue;
            }
            use std::os::unix::fs::MetadataExt as _;
            if meta.uid() != self.uid {
                continue; // somebody else's, whatever it is called
            }
            if meta.modified().is_ok_and(|at| at < cutoff) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

use std::os::unix::fs::DirBuilderExt as _;

fn path_from(payload: &[u8]) -> PathBuf {
    // SAFETY: the bytes came from an OsStr on the other side of the socket,
    // which is the same platform and the same encoding.
    PathBuf::from(unsafe { std::ffi::OsString::from_encoded_bytes_unchecked(payload.to_vec()) })
}

/// A relative path with no component that could climb out or be a link.
///
/// The textual check is not the protection — the `O_NOFOLLOW` walk below is —
/// but a path that cannot be expressed as ordinary components is a protocol
/// error worth naming rather than resolving.
fn checked_relative(payload: &[u8]) -> anyhow::Result<PathBuf> {
    let path = path_from(payload);
    anyhow::ensure!(!payload.is_empty(), "an empty path names no file");
    anyhow::ensure!(path.is_relative(), "{} is not relative", path.display());
    for component in path.components() {
        anyhow::ensure!(
            matches!(component, std::path::Component::Normal(_)),
            "{} contains a component that is not a plain name",
            path.display()
        );
    }
    Ok(path)
}

/// Open the parent of `relative` under `dir`, following no symlink on the way.
///
/// Every component is opened with `O_NOFOLLOW | O_DIRECTORY` relative to the
/// one before it, so nothing between `dir` and the final name can be replaced
/// with a link to somewhere else — including after this call started, since
/// each step commits to the directory it actually opened rather than to a path
/// that will be resolved again later.
fn walk_to_parent(dir: &Path, relative: &Path) -> anyhow::Result<(OwnedDir, std::ffi::OsString)> {
    let mut components: Vec<std::ffi::OsString> = relative
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let name = components.pop().context("an empty relative path names no file")?;

    let mut current = OwnedDir::open_root(dir)?;
    for component in components {
        current = current.open_child_dir(&component)?;
    }
    Ok((current, name))
}

/// A directory descriptor, closed when dropped.
struct OwnedDir(RawFd);

impl Drop for OwnedDir {
    fn drop(&mut self) {
        // SAFETY: a descriptor this type opened and owns.
        unsafe { libc::close(self.0) };
    }
}

impl OwnedDir {
    fn open_root(dir: &Path) -> anyhow::Result<Self> {
        let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).context("path NUL")?;
        // SAFETY: a valid NUL-terminated path; the flags are plain constants.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW) };
        anyhow::ensure!(fd >= 0, "open {}: {}", dir.display(), std::io::Error::last_os_error());
        Ok(Self(fd))
    }

    fn open_child_dir(&self, name: &std::ffi::OsStr) -> anyhow::Result<Self> {
        let c = std::ffi::CString::new(name.as_encoded_bytes()).context("name NUL")?;
        // SAFETY: a directory descriptor this type owns and a valid name.
        let fd = unsafe {
            libc::openat(
                self.0,
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        anyhow::ensure!(
            fd >= 0,
            "open {:?} below the paste directory: {}",
            name,
            std::io::Error::last_os_error()
        );
        Ok(Self(fd))
    }
}

fn make_dir_below(dir: &Path, relative: &Path) -> anyhow::Result<()> {
    // Each level in turn, so an intermediate directory is created the same
    // careful way the leaf is.
    let mut current = OwnedDir::open_root(dir)?;
    for component in relative.components() {
        let name = component.as_os_str();
        let c = std::ffi::CString::new(name.as_encoded_bytes()).context("name NUL")?;
        // SAFETY: a directory descriptor we own and a valid name. EEXIST is
        // expected — a second file in the same subdirectory.
        let made = unsafe { libc::mkdirat(current.0, c.as_ptr(), 0o700) };
        if made != 0 {
            let error = std::io::Error::last_os_error();
            anyhow::ensure!(
                error.kind() == std::io::ErrorKind::AlreadyExists,
                "create {:?} below the paste directory: {error}",
                name
            );
        }
        current = current.open_child_dir(name)?;
    }
    Ok(())
}

fn create_below(dir: &Path, relative: &Path) -> anyhow::Result<std::fs::File> {
    let (parent, name) = walk_to_parent(dir, relative)?;
    let c = std::ffi::CString::new(name.as_encoded_bytes()).context("name NUL")?;
    // O_EXCL after removing any previous attempt: the file written through the
    // descriptor is the file this call created, and never one somebody
    // substituted between the check and the open.
    // SAFETY: a directory descriptor we own and a valid name.
    unsafe { libc::unlinkat(parent.0, c.as_ptr(), 0) };
    // SAFETY: as above; O_EXCL makes the creation the only outcome.
    let fd = unsafe {
        libc::openat(
            parent.0,
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            libc::c_uint::from(0o600u32),
        )
    };
    anyhow::ensure!(
        fd >= 0,
        "create {:?} below the paste directory: {}",
        name,
        std::io::Error::last_os_error()
    );
    // SAFETY: a descriptor openat just produced, owned from here.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// A name nobody can predict, so a directory cannot be squatted before it is
/// made.
fn random_suffix() -> anyhow::Result<String> {
    let mut bytes = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read random bytes")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
impl FileAgent {
    /// A helper served by a thread of this same process, for tests.
    ///
    /// No privilege drop and no `exec`: it runs as whoever is running the
    /// tests. What it does exercise is everything else — the framing, the
    /// `SCM_RIGHTS` descriptor passing, the paste directory and the
    /// `O_NOFOLLOW` walk — which is the part a test can be wrong about.
    pub(crate) fn in_process_for_test() -> anyhow::Result<Self> {
        let mut pair = [0i32; 2];
        // SAFETY: a two-element array, which is what socketpair(2) fills in.
        let paired = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
        anyhow::ensure!(paired == 0, "socketpair: {}", std::io::Error::last_os_error());
        // SAFETY: a descriptor socketpair just created, owned from here.
        let ours = unsafe { UnixStream::from_raw_fd(pair[0]) };
        // SAFETY: the other end of the same pair, likewise owned from here.
        let theirs = unsafe { UnixStream::from_raw_fd(pair[1]) };

        // SAFETY: getuid and getpwuid are read immediately into owned values.
        let name = unsafe {
            let pw = libc::getpwuid(libc::getuid());
            anyhow::ensure!(!pw.is_null(), "this uid has no account");
            std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
        };
        let ids = super::privilege::lookup_user(&name)?;
        std::thread::Builder::new()
            .name("linrdp-file-agent-test".into())
            .spawn(move || {
                let _ = serve(theirs, &ids);
            })
            .context("spawn the in-process helper")?;

        Ok(Self {
            socket: ours,
            pid: -1,
            user: name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole protocol, end to end: a descriptor opened on one side of the
    /// socket and written through on the other.
    #[test]
    fn a_descriptor_crosses_the_socket_and_still_points_at_the_right_file() {
        let mut agent = FileAgent::in_process_for_test().expect("helper");
        let dir = agent.paste_dir().expect("paste dir");
        assert!(dir.is_dir(), "the helper makes its own private directory");

        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "umask must not decide who can read pasted files");

        let mut file = agent.create_file(Path::new("note.txt")).expect("create");
        file.write_all(b"through the descriptor").expect("write");
        drop(file);
        assert_eq!(
            std::fs::read(dir.join("note.txt")).expect("read"),
            b"through the descriptor"
        );

        let facts = agent.stat(&dir.join("note.txt")).expect("stat");
        assert!(facts.is_file);
        assert_eq!(facts.size, 22);

        let mut back = agent.open_read(&dir.join("note.txt")).expect("open");
        let mut got = String::new();
        back.read_to_string(&mut got).expect("read back");
        assert_eq!(got, "through the descriptor");

        agent.remove(Path::new("note.txt")).expect("remove");
        assert!(!dir.join("note.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refusal must come back as a refusal, not as a closed socket that
    /// takes the rest of the clipboard with it.
    #[test]
    fn a_refused_request_leaves_the_helper_usable() {
        let mut agent = FileAgent::in_process_for_test().expect("helper");
        let dir = agent.paste_dir().expect("paste dir");

        assert!(
            agent.stat(Path::new("/definitely/not/here")).is_err(),
            "a missing file is an error"
        );
        assert!(
            agent.create_file(Path::new("../escape")).is_err(),
            "a path that tries to climb out is refused"
        );
        // Still answering afterwards.
        agent.create_file(Path::new("after.txt")).expect("the helper survived the refusals");
        assert!(dir.join("after.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pasted file's path comes from the remote client, and used to be
    /// joined onto a shared directory and opened as root. Only plain names
    /// survive now, and the walk below refuses links besides.
    #[test]
    fn a_relative_path_may_only_be_plain_names() {
        assert!(checked_relative(b"sub/dir/file.txt").is_ok());
        assert!(checked_relative(b"file.txt").is_ok());

        assert!(checked_relative(b"/etc/passwd").is_err(), "absolute paths are refused");
        assert!(checked_relative(b"../outside").is_err(), "`..` cannot climb out");
        assert!(checked_relative(b"a/../../b").is_err(), "`..` anywhere is refused");
        assert!(checked_relative(b"").is_err(), "an empty path names nothing");
    }

    /// The point of the helper: a descriptor the worker writes through was
    /// resolved once, under the paste directory, with no link followed.
    #[test]
    fn creating_a_file_below_the_paste_directory_refuses_a_symlinked_parent() {
        let root = std::env::temp_dir().join(format!("linrdp-agent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("paste");
        std::fs::create_dir_all(&dir).expect("paste dir");

        // An ordinary create works, and lands inside.
        let mut file = create_below(&dir, Path::new("hello.txt")).expect("create");
        file.write_all(b"hi").expect("write");
        drop(file);
        assert_eq!(std::fs::read(dir.join("hello.txt")).expect("read"), b"hi");

        // A subdirectory that is really a link out must not be walked through.
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, dir.join("sneaky")).expect("plant the link");
        assert!(
            create_below(&dir, Path::new("sneaky/loot.txt")).is_err(),
            "a symlinked path component must be an error, not a redirection"
        );
        assert!(
            !elsewhere.join("loot.txt").exists(),
            "nothing may be written outside the paste directory"
        );

        // And a link where the file itself goes is refused too.
        let target = root.join("target.txt");
        std::fs::write(&target, b"original").expect("target");
        std::os::unix::fs::symlink(&target, dir.join("linked.txt")).expect("plant the link");
        let created = create_below(&dir, Path::new("linked.txt"));
        assert!(created.is_ok(), "the link is replaced, not followed");
        drop(created);
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"original",
            "the file the link pointed at must be untouched"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Directories from a file list are created the same careful way.
    #[test]
    fn making_directories_below_the_paste_directory_stays_inside_it() {
        let root = std::env::temp_dir().join(format!("linrdp-agent-mkdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("paste");
        std::fs::create_dir_all(&dir).expect("paste dir");

        make_dir_below(&dir, Path::new("a/b/c")).expect("nested directories");
        assert!(dir.join("a/b/c").is_dir());
        make_dir_below(&dir, Path::new("a/b/c")).expect("creating it twice is fine");

        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, dir.join("link")).expect("plant the link");
        assert!(
            make_dir_below(&dir, Path::new("link/inside")).is_err(),
            "a symlinked component must stop the walk"
        );
        assert!(!elsewhere.join("inside").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Two sessions must not be able to collide. The old scheme numbered
    /// directories from zero in every worker, so they always did.
    #[test]
    fn paste_directory_names_are_unpredictable_and_distinct() {
        let a = random_suffix().expect("random");
        let b = random_suffix().expect("random");
        assert_ne!(a, b, "a predictable name is a directory somebody else can make first");
        assert_eq!(a.len(), 16, "eight bytes of entropy, hex");
    }
}
