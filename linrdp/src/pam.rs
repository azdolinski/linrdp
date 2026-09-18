//! PAM authentication fallback via `dlopen("libpam.so.0")` — no build-time
//! dependency on libpam headers, mirroring KRdp's `pam_start` /
//! `pam_authenticate` / `pam_acct_mgmt` flow (`service = "login"`).
//!
//! Why dlopen: the rest of this server is a single static binary with no
//! C dependencies; PAM is optional at runtime. If libpam is absent (e.g. a
//! minimal container), [`authenticate`] returns `Err` and the caller keeps
//! its previous verdict.
//!
//! The conversation callback answers only `PAM_PROMPT_ECHO_ON` (username)
//! and `PAM_PROMPT_ECHO_OFF` (password) prompts — anything else (2FA,
//! password change) fails the conversation, the same choice KRdp made.

use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::OnceLock;

// pam_types.h constants (Linux-PAM, ABI-stable).
const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_CONV_ERR: c_int = 19;

const PAM_SERVICE_LOGIN: &str = "login";

/// Session stack for linrdp; must include `pam_systemd.so` so logind
/// registers the session and creates `/run/user/<uid>`.
pub(crate) const PAM_SERVICE_LINRDP: &str = "linrdp";

const PAM_ESTABLISH_CRED: c_int = 0x0002;
const PAM_DELETE_CRED: c_int = 0x0004;

type PamConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: PamConvFn,
    appdata_ptr: *mut c_void,
}

/// The subset of the Linux-PAM API this module needs (opaque `pam_handle_t`).
struct PamApi {
    _lib: *mut c_void,
    pam_start: unsafe extern "C" fn(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        handle: *mut *mut c_void,
    ) -> c_int,
    pam_authenticate: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_acct_mgmt: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_end: unsafe extern "C" fn(handle: *mut c_void, status: c_int) -> c_int,
    pam_setcred: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_open_session: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_close_session: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_getenvlist: unsafe extern "C" fn(handle: *mut c_void) -> *mut *mut c_char,
    // strdup equivalent: PAM frees response strings with free(3), so the
    // response memory must come from the same libc allocator.
    strdup: unsafe extern "C" fn(s: *const c_char) -> *mut c_char,
}

unsafe impl Send for PamApi {}
unsafe impl Sync for PamApi {}

static PAM: OnceLock<Result<PamApi, &'static str>> = OnceLock::new();

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

const RTLD_NOW: c_int = 0x2;
const RTLD_GLOBAL: c_int = 0x100;

fn load_pam() -> Result<PamApi, &'static str> {
    // SAFETY: dlopen/dlsym are thread-safe (refcounted loader lock); the
    // symbol signatures match Linux-PAM's published ABI.
    unsafe {
        let lib = ["libpam.so.0", "libpam.so"]
            .iter()
            .find_map(|name| {
                let cname = CString::new(*name).ok()?;
                let handle = dlopen(cname.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
                (!handle.is_null()).then_some(handle)
            })
            .ok_or("libpam.so.0 not loadable")?;

        macro_rules! sym {
            ($name:expr) => {{
                let cname = CString::new($name).map_err(|_| "bad symbol name")?;
                let ptr = dlsym(lib, cname.as_ptr());
                if ptr.is_null() {
                    return Err(concat!("missing symbol ", $name));
                }
                std::mem::transmute::<*mut c_void, _>(ptr)
            }};
        }

        Ok(PamApi {
            _lib: lib,
            pam_start: sym!("pam_start"),
            pam_authenticate: sym!("pam_authenticate"),
            pam_acct_mgmt: sym!("pam_acct_mgmt"),
            pam_end: sym!("pam_end"),
            pam_setcred: sym!("pam_setcred"),
            pam_open_session: sym!("pam_open_session"),
            pam_close_session: sym!("pam_close_session"),
            pam_getenvlist: sym!("pam_getenvlist"),
            strdup: sym!("strdup"),
        })
    }
}

/// Conversation data: the credentials PAM asks for, borrowed for the call.
struct ConvData {
    user: CString,
    password: CString,
}

/// Answer PAM's prompts from [`ConvData`]; every other prompt style is a
/// conversation error (see module docs).
unsafe extern "C" fn conv(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    // SAFETY: PAM calls us synchronously from pam_authenticate/pam_acct_mgmt
    // with pointers valid for the call; appdata_ptr is the &ConvData the
    // caller stacked for exactly this invocation.
    unsafe {
        let data = &*(appdata_ptr as *const ConvData);
        // PAM frees the array and each non-null string with free(3);
        // calloc-zero the block so untouched entries are already null.
        let count = num_msg.max(0) as usize;
        let responses = libc_calloc(count);
        if responses.is_null() {
            return 4; // PAM_BUF_ERR
        }
        let api = match PAM.get() {
            Some(Ok(api)) => api,
            _ => return PAM_CONV_ERR,
        };

        for i in 0..count {
            let message = *msg.add(i);
            if message.is_null() {
                continue;
            }
            let style = (*message).msg_style;
            let answer: *const c_char = match style {
                PAM_PROMPT_ECHO_ON => data.user.as_ptr(),
                PAM_PROMPT_ECHO_OFF => data.password.as_ptr(),
                _ => return PAM_CONV_ERR,
            };
            let dup = (api.strdup)(answer);
            if dup.is_null() {
                return 4; // PAM_BUF_ERR
            }
            (*responses.add(i)).resp = dup;
        }
        *resp = responses;
        PAM_SUCCESS
    }
}

/// Leak-free calloc for the PAM response array (freed by PAM with free(3)).
///
/// Sized as `count * size_of::<PamResponse>()`; zeroed like calloc.
#[expect(
    clippy::as_conversions,
    reason = "c_void to typed pointer is the only way to type calloc's result"
)]
unsafe fn libc_calloc(count: usize) -> *mut PamResponse {
    unsafe extern "C" {
        fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    }
    // SAFETY: count and size are nonzero-normalized by the caller; the
    // result is a fresh allocation (or null, which the caller checks).
    let block = unsafe { calloc(count, size_of::<PamResponse>()) };
    block as *mut PamResponse
}

/// Which PAM service a login decision is made against.
///
/// `/etc/pam.d/linrdp` is the stack `linrdp service install` writes, and the
/// one every session already opens — so authentication and the session that
/// follows go through the same rules, the same `pam_faillock` counters and
/// the same `account` modules. `login` is only for a host where that file was
/// never installed; picking it by looking at the file, rather than by reading
/// a failure code, keeps "the stack said no" distinguishable from "there was
/// no stack".
pub(crate) fn login_service() -> &'static str {
    if std::path::Path::new("/etc/pam.d").join(PAM_SERVICE_LINRDP).is_file() {
        PAM_SERVICE_LINRDP
    } else {
        PAM_SERVICE_LOGIN
    }
}

/// Whether the account is currently allowed to log in at all — `pam_acct_mgmt`
/// with no password involved.
///
/// This is the half of the decision a correct password says nothing about:
/// an expired account, a disabled one, or one an access rule (`pam_access`,
/// `pam_time`, `pam_nologin`) refuses. `Err` means PAM itself is unavailable,
/// never "denied".
pub(crate) fn account_valid(username: &str) -> Result<bool, NoVerdict> {
    let user = CString::new(username)
        .map_err(|_| NoVerdict::BackendFailed("username contains NUL".to_owned()))?;

    let api = match PAM.get_or_init(load_pam) {
        Ok(api) => api,
        Err(reason) => return Err(NoVerdict::NotInstalled((*reason).to_owned())),
    };

    // SAFETY: the handle is created, used and ended within this call; the
    // conversation callback is never reached, because pam_acct_mgmt asks for
    // no credentials — but it is given valid data anyway.
    unsafe {
        let service = CString::new(login_service()).expect("static, no NUL");
        let data = ConvData {
            user,
            password: CString::new("").expect("empty, no NUL"),
        };
        let conv_struct = PamConv {
            conv,
            appdata_ptr: (&raw const data).cast::<c_void>().cast_mut(),
        };
        let mut handle: *mut c_void = std::ptr::null_mut();
        let status = (api.pam_start)(service.as_ptr(), data.user.as_ptr(), &conv_struct, &mut handle);
        if status != PAM_SUCCESS {
            return Err(NoVerdict::BackendFailed(format!("pam_start: {status}")));
        }
        let acct = (api.pam_acct_mgmt)(handle, 0);
        (api.pam_end)(handle, acct);
        Ok(acct == PAM_SUCCESS)
    }
}

/// Why PAM produced no verdict.
///
/// The distinction is the whole point, and collapsing it into one error was a
/// hole: "this machine has no libpam" is a configuration a caller may fall
/// back from, while "the stack is here and it broke" is a failure of the
/// authority itself. Treating the second like the first meant a `pam_start`
/// failure — after the library had loaded perfectly well — silently handed the
/// decision to `/etc/shadow`, which knows nothing about `pam_access`,
/// `pam_time` or anything else the stack would have applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NoVerdict {
    /// libpam is not installed, or lacks a symbol this build needs. There is
    /// no PAM policy on this machine to bypass.
    NotInstalled(String),
    /// libpam loaded and then failed: `pam_start` refused, the service is
    /// missing, the conversation could not run. Policy exists and did not
    /// execute, which is not the same as policy not existing.
    BackendFailed(String),
}

impl core::fmt::Display for NoVerdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInstalled(reason) => write!(f, "libpam is not usable here: {reason}"),
            Self::BackendFailed(reason) => write!(f, "the PAM stack failed: {reason}"),
        }
    }
}

/// Verify a username/password pair through the system PAM stack.
///
/// `Ok(true/false)` = authenticated/not. `Err` = no verdict, and [`NoVerdict`]
/// says whether that is because PAM is absent or because it broke — which the
/// caller must not conflate.
pub(crate) fn authenticate(username: &str, password: &str) -> Result<bool, NoVerdict> {
    // Reject embedded NULs up front: they cannot travel through CString
    // into PAM, and truncation would authenticate the wrong string.
    let user = CString::new(username)
        .map_err(|_| NoVerdict::BackendFailed("username contains NUL".to_owned()))?;
    let pass = CString::new(password)
        .map_err(|_| NoVerdict::BackendFailed("password contains NUL".to_owned()))?;

    let api = match PAM.get_or_init(load_pam) {
        Ok(api) => api,
        Err(reason) => return Err(NoVerdict::NotInstalled((*reason).to_owned())),
    };

    // SAFETY: the handle is created, used and destroyed within this call;
    // the conversation callback only touches the ConvData alive here.
    unsafe {
        let service = CString::new(login_service()).expect("static, no NUL");
        let data = ConvData { user, password: pass };
        let conv = PamConv {
            conv,
            appdata_ptr: &data as *const ConvData as *mut c_void,
        };

        let mut handle: *mut c_void = std::ptr::null_mut();
        let status = (api.pam_start)(service.as_ptr(), data.user.as_ptr(), &conv, &mut handle);
        if status != PAM_SUCCESS {
            // The library is here; it is the stack that would not start.
            return Err(NoVerdict::BackendFailed(format!("pam_start: {status}")));
        }

        let auth = (api.pam_authenticate)(handle, 0);
        if auth != PAM_SUCCESS {
            (api.pam_end)(handle, auth);
            return Ok(false);
        }
        // Account validity (expiry, locked accounts) — same call order KRdp
        // uses; a password can be right while the account is still unusable.
        let acct = (api.pam_acct_mgmt)(handle, 0);
        (api.pam_end)(handle, acct);
        Ok(acct == PAM_SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_loads_or_reports_cleanly() {
        // In the sandbox there is usually no libpam — either way the call
        // must not panic and must not hang.
        match authenticate("linrdp-selftest", "wrong") {
            Ok(false) => {} // libpam present, credentials rejected — correct
            Ok(true) => panic!("PAM accepted garbage credentials"),
            Err(reason) => tracing::debug!(%reason, "PAM unavailable in this environment"),
        }
    }
}

/// A live PAM session: the handle stays open for as long as the desktop runs.
///
/// Dropping this closes the session, so the keeper holds it and the worker
/// never does — the desktop outlives every connection to it.
pub(crate) struct LibPamSession {
    handle: *mut c_void,
    /// Kept alive because the conversation callback borrows it for the whole
    /// authentication, and PAM may re-enter it during `pam_setcred`.
    _data: Box<ConvData>,
    closed: bool,
}

// SAFETY: the handle is only ever touched from the thread that owns this
// value; the keeper is single-threaded by construction.
unsafe impl Send for LibPamSession {}

impl LibPamSession {
    /// Authenticate `user` and open a PAM session for them.
    ///
    /// Call order is the contract (see `session::pam_session::PamSessionApi`):
    /// authenticate, account check, `setcred(ESTABLISH)`, then
    /// `open_session`. `pam_systemd` needs established credentials before it
    /// will register the logind session and create `/run/user/<uid>`.
    pub(crate) fn open(user: &str, password: &str) -> Result<(Self, Vec<(String, String)>), String> {
        let c_user = CString::new(user).map_err(|_| "username contains NUL".to_owned())?;
        let c_pass = CString::new(password).map_err(|_| "password contains NUL".to_owned())?;

        let api = match PAM.get_or_init(load_pam) {
            Ok(api) => api,
            Err(reason) => return Err((*reason).to_owned()),
        };

        let data = Box::new(ConvData {
            user: c_user,
            password: c_pass,
        });
        let conv_struct = PamConv {
            conv,
            appdata_ptr: (&raw const *data).cast::<c_void>().cast_mut(),
        };

        // SAFETY: every call below uses a handle produced by pam_start on the
        // line above; each failure path ends the handle before returning, so
        // no handle escapes un-ended.
        unsafe {
            let service = CString::new(PAM_SERVICE_LINRDP).expect("static, no NUL");
            let mut handle: *mut c_void = std::ptr::null_mut();
            let status = (api.pam_start)(service.as_ptr(), data.user.as_ptr(), &conv_struct, &mut handle);
            if status != PAM_SUCCESS {
                return Err(format!("pam_start: {status}"));
            }

            let mut fail = |code: c_int, what: &str| -> String {
                (api.pam_end)(handle, code);
                format!("{what}: {code}")
            };

            let auth = (api.pam_authenticate)(handle, 0);
            if auth != PAM_SUCCESS {
                return Err(fail(auth, "pam_authenticate"));
            }
            let acct = (api.pam_acct_mgmt)(handle, 0);
            if acct != PAM_SUCCESS {
                return Err(fail(acct, "pam_acct_mgmt"));
            }
            let cred = (api.pam_setcred)(handle, PAM_ESTABLISH_CRED);
            if cred != PAM_SUCCESS {
                return Err(fail(cred, "pam_setcred"));
            }
            let sess = (api.pam_open_session)(handle, 0);
            if sess != PAM_SUCCESS {
                (api.pam_setcred)(handle, PAM_DELETE_CRED);
                return Err(fail(sess, "pam_open_session"));
            }

            let env = read_env(api, handle);
            Ok((
                Self {
                    handle,
                    _data: data,
                    closed: false,
                },
                env,
            ))
        }
    }

    /// Close the session and end the handle. Idempotent.
    pub(crate) fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let api = match PAM.get_or_init(load_pam) {
            Ok(api) => api,
            Err(reason) => return Err((*reason).to_owned()),
        };
        // SAFETY: `handle` came from pam_start and has not been ended yet.
        unsafe {
            let sess = (api.pam_close_session)(self.handle, 0);
            (api.pam_setcred)(self.handle, PAM_DELETE_CRED);
            (api.pam_end)(self.handle, sess);
        }
        Ok(())
    }
}

impl Drop for LibPamSession {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Copy PAM's environment list into owned pairs.
///
/// The list and its strings are allocated by PAM with malloc; this reads them
/// and leaks the array deliberately — the alternative is calling free(3) on
/// each element, and the leak is bounded by one session.
unsafe fn read_env(api: &PamApi, handle: *mut c_void) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // SAFETY: pam_getenvlist returns a NULL-terminated array of NUL-terminated
    // "KEY=VALUE" strings, or NULL.
    unsafe {
        let list = (api.pam_getenvlist)(handle);
        if list.is_null() {
            return out;
        }
        let mut i = 0isize;
        loop {
            let entry = *list.offset(i);
            if entry.is_null() {
                break;
            }
            if let Ok(text) = std::ffi::CStr::from_ptr(entry).to_str()
                && let Some((k, v)) = text.split_once('=')
            {
                out.push((k.to_owned(), v.to_owned()));
            }
            i += 1;
        }
    }
    out
}
