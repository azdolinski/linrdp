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

/// Verify a username/password pair through the system PAM stack.
///
/// Returns `Ok(true/false)` = authenticated/not, `Err(reason)` = PAM itself
/// unavailable (no libpam, or a symbol the running version lacks) — the
/// caller should treat that as "fallback not possible", not as a verdict.
pub(crate) fn authenticate(username: &str, password: &str) -> Result<bool, String> {
    // Reject embedded NULs up front: they cannot travel through CString
    // into PAM, and truncation would authenticate the wrong string.
    let user = CString::new(username).map_err(|_| "username contains NUL".to_owned())?;
    let pass = CString::new(password).map_err(|_| "password contains NUL".to_owned())?;

    let api = match PAM.get_or_init(load_pam) {
        Ok(api) => api,
        Err(reason) => return Err((*reason).to_owned()),
    };

    // SAFETY: the handle is created, used and destroyed within this call;
    // the conversation callback only touches the ConvData alive here.
    unsafe {
        let service = CString::new(PAM_SERVICE_LOGIN).expect("static, no NUL");
        let data = ConvData { user, password: pass };
        let conv = PamConv {
            conv,
            appdata_ptr: &data as *const ConvData as *mut c_void,
        };

        let mut handle: *mut c_void = std::ptr::null_mut();
        let status = (api.pam_start)(service.as_ptr(), data.user.as_ptr(), &conv, &mut handle);
        if status != PAM_SUCCESS {
            return Err(format!("pam_start: {status}"));
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
