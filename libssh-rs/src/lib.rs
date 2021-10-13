pub use libssh_rs_sys as sys;
use std::ffi::CStr;
use std::sync::Once;
use thiserror::Error;

static INIT: Once = Once::new();

fn initialize() {
    INIT.call_once(|| unsafe {
        let res = sys::ssh_init();
        if res != sys::SSH_OK as i32 {
            panic!("ssh_init failed");
        }
    });
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// The last request was denied but situation is recoverable
    #[error("RequestDenied: {}", .0)]
    RequestDenied(String),
    /// A fatal error occurred. This could be an unexpected disconnection
    #[error("Fatal: {}", .0)]
    Fatal(String),
    /// The session is in non-blocking mode and the call must be tried again
    #[error("TryAgain")]
    TryAgain,
}

impl Error {
    pub fn is_try_again(&self) -> bool {
        matches!(self, Self::TryAgain)
    }
}

pub struct Session {
    sess: sys::ssh_session,
}

unsafe impl Send for Session {}

impl Session {
    pub fn new() -> Self {
        initialize();
        let sess = unsafe { sys::ssh_new() };
        if sess.is_null() {
            panic!("Out of memory when calling ssh_new");
        }
        Self { sess }
    }

    pub fn connect(&self) -> Result<(), Error> {
        let res = unsafe { sys::ssh_connect(self.sess) };
        if res == sys::SSH_OK as i32 {
            Ok(())
        } else if res == sys::SSH_AGAIN {
            Err(Error::TryAgain)
        } else if let Some(err) = self.last_error() {
            Err(err)
        } else {
            Err(Error::Fatal(format!(
                "unexpected error result {} from \
                     ssh_connect, and there is no recorded \
                     error condition on the session",
                res
            )))
        }
    }

    pub fn last_error(&self) -> Option<Error> {
        let code = unsafe { sys::ssh_get_error_code(self.sess as _) } as sys::ssh_error_types_e;
        if code == sys::ssh_error_types_e_SSH_NO_ERROR {
            return None;
        }

        let reason = unsafe { sys::ssh_get_error(self.sess as _) };
        let reason = if reason.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(reason) }
                .to_string_lossy()
                .to_string()
        };

        if code == sys::ssh_error_types_e_SSH_REQUEST_DENIED {
            Some(Error::RequestDenied(reason))
        } else {
            Some(Error::Fatal(reason))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            sys::ssh_free(self.sess);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn init() {
        let sess = Session::new();
        assert!(sess.last_error().is_none());
        assert_eq!(
            sess.connect(),
            Err(Error::Fatal("Hostname required".to_string()))
        );
    }
}
