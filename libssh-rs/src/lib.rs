pub use libssh_rs_sys as sys;
use std::ffi::{CStr, CString};
use std::os::raw::{c_uint, c_ulong};
#[cfg(unix)]
use std::os::unix::io::RawFd as RawSocket;
#[cfg(windows)]
use std::os::windows::io::RawSocket;
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

    /// Parse the ssh config file.
    /// This should be the last call of all options, it may overwrite options
    /// which are already set.
    /// It requires that the `SshOption::Hostname` is already set.
    pub fn options_parse_config(&self, file_name: String) -> Result<(), Error> {
        let res = unsafe {
            sys::ssh_options_parse_config(
                self.sess,
                CString::new(file_name.clone())
                    .map_err(|e| Error::Fatal(e.to_string()))?
                    .as_ptr() as _,
            )
        };
        if res == 0 {
            Ok(())
        } else if let Some(err) = self.last_error() {
            Err(err)
        } else {
            Err(Error::Fatal(format!(
                "error parsing config file: {}",
                file_name
            )))
        }
    }

    pub fn set_option(&self, option: SshOption) -> Result<(), Error> {
        let res = match option {
            SshOption::Hostname(name) => unsafe {
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_HOST,
                    CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                )
            },
            SshOption::BindAddress(name) => unsafe {
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_BINDADDR,
                    CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                )
            },
            SshOption::AddIdentity(name) => unsafe {
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_ADD_IDENTITY,
                    CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                )
            },
            SshOption::User(name) => unsafe {
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_USER,
                    match name {
                        None => std::ptr::null(),
                        Some(name) => CString::new(name)
                            .map_err(|e| Error::Fatal(e.to_string()))?
                            .as_ptr() as _,
                    },
                )
            },
            SshOption::SshDir(name) => unsafe {
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_SSH_DIR,
                    match name {
                        None => std::ptr::null(),
                        Some(name) => CString::new(name)
                            .map_err(|e| Error::Fatal(e.to_string()))?
                            .as_ptr() as _,
                    },
                )
            },
            SshOption::KnownHosts(known_hosts) => unsafe {
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_KNOWNHOSTS,
                    match known_hosts {
                        None => std::ptr::null(),
                        Some(kh) => CString::new(kh)
                            .map_err(|e| Error::Fatal(e.to_string()))?
                            .as_ptr() as _,
                    },
                )
            },
            SshOption::Port(port) => {
                let port: c_uint = port.into();
                unsafe {
                    sys::ssh_options_set(
                        self.sess,
                        sys::ssh_options_e::SSH_OPTIONS_PORT,
                        &port as *const _ as _,
                    )
                }
            }
            SshOption::Socket(socket) => unsafe {
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_FD,
                    &socket as *const _ as _,
                )
            },
            SshOption::Timeout(duration) => unsafe {
                let micros: c_ulong = duration.as_micros() as c_ulong;
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_TIMEOUT_USEC,
                    &micros as *const _ as _,
                )
            },
        };

        if res == 0 {
            Ok(())
        } else if let Some(err) = self.last_error() {
            Err(err)
        } else {
            Err(Error::Fatal("failed to set option".to_string()))
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

#[derive(Debug)]
pub enum SshOption {
    /// The hostname or ip address to connect to
    Hostname(String),

    /// The port to connect to
    Port(u16),

    /// The pre-opened socket
    /// Don't forget to set the hostname as the hostname is used as a key in the known_host mechanism.
    Socket(RawSocket),

    /// The address to bind the client to
    BindAddress(String),

    /// The username for authentication
    /// If the value is None, the username is set to the default username.
    User(Option<String>),

    /// Set the ssh directory
    /// If the value is None, the directory is set to the default ssh directory.
    /// The ssh directory is used for files like known_hosts and identity (private and public key). It may include "%s" which will be replaced by the user home directory.
    SshDir(Option<String>),

    /// Set the known hosts file name
    /// If the value is None, the directory is set to the default known hosts file, normally ~/.ssh/known_hosts.
    /// The known hosts file is used to certify remote hosts are genuine. It may include "%d" which will be replaced by the user home directory.
    KnownHosts(Option<String>),

    /// Add a new identity file (const char *, format string) to the identity list.
    /// By default identity, id_dsa and id_rsa are checked.
    /// The identity used to authenticate with public key will be prepended to the list. It may include "%s" which will be replaced by the user home directory.
    AddIdentity(String),

    /// Set a timeout for the connection
    Timeout(std::time::Duration),
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
