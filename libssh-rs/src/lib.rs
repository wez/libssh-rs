pub use libssh_rs_sys as sys;
use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_uint, c_ulong};
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

pub type SshResult<T> = Result<T, Error>;

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

    /// Disconnect from a session (client or server). The session can then be reused to open a new session.
    pub fn disconnect(&self) {
        unsafe { sys::ssh_disconnect(self.sess) };
    }

    pub fn connect(&self) -> SshResult<()> {
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

    /// Check if the servers public key for the connected session is known.
    /// This checks if we already know the public key of the server we want
    /// to connect to. This allows to detect if there is a MITM attack going
    /// on of if there have been changes on the server we don't know about.
    pub fn is_known_server(&self) -> SshResult<KnownHosts> {
        match unsafe { sys::ssh_session_is_known_server(self.sess) } {
            sys::ssh_known_hosts_e_SSH_KNOWN_HOSTS_NOT_FOUND => Ok(KnownHosts::NotFound),
            sys::ssh_known_hosts_e_SSH_KNOWN_HOSTS_UNKNOWN => Ok(KnownHosts::Unknown),
            sys::ssh_known_hosts_e_SSH_KNOWN_HOSTS_OK => Ok(KnownHosts::Ok),
            sys::ssh_known_hosts_e_SSH_KNOWN_HOSTS_CHANGED => Ok(KnownHosts::Changed),
            sys::ssh_known_hosts_e_SSH_KNOWN_HOSTS_OTHER => Ok(KnownHosts::Other),
            sys::ssh_known_hosts_e_SSH_KNOWN_HOSTS_ERROR | _ => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal(
                        "unknown error in ssh_session_is_known_server".to_string(),
                    ))
                }
            }
        }
    }

    /// Add the current connected server to the user known_hosts file.
    /// This adds the currently connected server to the known_hosts file
    /// by appending a new line at the end. The global known_hosts file
    /// is considered read-only so it is not touched by this function.
    pub fn update_known_hosts_file(&self) -> SshResult<()> {
        let res = unsafe { sys::ssh_session_update_known_hosts(self.sess) };

        if res == sys::SSH_OK as i32 {
            Ok(())
        } else if let Some(err) = self.last_error() {
            Err(err)
        } else {
            Err(Error::Fatal("error updating known hosts file".to_string()))
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
    /// if `file_name` is None the default `~/.ssh/config` will be used.
    pub fn options_parse_config(&self, file_name: Option<&str>) -> SshResult<()> {
        let res = unsafe {
            sys::ssh_options_parse_config(
                self.sess,
                match file_name {
                    None => std::ptr::null(),
                    Some(name) => CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                },
            )
        };
        if res == 0 {
            Ok(())
        } else if let Some(err) = self.last_error() {
            Err(err)
        } else {
            Err(Error::Fatal(format!(
                "error parsing config file: {:?}",
                file_name
            )))
        }
    }

    pub fn set_option(&self, option: SshOption) -> SshResult<()> {
        let res = match option {
            SshOption::LogLevel(level) => unsafe {
                let level = match level {
                    LogLevel::NoLogging => sys::SSH_LOG_NOLOG,
                    LogLevel::Warning => sys::SSH_LOG_WARNING,
                    LogLevel::Protocol => sys::SSH_LOG_PROTOCOL,
                    LogLevel::Packet => sys::SSH_LOG_PACKET,
                    LogLevel::Functions => sys::SSH_LOG_FUNCTIONS,
                } as u32 as c_int;
                sys::ssh_options_set(
                    self.sess,
                    sys::ssh_options_e::SSH_OPTIONS_LOG_VERBOSITY,
                    &level as *const _ as _,
                )
            },
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

    /// This function allows you to get a hash of the public key. You can then print this hash in a human-readable form to the user so that he is able to verify it.
    /// It is very important that you verify at some moment that the hash matches a known server. If you don't do it, cryptography wont help you at making things secure. OpenSSH uses SHA1 to print public key digests.
    pub fn get_server_public_key(&self) -> SshResult<SshKey> {
        let mut key = std::ptr::null_mut();
        let res = unsafe { sys::ssh_get_server_publickey(self.sess, &mut key) };
        if res == sys::SSH_OK as i32 && !key.is_null() {
            Ok(SshKey { key })
        } else if let Some(err) = self.last_error() {
            Err(err)
        } else {
            Err(Error::Fatal("failed to get server public key".to_string()))
        }
    }

    pub fn userauth_public_key_auto(
        &self,
        username: Option<&str>,
        password: Option<&str>,
    ) -> SshResult<AuthStatus> {
        let res = unsafe {
            sys::ssh_userauth_publickey_auto(
                self.sess,
                match username {
                    Some(name) => CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
                match password {
                    Some(name) => CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
            )
        };

        match res {
            sys::ssh_auth_e_SSH_AUTH_SUCCESS => Ok(AuthStatus::Success),
            sys::ssh_auth_e_SSH_AUTH_DENIED => Ok(AuthStatus::Denied),
            sys::ssh_auth_e_SSH_AUTH_PARTIAL => Ok(AuthStatus::Partial),
            sys::ssh_auth_e_SSH_AUTH_INFO => Ok(AuthStatus::Info),
            sys::ssh_auth_e_SSH_AUTH_AGAIN => Ok(AuthStatus::Again),
            sys::ssh_auth_e_SSH_AUTH_ERROR | _ => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal("authentication error".to_string()))
                }
            }
        }
    }

    pub fn userauth_none(&self, username: Option<&str>) -> SshResult<AuthStatus> {
        let res = unsafe {
            sys::ssh_userauth_none(
                self.sess,
                match username {
                    Some(name) => CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
            )
        };

        match res {
            sys::ssh_auth_e_SSH_AUTH_SUCCESS => Ok(AuthStatus::Success),
            sys::ssh_auth_e_SSH_AUTH_DENIED => Ok(AuthStatus::Denied),
            sys::ssh_auth_e_SSH_AUTH_PARTIAL => Ok(AuthStatus::Partial),
            sys::ssh_auth_e_SSH_AUTH_INFO => Ok(AuthStatus::Info),
            sys::ssh_auth_e_SSH_AUTH_AGAIN => Ok(AuthStatus::Again),
            sys::ssh_auth_e_SSH_AUTH_ERROR | _ => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal("authentication error".to_string()))
                }
            }
        }
    }

    pub fn userauth_list(&self, username: Option<&str>) -> SshResult<AuthMethods> {
        Ok(unsafe {
            AuthMethods::from_bits_unchecked(sys::ssh_userauth_list(
                self.sess,
                match username {
                    Some(name) => CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
            ) as u32)
        })
    }

    pub fn userauth_keyboard_interactive_info(&self) -> SshResult<InteractiveAuthInfo> {
        let name = unsafe { sys::ssh_userauth_kbdint_getname(self.sess) };
        let name = unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .to_string();

        let instruction = unsafe { sys::ssh_userauth_kbdint_getinstruction(self.sess) };
        let instruction = unsafe { CStr::from_ptr(instruction) }
            .to_string_lossy()
            .to_string();

        let n_prompts = unsafe { sys::ssh_userauth_kbdint_getnprompts(self.sess) };
        assert!(n_prompts >= 0);
        let n_prompts = n_prompts as u32;
        let mut prompts = vec![];
        for i in 0..n_prompts {
            let mut echo = 0;
            let prompt = unsafe { sys::ssh_userauth_kbdint_getprompt(self.sess, i, &mut echo) };

            prompts.push(InteractiveAuthPrompt {
                prompt: unsafe { CStr::from_ptr(prompt) }
                    .to_string_lossy()
                    .to_string(),
                echo: echo != 0,
            });
        }

        Ok(InteractiveAuthInfo {
            name,
            instruction,
            prompts,
        })
    }

    pub fn userauth_keyboard_interactive_set_answers(&self, answers: &[String]) -> SshResult<()> {
        for (idx, answer) in answers.iter().enumerate() {
            let answer = CString::new(answer.as_bytes())
                .map_err(|e| Error::Fatal(e.to_string()))?
                .as_ptr() as _;

            let res = unsafe { sys::ssh_userauth_kbdint_setanswer(self.sess, idx as u32, answer) };

            if res != 0 {
                if let Some(err) = self.last_error() {
                    return Err(err);
                }
                return Err(Error::Fatal("error setting answer".to_string()));
            }
        }
        Ok(())
    }

    pub fn userauth_keyboard_interactive(
        &self,
        username: Option<&str>,
        sub_methods: Option<&str>,
    ) -> SshResult<AuthStatus> {
        let res = unsafe {
            sys::ssh_userauth_kbdint(
                self.sess,
                match username {
                    Some(name) => CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
                match sub_methods {
                    Some(sm) => CString::new(sm)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
            )
        };
        match res {
            sys::ssh_auth_e_SSH_AUTH_SUCCESS => Ok(AuthStatus::Success),
            sys::ssh_auth_e_SSH_AUTH_DENIED => Ok(AuthStatus::Denied),
            sys::ssh_auth_e_SSH_AUTH_PARTIAL => Ok(AuthStatus::Partial),
            sys::ssh_auth_e_SSH_AUTH_INFO => Ok(AuthStatus::Info),
            sys::ssh_auth_e_SSH_AUTH_AGAIN => Ok(AuthStatus::Again),
            sys::ssh_auth_e_SSH_AUTH_ERROR | _ => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal("authentication error".to_string()))
                }
            }
        }
    }

    pub fn userauth_password(
        &self,
        username: Option<&str>,
        password: Option<&str>,
    ) -> SshResult<AuthStatus> {
        let res = unsafe {
            sys::ssh_userauth_password(
                self.sess,
                match username {
                    Some(name) => CString::new(name)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
                match password {
                    Some(pw) => CString::new(pw)
                        .map_err(|e| Error::Fatal(e.to_string()))?
                        .as_ptr() as _,
                    None => std::ptr::null(),
                },
            )
        };
        match res {
            sys::ssh_auth_e_SSH_AUTH_SUCCESS => Ok(AuthStatus::Success),
            sys::ssh_auth_e_SSH_AUTH_DENIED => Ok(AuthStatus::Denied),
            sys::ssh_auth_e_SSH_AUTH_PARTIAL => Ok(AuthStatus::Partial),
            sys::ssh_auth_e_SSH_AUTH_INFO => Ok(AuthStatus::Info),
            sys::ssh_auth_e_SSH_AUTH_AGAIN => Ok(AuthStatus::Again),
            sys::ssh_auth_e_SSH_AUTH_ERROR | _ => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal("authentication error".to_string()))
                }
            }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Success,
    Denied,
    Partial,
    Info,
    Again,
}

bitflags::bitflags! {
    pub struct AuthMethods : u32 {
        const NONE = sys::SSH_AUTH_METHOD_NONE;
        const PASSWORD = sys::SSH_AUTH_METHOD_PASSWORD;
        const PUBLIC_KEY = sys::SSH_AUTH_METHOD_PUBLICKEY;
        const HOST_BASED = sys::SSH_AUTH_METHOD_HOSTBASED;
        const INTERACTIVE = sys::SSH_AUTH_METHOD_INTERACTIVE;
        const GSSAPI_MIC = sys::SSH_AUTH_METHOD_GSSAPI_MIC;
    }
}

pub struct SshKey {
    key: sys::ssh_key,
}

impl Drop for SshKey {
    fn drop(&mut self) {
        unsafe { sys::ssh_key_free(self.key) }
    }
}

impl SshKey {
    pub fn get_public_key_hash(&self, hash_type: PublicKeyHashType) -> SshResult<Vec<u8>> {
        let mut bytes = std::ptr::null_mut();
        let mut len = 0;
        let res = unsafe {
            sys::ssh_get_publickey_hash(
                self.key,
                match hash_type {
                    PublicKeyHashType::Sha1 => {
                        sys::ssh_publickey_hash_type::SSH_PUBLICKEY_HASH_SHA1
                    }
                    PublicKeyHashType::Md5 => sys::ssh_publickey_hash_type::SSH_PUBLICKEY_HASH_MD5,
                    PublicKeyHashType::Sha256 => {
                        sys::ssh_publickey_hash_type::SSH_PUBLICKEY_HASH_SHA256
                    }
                },
                &mut bytes,
                &mut len,
            )
        };

        if res != 0 || bytes.is_null() {
            Err(Error::Fatal("failed to get public key hash".to_string()))
        } else {
            let data = unsafe { std::slice::from_raw_parts(bytes, len).to_vec() };
            unsafe {
                sys::ssh_clean_pubkey_hash(&mut bytes);
            }
            Ok(data)
        }
    }

    pub fn get_public_key_hash_hexa(&self, hash_type: PublicKeyHashType) -> SshResult<String> {
        let bytes = self.get_public_key_hash(hash_type)?;
        let hexa = unsafe { sys::ssh_get_hexa(bytes.as_ptr(), bytes.len()) };
        if hexa.is_null() {
            Err(Error::Fatal(
                "failed to allocate bytes for hexa representation".to_string(),
            ))
        } else {
            let res = unsafe { CStr::from_ptr(hexa) }
                .to_string_lossy()
                .to_string();
            unsafe { sys::ssh_string_free_char(hexa) };
            Ok(res)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    NoLogging,
    Warning,
    Protocol,
    Packet,
    Functions,
}

#[derive(Debug)]
pub enum SshOption {
    /// The hostname or ip address to connect to
    Hostname(String),

    /// The port to connect to
    Port(u16),

    LogLevel(LogLevel),

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHosts {
    /// The known host file does not exist. The host is thus unknown. File will be created if host key is accepted.
    NotFound,
    /// The server is unknown. User should confirm the public key hash is correct.
    Unknown,
    /// The server is known and has not changed.
    Ok,
    /// The server key has changed. Either you are under attack or the administrator changed the key. You HAVE to warn the user about a possible attack.
    Changed,
    /// The server gave use a key of a type while we had an other type recorded. It is a possible attack.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyHashType {
    Sha1,
    Md5,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveAuthPrompt {
    pub prompt: String,
    pub echo: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveAuthInfo {
    pub instruction: String,
    pub name: String,
    pub prompts: Vec<InteractiveAuthPrompt>,
}

pub fn get_password(
    prompt: &str,
    default_value: Option<&str>,
    echo: bool,
    verify: bool,
) -> Option<String> {
    const BUF_LEN: usize = 128;
    let mut buf = [0u8; BUF_LEN];

    if let Some(def) = default_value {
        let def = def.as_bytes();
        let len = buf.len().min(def.len());
        buf[0..len].copy_from_slice(&def[0..len]);
    }

    let prompt = CString::new(prompt).ok()?;

    let res = unsafe {
        sys::ssh_getpass(
            prompt.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            if echo { 1 } else { 0 },
            if verify { 1 } else { 0 },
        )
    };

    if res == 0 {
        Some(
            unsafe { CStr::from_ptr(buf.as_ptr() as *const _) }
                .to_string_lossy()
                .to_string(),
        )
    } else {
        None
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
