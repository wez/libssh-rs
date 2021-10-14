use thiserror::Error;

/// Represents an error condition
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

/// Represents the result of a fallible operation
pub type SshResult<T> = Result<T, Error>;

impl Error {
    pub fn is_try_again(&self) -> bool {
        matches!(self, Self::TryAgain)
    }

    pub fn fatal<S: Into<String>>(s: S) -> Self {
        Self::Fatal(s.into())
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> std::io::Error {
        match err {
            Error::TryAgain => std::io::Error::new(std::io::ErrorKind::WouldBlock, "TryAgain"),
            Error::RequestDenied(msg) | Error::Fatal(msg) => {
                std::io::Error::new(std::io::ErrorKind::Other, msg)
            }
        }
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::Fatal(err.to_string())
    }
}
