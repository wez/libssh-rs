use crate::{opt_cstring_to_cstr, opt_str_to_cstring, Error, SessionHolder, SshResult};
use libssh_rs_sys as sys;
use std::convert::TryInto;
use std::ffi::CString;
use std::os::raw::c_int;
use std::sync::Arc;
use std::time::Duration;

/// Represents a channel in a Session.
/// A Session can have multiple channels; there is typically one
/// for the shell/program being run, but additional channels can
/// be opened to forward TCP or other connections.
pub struct Channel {
    pub(crate) sess: Arc<SessionHolder>,
    pub(crate) chan: sys::ssh_channel,
}

unsafe impl Send for Channel {}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe {
            sys::ssh_channel_free(self.chan);
        }
    }
}

impl Channel {
    /// Accept an X11 forwarding channel.
    /// A newly created channel, or None if no X11 request from the server.
    pub fn accept_x11(&self, timeout: std::time::Duration) -> Option<Self> {
        let timeout = timeout.as_millis();
        let chan = unsafe { sys::ssh_channel_accept_x11(self.chan, timeout.try_into().unwrap()) };
        if chan.is_null() {
            None
        } else {
            Some(Self {
                sess: Arc::clone(&self.sess),
                chan,
            })
        }
    }

    fn last_error(&self) -> Option<Error> {
        self.sess.last_error()
    }

    fn basic_status(&self, res: i32, what: &str) -> SshResult<()> {
        if res == sys::SSH_OK as i32 {
            Ok(())
        } else if res == sys::SSH_AGAIN {
            Err(Error::TryAgain)
        } else if let Some(err) = self.last_error() {
            Err(err)
        } else {
            Err(Error::Fatal(what.to_string()))
        }
    }

    /// Close a channel.
    /// This sends an end of file and then closes the channel.
    /// You won't be able to recover any data the server was going
    /// to send or was in buffers.
    pub fn close(&self) -> SshResult<()> {
        let res = unsafe { sys::ssh_channel_close(self.chan) };
        self.basic_status(res, "error closing channel")
    }

    /// Get the exit status of the channel
    /// (error code from the executed instruction).
    /// This function may block until a timeout (or never) if the other
    /// side is not willing to close the channel.
    pub fn get_exit_status(&self) -> Option<c_int> {
        let res = unsafe { sys::ssh_channel_get_exit_status(self.chan) };
        if res == -1 {
            None
        } else {
            Some(res)
        }
    }

    /// Check if the channel is closed or not.
    pub fn is_closed(&self) -> bool {
        unsafe { sys::ssh_channel_is_closed(self.chan) != 0 }
    }

    /// Check if remote has sent an EOF.
    pub fn is_eof(&self) -> bool {
        unsafe { sys::ssh_channel_is_eof(self.chan) != 0 }
    }

    /// Send an end of file on the channel.
    /// This doesn't close the channel.
    /// You may still read from it but not write.
    pub fn send_eof(&self) -> SshResult<()> {
        let res = unsafe { sys::ssh_channel_send_eof(self.chan) };
        self.basic_status(res, "ssh_channel_send_eof failed")
    }

    /// Check if the channel is open or not.
    pub fn is_open(&self) -> bool {
        unsafe { sys::ssh_channel_is_open(self.chan) != 0 }
    }

    /// Open an agent authentication forwarding channel.
    /// This type of channel can be opened by a server towards a
    /// client in order to provide SSH-Agent services to the server-side
    /// process. This channel can only be opened if the client claimed
    /// support by sending a channel request beforehand.
    pub fn open_auth_agent(&self) -> SshResult<()> {
        let res = unsafe { sys::ssh_channel_open_auth_agent(self.chan) };
        self.basic_status(res, "ssh_channel_open_auth_agent failed")
    }

    /// Send an "auth-agent-req" channel request over an existing session channel.
    /// This client-side request will enable forwarding the agent
    /// over an secure tunnel. When the server is ready to open one
    /// authentication agent channel, an
    /// ssh_channel_open_request_auth_agent_callback event will be generated.
    pub fn request_auth_agent(&self) -> SshResult<()> {
        let res = unsafe { sys::ssh_channel_request_auth_agent(self.chan) };
        self.basic_status(res, "ssh_channel_request_auth_agent failed")
    }

    /// Set environment variable.
    /// Some environment variables may be refused by security reasons.
    pub fn request_env(&self, name: &str, value: &str) -> SshResult<()> {
        let name = CString::new(name).map_err(|e| Error::Fatal(e.to_string()))?;
        let value = CString::new(value).map_err(|e| Error::Fatal(e.to_string()))?;
        let res = unsafe { sys::ssh_channel_request_env(self.chan, name.as_ptr(), value.as_ptr()) };
        self.basic_status(res, "ssh_channel_request_env failed")
    }

    /// Requests a shell; asks the server to spawn the user's shell,
    /// rather than directly executing a command specified by the client.
    pub fn request_shell(&self) -> SshResult<()> {
        let res = unsafe { sys::ssh_channel_request_shell(self.chan) };
        self.basic_status(res, "ssh_channel_request_shell failed")
    }

    /// Run a shell command without an interactive shell.
    /// This is similar to 'sh -c command'.
    pub fn request_exec(&self, command: &str) -> SshResult<()> {
        let command = CString::new(command).map_err(|e| Error::Fatal(e.to_string()))?;
        let res = unsafe { sys::ssh_channel_request_exec(self.chan, command.as_ptr()) };
        self.basic_status(res, "ssh_channel_request_exec failed")
    }

    /// Request a subsystem
    pub fn request_subsystem(&self, subsys: &str) -> SshResult<()> {
        let subsys = CString::new(subsys).map_err(|e| Error::Fatal(e.to_string()))?;
        let res = unsafe { sys::ssh_channel_request_subsystem(self.chan, subsys.as_ptr()) };
        self.basic_status(res, "ssh_channel_request_subsystem failed")
    }

    /// Request a pty with a specific type and size.
    /// `term` is the initial value for the `TERM` environment variable.
    /// If you're not sure what to fill for the values,
    /// `term = "xterm"`, `columns = 80` and `rows = 24` are reasonable
    /// defaults.
    pub fn request_pty_size(&self, term: &str, columns: u32, rows: u32) -> SshResult<()> {
        let term = CString::new(term).map_err(|e| Error::Fatal(e.to_string()))?;
        let res = unsafe {
            sys::ssh_channel_request_pty_size(
                self.chan,
                term.as_ptr(),
                columns.try_into().unwrap(),
                rows.try_into().unwrap(),
            )
        };
        self.basic_status(res, "ssh_channel_request_exec failed")
    }

    /// Send a break signal to the server (as described in RFC 4335).
    /// Sends a break signal to the remote process. Note, that remote
    /// system may not support breaks. In such a case this request will
    /// be silently ignored.
    pub fn request_send_break(&self, length: Duration) -> SshResult<()> {
        let res =
            unsafe { sys::ssh_channel_request_send_break(self.chan, length.as_millis() as _) };
        self.basic_status(res, "ssh_channel_request_send_break failed")
    }

    /// Send a signal to remote process (as described in RFC 4254, section 6.9).
    /// Sends a signal to the remote process.
    /// Note, that remote system may not support signals concept.
    /// In such a case this request will be silently ignored.
    ///
    /// `signal` is the name of the signal, without the `"SIG"` prefix.
    /// For example, `"ABRT"`, `"INT"`, `"KILL"` and so on.
    ///
    /// The OpenSSH server has only supported signals since OpenSSH version 8.1,
    /// release in 2019.
    /// <https://bugzilla.mindrot.org/show_bug.cgi?id=1424>
    pub fn request_send_signal(&self, signal: &str) -> SshResult<()> {
        let signal = CString::new(signal).map_err(|e| Error::Fatal(e.to_string()))?;
        let res = unsafe { sys::ssh_channel_request_send_signal(self.chan, signal.as_ptr()) };
        self.basic_status(res, "ssh_channel_request_send_signal failed")
    }

    /// Open a TCP/IP forwarding channel.
    /// `remote_host`, `remote_port` identify the destination for the
    /// connection.
    /// `source_host`, `source_port` identify the origin of the connection
    /// on the client side; these are used primarily for logging purposes.
    ///
    /// This function does not bind the source port and does not
    /// automatically forward the content of a socket to the channel.
    /// You still have to read/write this channel object to achieve that.
    pub fn open_forward(
        &self,
        remote_host: &str,
        remote_port: u16,
        source_host: &str,
        source_port: u16,
    ) -> SshResult<()> {
        let remote_host = CString::new(remote_host).map_err(|e| Error::Fatal(e.to_string()))?;
        let source_host = CString::new(source_host).map_err(|e| Error::Fatal(e.to_string()))?;
        let res = unsafe {
            sys::ssh_channel_open_forward(
                self.chan,
                remote_host.as_ptr(),
                remote_port as i32,
                source_host.as_ptr(),
                source_port as i32,
            )
        };
        self.basic_status(res, "ssh_channel_open_forward failed")
    }

    /// Sends the "x11-req" channel request over an existing session channel.
    /// This will enable redirecting the display of the remote X11 applications
    /// to local X server over an secure tunnel.
    pub fn request_x11(
        &self,
        single_connection: bool,
        protocol: Option<&str>,
        cookie: Option<&str>,
        screen_number: c_int,
    ) -> SshResult<()> {
        let protocol = opt_str_to_cstring(protocol);
        let cookie = opt_str_to_cstring(cookie);
        let res = unsafe {
            sys::ssh_channel_request_x11(
                self.chan,
                if single_connection { 1 } else { 0 },
                opt_cstring_to_cstr(&protocol),
                opt_cstring_to_cstr(&cookie),
                screen_number,
            )
        };

        self.basic_status(res, "ssh_channel_open_forward failed")
    }

    /// Open a session channel (suited for a shell, not TCP forwarding).
    pub fn open_session(&self) -> SshResult<()> {
        let res = unsafe { sys::ssh_channel_open_session(self.chan) };
        self.basic_status(res, "ssh_channel_open_session failed")
    }

    /// Polls a channel for data to read.
    /// Returns the number of bytes available for reading.
    /// If `timeout` is None, then blocks until data is available.
    pub fn poll_timeout(
        &self,
        is_stderr: bool,
        timeout: Option<Duration>,
    ) -> SshResult<PollStatus> {
        let timeout = match timeout {
            Some(t) => t.as_millis() as c_int,
            None => -1,
        };
        let res = unsafe {
            sys::ssh_channel_poll_timeout(self.chan, if is_stderr { 1 } else { 0 }, timeout)
        };
        match res {
            sys::SSH_ERROR => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal("ssh_channel_poll failed".to_string()))
                }
            }
            sys::SSH_EOF => Ok(PollStatus::EndOfFile),
            n if n >= 0 => Ok(PollStatus::AvailableBytes(n as u32)),
            n => Err(Error::Fatal(format!(
                "ssh_channel_poll returned unexpected {} value",
                n
            ))),
        }
    }

    /// Reads data from a channel.
    /// This function may fewer bytes than the buf size.
    pub fn read_timeout(
        &self,
        buf: &mut [u8],
        is_stderr: bool,
        timeout: Option<Duration>,
    ) -> SshResult<usize> {
        let timeout = match timeout {
            Some(t) => t.as_millis() as c_int,
            None => -1,
        };
        let res = unsafe {
            sys::ssh_channel_read_timeout(
                self.chan,
                buf.as_mut_ptr() as _,
                buf.len() as u32,
                if is_stderr { 1 } else { 0 },
                timeout,
            )
        };
        match res {
            sys::SSH_ERROR => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal("ssh_channel_read_timeout failed".to_string()))
                }
            }
            sys::SSH_AGAIN => Err(Error::TryAgain),
            n if n < 0 => Err(Error::Fatal(format!(
                "ssh_channel_read_timeout returned unexpected {} value",
                n
            ))),
            n => Ok(n as usize),
        }
    }

    fn read_impl(&self, buf: &mut [u8], is_stderr: bool) -> std::io::Result<usize> {
        self.read_timeout(buf, is_stderr, None)
            .map_err(|e| match e {
                Error::TryAgain => std::io::Error::new(std::io::ErrorKind::WouldBlock, "TryAgain"),
                Error::RequestDenied(msg) | Error::Fatal(msg) => {
                    std::io::Error::new(std::io::ErrorKind::Other, msg)
                }
            })
    }

    fn write_impl(&self, buf: &[u8], is_stderr: bool) -> SshResult<usize> {
        let res = unsafe {
            (if is_stderr {
                sys::ssh_channel_write_stderr
            } else {
                sys::ssh_channel_write
            })(self.chan, buf.as_ptr() as _, buf.len() as _)
        };

        match res {
            sys::SSH_ERROR => {
                if let Some(err) = self.last_error() {
                    Err(err)
                } else {
                    Err(Error::Fatal("ssh_channel_read_timeout failed".to_string()))
                }
            }
            sys::SSH_AGAIN => Err(Error::TryAgain),
            n if n < 0 => Err(Error::Fatal(format!(
                "ssh_channel_read_timeout returned unexpected {} value",
                n
            ))),
            n => Ok(n as usize),
        }
    }

    /// Returns an struct that implements std::io::Read
    /// and that will read data from the stdout channel.
    pub fn stdout(&self) -> ChannelStdout {
        ChannelStdout { chan: self }
    }

    /// Returns an struct that implements std::io::Read
    /// and that will read data from the stderr channel.
    pub fn stderr(&self) -> ChannelStderr {
        ChannelStderr { chan: self }
    }

    /// Returns a struct that implements std::io::Write
    /// and that will write data to the stdin channel
    pub fn stdin(&self) -> ChannelStdin {
        ChannelStdin { chan: self }
    }
}

/// Represents the stdin stream for the channel.
/// Implements std::io::Write; writing to this struct
/// will write to the stdin of the channel.
pub struct ChannelStdin<'a> {
    chan: &'a Channel,
}

impl<'a> std::io::Write for ChannelStdin<'a> {
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.chan.write_impl(buf, false).map_err(|e| match e {
            Error::TryAgain => std::io::Error::new(std::io::ErrorKind::WouldBlock, "TryAgain"),
            Error::RequestDenied(msg) | Error::Fatal(msg) => {
                std::io::Error::new(std::io::ErrorKind::Other, msg)
            }
        })
    }
}

/// Represents the stdout stream for the channel.
/// Implements std::io::Read; reading from this struct
/// will read from the stdout of the channel.
pub struct ChannelStdout<'a> {
    chan: &'a Channel,
}

impl<'a> std::io::Read for ChannelStdout<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.chan.read_impl(buf, false)
    }
}

/// Represents the stderr stream for the channel.
/// Implements std::io::Read; reading from this struct
/// will read from the stderr of the channel.
pub struct ChannelStderr<'a> {
    chan: &'a Channel,
}

impl<'a> std::io::Read for ChannelStderr<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.chan.read_impl(buf, true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollStatus {
    /// The available bytes to read; may be 0
    AvailableBytes(u32),
    /// The channel is in the EOF state
    EndOfFile,
}
