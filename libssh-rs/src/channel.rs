use crate::{opt_cstring_to_cstr, opt_str_to_cstring, Error, SessionHolder, SshResult};
use libssh_rs_sys as sys;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Represents a channel in a `Session`.
///
/// A `Session` can have multiple channels; there is typically one
/// for the shell/program being run, but additional channels can
/// be opened to forward TCP or other connections.
///
/// [open_session](#method.open_session) is often the first
/// thing you will call on the `Channel` after creating it; this establishes
/// the channel for executing commands.
///
/// Then you will typically use either [request_exec](#method.request_exec)
/// to run a non-interactive command, or [request_pty](#method.request_pty)
/// followed [request_shell](#method.request_shell) to set up an interactive
/// remote shell.
///
/// # Thread Safety
///
/// `Channel` is strongly associated with the `Session` to which it belongs.
/// libssh doesn't allow using anything associated with a given `Session`
/// from multiple threads concurrently.  These Rust bindings encapsulate
/// the underlying `Session` in an internal mutex, which allows you to
/// safely operate on the various elements of the session and even move
/// them to other threads, but you need to be aware that calling methods
/// on any of those structs will attempt to lock the underlying session,
/// and this can lead to blocking in surprising situations.
pub struct Channel {
    pub(crate) sess: Arc<Mutex<SessionHolder>>,
    pub(crate) chan_inner: sys::ssh_channel,
    _callbacks: Box<sys::ssh_channel_callbacks_struct>,
    callback_state: Box<CallbackState>,
}

unsafe impl Send for Channel {}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe {
            // Prevent any callbacks firing as part the remainder of this drop operation
            sys::ssh_remove_channel_callbacks(self.chan_inner, self._callbacks.as_mut());
        }
        let (_sess, chan) = self.lock_session();
        unsafe {
            sys::ssh_channel_free(chan);
        }
    }
}

/// State visible to the callbacks
struct CallbackState {
    signal_state: Mutex<Option<SignalState>>,
}

#[derive(Clone, Debug)]
pub struct SignalState {
    pub signal_name: Option<String>,
    pub core_dumped: bool,
    pub error_message: Option<String>,
    pub language: Option<String>,
}

fn cstr_to_opt_string(cstr: *const ::std::os::raw::c_char) -> Option<String> {
    if cstr.is_null() {
        return None;
    }

    Some(
        unsafe { CStr::from_ptr(cstr) }
            .to_string_lossy()
            .to_string(),
    )
}

unsafe extern "C" fn handle_exit_signal(
    _session: sys::ssh_session,
    _channel: sys::ssh_channel,
    signal: *const ::std::os::raw::c_char,
    core_dumped: ::std::os::raw::c_int,
    errmsg: *const ::std::os::raw::c_char,
    lang: *const ::std::os::raw::c_char,
    userdata: *mut ::std::os::raw::c_void,
) {
    let callback_state: &CallbackState = &*(userdata as *const CallbackState);

    let signal_name = cstr_to_opt_string(signal);
    let error_message = cstr_to_opt_string(errmsg);
    let language = cstr_to_opt_string(lang);

    callback_state
        .signal_state
        .lock()
        .unwrap()
        .replace(SignalState {
            signal_name,
            core_dumped: if core_dumped == 0 { false } else { true },
            error_message,
            language,
        });
}

impl Channel {
    /// Accept an X11 forwarding channel.
    /// Returns a newly created `Channel`, or `None` if no X11 request from the server.
    pub fn accept_x11(&self, timeout: std::time::Duration) -> Option<Self> {
        let (_sess, chan) = self.lock_session();
        let timeout = timeout.as_millis();
        let chan = unsafe { sys::ssh_channel_accept_x11(chan, timeout.try_into().unwrap()) };
        if chan.is_null() {
            None
        } else {
            Some(Self::new(&self.sess, chan))
        }
    }

    pub(crate) fn new(sess: &Arc<Mutex<SessionHolder>>, chan: sys::ssh_channel) -> Self {
        let callback_state = Box::new(CallbackState {
            signal_state: Mutex::new(None),
        });

        let callbacks = Box::new(sys::ssh_channel_callbacks_struct {
            size: std::mem::size_of::<sys::ssh_channel_callbacks_struct>(),
            userdata: callback_state.as_ref() as *const CallbackState as *mut _,
            channel_data_function: None,
            channel_eof_function: None,
            channel_close_function: None,
            channel_signal_function: None,
            channel_exit_status_function: None,
            channel_exit_signal_function: Some(handle_exit_signal),
            channel_pty_request_function: None,
            channel_shell_request_function: None,
            channel_auth_agent_req_function: None,
            channel_x11_req_function: None,
            channel_pty_window_change_function: None,
            channel_exec_request_function: None,
            channel_env_request_function: None,
            channel_subsystem_request_function: None,
            channel_write_wontblock_function: None,
        });

        unsafe { sys::ssh_set_channel_callbacks(chan, callbacks.as_ref() as *const _ as *mut _) };

        Self {
            sess: Arc::clone(&sess),
            chan_inner: chan,
            callback_state,
            _callbacks: callbacks,
        }
    }

    fn lock_session(&self) -> (MutexGuard<SessionHolder>, sys::ssh_channel) {
        (self.sess.lock().unwrap(), self.chan_inner)
    }

    /// Close a channel.
    /// This sends an end of file and then closes the channel.
    /// You won't be able to recover any data the server was going
    /// to send or was in buffers.
    pub fn close(&self) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_close(chan) };
        sess.basic_status(res, "error closing channel")
    }

    /// Get the exit status of the channel
    /// (error code from the executed instruction).
    /// This function may block until a timeout (or never) if the other
    /// side is not willing to close the channel.
    pub fn get_exit_status(&self) -> Option<c_int> {
        let (_sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_get_exit_status(chan) };
        if res == -1 {
            None
        } else {
            Some(res)
        }
    }

    /// Get the exit signal status of the channel.
    /// If the channel was closed/terminated due to a signal, and the
    /// remote system supports the signal concept, the signal state
    /// will be set and reported here.
    pub fn get_exit_signal(&self) -> Option<SignalState> {
        self.callback_state.signal_state.lock().unwrap().clone()
    }

    /// Check if the channel is closed or not.
    pub fn is_closed(&self) -> bool {
        let (_sess, chan) = self.lock_session();
        unsafe { sys::ssh_channel_is_closed(chan) != 0 }
    }

    /// Check if remote has sent an EOF.
    pub fn is_eof(&self) -> bool {
        let (_sess, chan) = self.lock_session();
        unsafe { sys::ssh_channel_is_eof(chan) != 0 }
    }

    /// Send an end of file on the channel.
    ///
    /// You should call this when you have no additional data to send
    /// to the channel to signal that information to the remote host.
    ///
    /// This doesn't close the channel.
    /// You may still read from it but not write.
    pub fn send_eof(&self) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_send_eof(chan) };
        sess.basic_status(res, "ssh_channel_send_eof failed")
    }

    /// Check if the channel is open or not.
    pub fn is_open(&self) -> bool {
        let (_sess, chan) = self.lock_session();
        unsafe { sys::ssh_channel_is_open(chan) != 0 }
    }

    /// Open an agent authentication forwarding channel.
    /// This type of channel can be opened by a *server* towards a
    /// client in order to provide SSH-Agent services to the server-side
    /// process. This channel can only be opened if the client claimed
    /// support by sending a channel request beforehand.
    pub fn open_auth_agent(&self) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_open_auth_agent(chan) };
        sess.basic_status(res, "ssh_channel_open_auth_agent failed")
    }

    /// Send an `"auth-agent-req"` channel request over an existing session channel.
    ///
    /// This client-side request will enable forwarding the agent
    /// over a secure tunnel. When the server is ready to open one
    /// authentication agent channel, an
    /// ssh_channel_open_request_auth_agent_callback event will be generated.
    pub fn request_auth_agent(&self) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_request_auth_agent(chan) };
        sess.basic_status(res, "ssh_channel_request_auth_agent failed")
    }

    /// Set environment variable.
    /// Some environment variables may be refused by security reasons.
    pub fn request_env(&self, name: &str, value: &str) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let name = CString::new(name)?;
        let value = CString::new(value)?;
        let res = unsafe { sys::ssh_channel_request_env(chan, name.as_ptr(), value.as_ptr()) };
        sess.basic_status(res, "ssh_channel_request_env failed")
    }

    /// Requests a shell; asks the server to spawn the user's shell,
    /// rather than directly executing a command specified by the client.
    ///
    /// The channel must be a session channel; you need to have called
    /// [open_session](#method.open_session) before this will succeed.
    pub fn request_shell(&self) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_request_shell(chan) };
        sess.basic_status(res, "ssh_channel_request_shell failed")
    }

    /// Run a shell command without an interactive shell.
    /// This is similar to 'sh -c command'.
    ///
    /// The channel must be a session channel; you need to have called
    /// [open_session](#method.open_session) before this will succeed.
    pub fn request_exec(&self, command: &str) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let command = CString::new(command)?;
        let res = unsafe { sys::ssh_channel_request_exec(chan, command.as_ptr()) };
        sess.basic_status(res, "ssh_channel_request_exec failed")
    }

    /// Request a subsystem.
    ///
    /// You probably don't need this unless you know what you are doing!
    pub fn request_subsystem(&self, subsys: &str) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let subsys = CString::new(subsys)?;
        let res = unsafe { sys::ssh_channel_request_subsystem(chan, subsys.as_ptr()) };
        sess.basic_status(res, "ssh_channel_request_subsystem failed")
    }

    /// Request a PTY with a specific type and size.
    /// A PTY is useful when you want to run an interactive program on
    /// the remote host.
    ///
    /// `term` is the initial value for the `TERM` environment variable.
    /// If you're not sure what to fill for the values,
    /// `term = "xterm"`, `columns = 80` and `rows = 24` are reasonable
    /// defaults.
    pub fn request_pty(&self, term: &str, columns: u32, rows: u32) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let term = CString::new(term)?;
        let res = unsafe {
            sys::ssh_channel_request_pty_size(
                chan,
                term.as_ptr(),
                columns.try_into().unwrap(),
                rows.try_into().unwrap(),
            )
        };
        sess.basic_status(res, "ssh_channel_request_pty_size failed")
    }

    /// Informs the server that the local size of the PTY has changed
    pub fn change_pty_size(&self, columns: u32, rows: u32) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe {
            sys::ssh_channel_change_pty_size(
                chan,
                columns.try_into().unwrap(),
                rows.try_into().unwrap(),
            )
        };
        sess.basic_status(res, "ssh_channel_change_pty_size failed")
    }

    /// Send a break signal to the server (as described in RFC 4335).
    /// Sends a break signal to the remote process. Note, that remote
    /// system may not support breaks. In such a case this request will
    /// be silently ignored.
    pub fn request_send_break(&self, length: Duration) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_request_send_break(chan, length.as_millis() as _) };
        sess.basic_status(res, "ssh_channel_request_send_break failed")
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
    /// released in 2019.
    /// <https://bugzilla.mindrot.org/show_bug.cgi?id=1424>
    pub fn request_send_signal(&self, signal: &str) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let signal = CString::new(signal)?;
        let res = unsafe { sys::ssh_channel_request_send_signal(chan, signal.as_ptr()) };
        sess.basic_status(res, "ssh_channel_request_send_signal failed")
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
        let (sess, chan) = self.lock_session();
        let remote_host = CString::new(remote_host)?;
        let source_host = CString::new(source_host)?;
        let res = unsafe {
            sys::ssh_channel_open_forward(
                chan,
                remote_host.as_ptr(),
                remote_port as i32,
                source_host.as_ptr(),
                source_port as i32,
            )
        };
        sess.basic_status(res, "ssh_channel_open_forward failed")
    }

    /// Open a UNIX domain socket forwarding channel.
    /// `remote_path` is the path to the unix socket to open on the remote
    /// machine.
    /// `source_host` and `source_port` identify the originating connection
    /// from the client machine and are used for logging purposes.
    ///
    /// This function does not bind the source and does not
    /// automatically forward the content of a socket to the channel.
    /// You still have to read/write this channel object to achieve that.
    pub fn open_forward_unix(
        &self,
        remote_path: &str,
        source_host: &str,
        source_port: u16,
    ) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let remote_path = CString::new(remote_path)?;
        let source_host = CString::new(source_host)?;
        let res = unsafe {
            sys::ssh_channel_open_forward_unix(
                chan,
                remote_path.as_ptr(),
                source_host.as_ptr(),
                source_port as i32,
            )
        };
        sess.basic_status(res, "ssh_channel_open_forward_unix failed")
    }

    /// Sends the `"x11-req"` channel request over an existing session channel.
    /// This will enable redirecting the display of the remote X11 applications
    /// to local X server over an secure tunnel.
    pub fn request_x11(
        &self,
        single_connection: bool,
        protocol: Option<&str>,
        cookie: Option<&str>,
        screen_number: c_int,
    ) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let protocol = opt_str_to_cstring(protocol);
        let cookie = opt_str_to_cstring(cookie);
        let res = unsafe {
            sys::ssh_channel_request_x11(
                chan,
                if single_connection { 1 } else { 0 },
                opt_cstring_to_cstr(&protocol),
                opt_cstring_to_cstr(&cookie),
                screen_number,
            )
        };

        sess.basic_status(res, "ssh_channel_open_forward failed")
    }

    /// Open a session channel (suited for a shell, not TCP forwarding).
    pub fn open_session(&self) -> SshResult<()> {
        let (sess, chan) = self.lock_session();
        let res = unsafe { sys::ssh_channel_open_session(chan) };
        sess.basic_status(res, "ssh_channel_open_session failed")
    }

    /// Polls a channel for data to read.
    /// Returns the number of bytes available for reading.
    /// If `timeout` is None, then blocks until data is available.
    pub fn poll_timeout(
        &self,
        is_stderr: bool,
        timeout: Option<Duration>,
    ) -> SshResult<PollStatus> {
        let (sess, chan) = self.lock_session();
        let timeout = match timeout {
            Some(t) => t.as_millis() as c_int,
            None => -1,
        };
        let res =
            unsafe { sys::ssh_channel_poll_timeout(chan, if is_stderr { 1 } else { 0 }, timeout) };
        match res {
            sys::SSH_ERROR => {
                if let Some(err) = sess.last_error() {
                    Err(err)
                } else {
                    Err(Error::fatal("ssh_channel_poll failed"))
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
        let (sess, chan) = self.lock_session();

        let timeout = match timeout {
            Some(t) => t.as_millis() as c_int,
            None => -1,
        };
        let res = unsafe {
            sys::ssh_channel_read_timeout(
                chan,
                buf.as_mut_ptr() as _,
                buf.len() as u32,
                if is_stderr { 1 } else { 0 },
                timeout,
            )
        };
        match res {
            sys::SSH_ERROR => {
                if let Some(err) = sess.last_error() {
                    Err(err)
                } else {
                    Err(Error::fatal("ssh_channel_read_timeout failed"))
                }
            }
            sys::SSH_AGAIN => Err(Error::TryAgain),
            n if n < 0 => Err(Error::Fatal(format!(
                "ssh_channel_read_timeout returned unexpected {} value",
                n
            ))),
            0 if !sess.is_blocking() => Err(Error::TryAgain),
            n => Ok(n as usize),
        }
    }

    /// Get the remote window size.
    /// This is the maximum amounts of bytes the remote side expects us to send
    /// before growing the window again.
    /// A nonzero return value does not guarantee the socket is ready to send that much data.
    /// Buffering may happen in the local SSH packet buffer, so beware of really big window sizes.
    /// A zero return value means that a write will block (if the session is in blocking mode)
    /// until the window grows back.
    pub fn window_size(&self) -> usize {
        let (_sess, chan) = self.lock_session();
        unsafe { sys::ssh_channel_window_size(chan).try_into().unwrap() }
    }

    fn read_impl(&self, buf: &mut [u8], is_stderr: bool) -> std::io::Result<usize> {
        Ok(self.read_timeout(buf, is_stderr, None)?)
    }

    fn write_impl(&self, buf: &[u8], is_stderr: bool) -> SshResult<usize> {
        let (sess, chan) = self.lock_session();

        let res = unsafe {
            (if is_stderr {
                sys::ssh_channel_write_stderr
            } else {
                sys::ssh_channel_write
            })(chan, buf.as_ptr() as _, buf.len() as _)
        };

        match res {
            sys::SSH_ERROR => {
                if let Some(err) = sess.last_error() {
                    Err(err)
                } else {
                    Err(Error::fatal("ssh_channel_read_timeout failed"))
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

    /// Returns a struct that implements `std::io::Read`
    /// and that will read data from the stdout channel.
    pub fn stdout(&self) -> impl std::io::Read + '_ {
        ChannelStdout { chan: self }
    }

    /// Returns a struct that implements `std::io::Read`
    /// and that will read data from the stderr channel.
    pub fn stderr(&self) -> impl std::io::Read + '_ {
        ChannelStderr { chan: self }
    }

    /// Returns a struct that implements `std::io::Write`
    /// and that will write data to the stdin channel
    pub fn stdin(&self) -> impl std::io::Write + '_ {
        ChannelStdin { chan: self }
    }
}

/// Represents the stdin stream for the channel.
/// Implements std::io::Write; writing to this struct
/// will write to the stdin of the channel.
struct ChannelStdin<'a> {
    chan: &'a Channel,
}

impl<'a> std::io::Write for ChannelStdin<'a> {
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(self.chan.sess.lock().unwrap().blocking_flush(None)?)
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(self.chan.write_impl(buf, false)?)
    }
}

/// Represents the stdout stream for the channel.
/// Implements std::io::Read; reading from this struct
/// will read from the stdout of the channel.
struct ChannelStdout<'a> {
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
struct ChannelStderr<'a> {
    chan: &'a Channel,
}

impl<'a> std::io::Read for ChannelStderr<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.chan.read_impl(buf, true)
    }
}

/// Indicates available data for the stdout or stderr on a `Channel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollStatus {
    /// The available bytes to read; may be 0
    AvailableBytes(u32),
    /// The channel is in the EOF state
    EndOfFile,
}
