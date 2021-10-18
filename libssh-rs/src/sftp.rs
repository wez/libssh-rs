use crate::{Error, SessionHolder, SshResult};
use libssh_rs_sys as sys;
use std::ffi::{CStr, CString};
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
#[error("Sftp error code {}", .0)]
pub struct SftpError(u32);

impl SftpError {
    pub(crate) fn from_session(sftp: sys::sftp_session) -> Self {
        let code = unsafe { sys::sftp_get_error(sftp) as u32 };
        Self(code)
    }

    pub(crate) fn result<T>(sftp: sys::sftp_session, status: i32, res: T) -> SshResult<T> {
        if status == sys::SSH_OK as i32 {
            Ok(res)
        } else {
            Err(Error::Sftp(SftpError::from_session(sftp)))
        }
    }
}

pub struct Sftp {
    pub(crate) sess: Arc<Mutex<SessionHolder>>,
    pub(crate) sftp_inner: sys::sftp_session,
}

unsafe impl Send for Sftp {}

impl Drop for Sftp {
    fn drop(&mut self) {
        let (_sess, sftp) = self.lock_session();
        unsafe {
            sys::sftp_free(sftp);
        }
    }
}

impl Sftp {
    fn lock_session(&self) -> (MutexGuard<SessionHolder>, sys::sftp_session) {
        (self.sess.lock().unwrap(), self.sftp_inner)
    }

    pub(crate) fn init(&self) -> SshResult<()> {
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_init(sftp) };
        SftpError::result(sftp, res, ())
    }

    pub fn create_dir(&self, filename: &str, mode: sys::mode_t) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_mkdir(sftp, filename.as_ptr(), mode) };
        SftpError::result(sftp, res, ())
    }

    pub fn canonicalize(&self, filename: &str) -> SshResult<String> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_canonicalize_path(sftp, filename.as_ptr()) };
        if res.is_null() {
            Err(Error::Sftp(SftpError::from_session(sftp)))
        } else {
            let result = unsafe { CStr::from_ptr(res) }.to_string_lossy().to_string();
            unsafe { sys::ssh_string_free_char(res) };
            Ok(result)
        }
    }

    pub fn chmod(&self, filename: &str, mode: sys::mode_t) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_chmod(sftp, filename.as_ptr(), mode) };
        SftpError::result(sftp, res, ())
    }

    pub fn chown(&self, filename: &str, owner: sys::uid_t, group: sys::gid_t) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_chown(sftp, filename.as_ptr(), owner, group) };
        SftpError::result(sftp, res, ())
    }

    pub fn read_link(&self, filename: &str) -> SshResult<String> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_readlink(sftp, filename.as_ptr()) };
        if res.is_null() {
            Err(Error::Sftp(SftpError::from_session(sftp)))
        } else {
            let result = unsafe { CStr::from_ptr(res) }.to_string_lossy().to_string();
            unsafe { sys::ssh_string_free_char(res) };
            Ok(result)
        }
    }

    pub fn rename(&self, filename: &str, new_name: &str) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let new_name = CString::new(new_name)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_rename(sftp, filename.as_ptr(), new_name.as_ptr()) };
        SftpError::result(sftp, res, ())
    }

    pub fn remove_file(&self, filename: &str) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_unlink(sftp, filename.as_ptr()) };
        SftpError::result(sftp, res, ())
    }

    pub fn remove_dir(&self, filename: &str) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_rmdir(sftp, filename.as_ptr()) };
        SftpError::result(sftp, res, ())
    }

    pub fn symlink(&self, target: &str, dest: &str) -> SshResult<()> {
        let target = CString::new(target)?;
        let dest = CString::new(dest)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_symlink(sftp, target.as_ptr(), dest.as_ptr()) };
        SftpError::result(sftp, res, ())
    }
}
