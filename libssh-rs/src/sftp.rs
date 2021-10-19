use crate::{Error, SessionHolder, SshResult};
use libssh_rs_sys as sys;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
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

    /// Create a directory.
    /// `mode` specifies the permission bits to use on the directory.
    /// They will be modified by the effective umask on the server.
    pub fn create_dir(&self, filename: &str, mode: sys::mode_t) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_mkdir(sftp, filename.as_ptr(), mode) };
        SftpError::result(sftp, res, ())
    }

    /// Canonicalize `filename`, resolving relative directory references
    /// and symlinks.
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

    /// Change the permissions of a file
    pub fn chmod(&self, filename: &str, mode: sys::mode_t) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_chmod(sftp, filename.as_ptr(), mode) };
        SftpError::result(sftp, res, ())
    }

    /// Change the ownership of a file.
    pub fn chown(&self, filename: &str, owner: sys::uid_t, group: sys::gid_t) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_chown(sftp, filename.as_ptr(), owner, group) };
        SftpError::result(sftp, res, ())
    }

    /// Read the payload of a symlink
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

    /// Change certain metadata attributes of the named file.
    pub fn set_metadata(&self, filename: &str, metadata: &SetAttributes) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let mut attributes: sys::sftp_attributes_struct = unsafe { std::mem::zeroed() };

        if let Some(size) = metadata.size {
            attributes.size = size;
            attributes.flags |= sys::SSH_FILEXFER_ATTR_SIZE;
        }

        if let Some((uid, gid)) = metadata.uid_gid {
            attributes.uid = uid;
            attributes.gid = gid;
            attributes.flags |= sys::SSH_FILEXFER_ATTR_UIDGID;
        }

        if let Some(perms) = metadata.permissions {
            attributes.permissions = perms;
            attributes.flags |= sys::SSH_FILEXFER_ATTR_PERMISSIONS;
        }

        if let Some((atime, mtime)) = metadata.atime_mtime {
            attributes.atime = atime
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("SystemTime to always be > UNIX_EPOCH")
                .as_secs()
                .try_into()
                .unwrap();
            attributes.mtime = mtime
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("SystemTime to always be > UNIX_EPOCH")
                .as_secs()
                .try_into()
                .unwrap();
            attributes.flags |= sys::SSH_FILEXFER_ATTR_ACMODTIME;
        }

        let res = unsafe { sys::sftp_setstat(sftp, filename.as_ptr(), &mut attributes) };
        SftpError::result(sftp, res, ())
    }

    /// Retrieve metadata for a file, traversing symlinks
    pub fn metadata(&self, filename: &str) -> SshResult<Metadata> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let attr = unsafe { sys::sftp_stat(sftp, filename.as_ptr()) };
        if attr.is_null() {
            Err(Error::Sftp(SftpError::from_session(sftp)))
        } else {
            Ok(Metadata { attr })
        }
    }

    /// Retrieve metadata for a file, without traversing symlinks.
    pub fn symlink_metadata(&self, filename: &str) -> SshResult<Metadata> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let attr = unsafe { sys::sftp_lstat(sftp, filename.as_ptr()) };
        if attr.is_null() {
            Err(Error::Sftp(SftpError::from_session(sftp)))
        } else {
            Ok(Metadata { attr })
        }
    }

    /// Rename a file from `filename` to `new_name`
    pub fn rename(&self, filename: &str, new_name: &str) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let new_name = CString::new(new_name)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_rename(sftp, filename.as_ptr(), new_name.as_ptr()) };
        SftpError::result(sftp, res, ())
    }

    /// Remove a file or an empty directory
    pub fn remove_file(&self, filename: &str) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_unlink(sftp, filename.as_ptr()) };
        SftpError::result(sftp, res, ())
    }

    /// Remove an empty directory
    pub fn remove_dir(&self, filename: &str) -> SshResult<()> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_rmdir(sftp, filename.as_ptr()) };
        SftpError::result(sftp, res, ())
    }

    /// Create a symlink on the server.
    /// `target` is the filename of the symlink to be created,
    /// and `dest` is the payload of the symlink.
    pub fn symlink(&self, target: &str, dest: &str) -> SshResult<()> {
        let target = CString::new(target)?;
        let dest = CString::new(dest)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_symlink(sftp, target.as_ptr(), dest.as_ptr()) };
        SftpError::result(sftp, res, ())
    }

    /// Open a file on the server.
    /// `accesstype` corresponds to the `open(2)` `flags` parameter
    /// and controls whether the file is opened for read/write and so on.
    /// `mode` specified the permission bits to use when creating a new file;
    /// they will be modified by the effective umask on the server side.
    pub fn open(
        &self,
        filename: &str,
        accesstype: c_int,
        mode: sys::mode_t,
    ) -> SshResult<SftpFile> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_open(sftp, filename.as_ptr(), accesstype, mode) };
        if res.is_null() {
            Err(Error::Sftp(SftpError::from_session(sftp)))
        } else {
            Ok(SftpFile {
                sess: Arc::clone(&self.sess),
                file_inner: res,
                sftp: sftp,
            })
        }
    }

    /// Open a directory to obtain directory entries
    pub fn open_dir(&self, filename: &str) -> SshResult<SftpDir> {
        let filename = CString::new(filename)?;
        let (_sess, sftp) = self.lock_session();
        let res = unsafe { sys::sftp_opendir(sftp, filename.as_ptr()) };
        if res.is_null() {
            Err(Error::Sftp(SftpError::from_session(sftp)))
        } else {
            Ok(SftpDir {
                sess: Arc::clone(&self.sess),
                dir_inner: res,
                sftp: sftp,
            })
        }
    }

    /// Convenience function that reads all of the directory entries
    /// into a Vec.  If you need to deal with very large directories,
    /// you may wish to directly use [open_dir](#method.open_dir)
    /// and manually iterate the directory contents.
    pub fn read_dir(&self, filename: &str) -> SshResult<Vec<Metadata>> {
        let dir = self.open_dir(filename)?;
        let mut res = vec![];
        while let Some(item) = dir.read_dir() {
            res.push(item?);
        }
        Ok(res)
    }
}

pub struct SftpFile {
    pub(crate) sess: Arc<Mutex<SessionHolder>>,
    pub(crate) file_inner: sys::sftp_file,
    pub(crate) sftp: sys::sftp_session,
}

unsafe impl Send for SftpFile {}

impl Drop for SftpFile {
    fn drop(&mut self) {
        let (_sess, file) = self.lock_session();
        unsafe {
            sys::sftp_close(file);
        }
    }
}

impl SftpFile {
    fn lock_session(&self) -> (MutexGuard<SessionHolder>, sys::sftp_file) {
        (self.sess.lock().unwrap(), self.file_inner)
    }

    pub fn set_blocking(&self, blocking: bool) {
        let (_sess, file) = self.lock_session();
        if blocking {
            unsafe { sys::sftp_file_set_blocking(file) }
        } else {
            unsafe { sys::sftp_file_set_nonblocking(file) }
        }
    }

    /// Retrieve metadata for the file
    pub fn metadata(&self) -> SshResult<Metadata> {
        let (_sess, file) = self.lock_session();
        let attr = unsafe { sys::sftp_fstat(file) };
        if attr.is_null() {
            Err(Error::Sftp(SftpError::from_session(self.sftp)))
        } else {
            Ok(Metadata { attr })
        }
    }
}

fn io_err_from_sftp(sftp: sys::sftp_session, reason: &str) -> std::io::Error {
    use std::io::ErrorKind;
    let res = unsafe { sys::sftp_get_error(sftp) };
    let kind = match res as u32 {
        sys::SSH_FX_OK => ErrorKind::Other,
        sys::SSH_FX_EOF => ErrorKind::UnexpectedEof,
        sys::SSH_FX_NO_SUCH_FILE => ErrorKind::NotFound,
        sys::SSH_FX_PERMISSION_DENIED => ErrorKind::PermissionDenied,
        sys::SSH_FX_FAILURE => ErrorKind::Other,
        sys::SSH_FX_BAD_MESSAGE => ErrorKind::Other,
        sys::SSH_FX_NO_CONNECTION => ErrorKind::NotConnected,
        sys::SSH_FX_CONNECTION_LOST => ErrorKind::ConnectionReset,
        sys::SSH_FX_OP_UNSUPPORTED => ErrorKind::Unsupported,
        sys::SSH_FX_INVALID_HANDLE => ErrorKind::Other,
        sys::SSH_FX_NO_SUCH_PATH => ErrorKind::NotFound,
        sys::SSH_FX_FILE_ALREADY_EXISTS => ErrorKind::AlreadyExists,
        sys::SSH_FX_WRITE_PROTECT => ErrorKind::Other,
        sys::SSH_FX_NO_MEDIA => ErrorKind::Other,
        _ => ErrorKind::Other,
    };
    std::io::Error::new(kind, format!("{}: sftp error code {}", reason, res))
}

impl std::io::Read for SftpFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (_sess, file) = self.lock_session();

        let res = unsafe { sys::sftp_read(file, buf.as_mut_ptr() as _, buf.len()) };

        if res >= 0 {
            Ok(res as usize)
        } else {
            let err = io_err_from_sftp(self.sftp, "read");
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Ok(0)
            } else {
                Err(err)
            }
        }
    }
}

impl std::io::Write for SftpFile {
    fn flush(&mut self) -> std::io::Result<()> {
        let (_sess, file) = self.lock_session();
        let res = unsafe { sys::sftp_fsync(file) };
        if res == 0 {
            Ok(())
        } else {
            Err(io_err_from_sftp(self.sftp, "fsync"))
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let (_sess, file) = self.lock_session();

        let res = unsafe { sys::sftp_write(file, buf.as_ptr() as _, buf.len()) };

        if res >= 0 {
            Ok(res as usize)
        } else {
            let err = io_err_from_sftp(self.sftp, "write");
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Ok(0)
            } else {
                Err(err)
            }
        }
    }
}

impl std::io::Seek for SftpFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let (_sess, file) = self.lock_session();
        match pos {
            std::io::SeekFrom::Start(p) => {
                let res = unsafe { sys::sftp_seek64(file, p) };
                if res == 0 {
                    Ok(p)
                } else {
                    Err(io_err_from_sftp(self.sftp, "seek"))
                }
            }
            std::io::SeekFrom::End(p) => {
                let end = self.metadata().map_err(|e| e)?.len().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "metadata didn't return the length",
                    )
                })?;
                let target = if p < 0 {
                    end.saturating_sub(p.abs() as u64)
                } else {
                    end.saturating_add(p as u64)
                };
                let res = unsafe { sys::sftp_seek64(file, target) };
                if res == 0 {
                    Ok(target)
                } else {
                    Err(io_err_from_sftp(self.sftp, "seek"))
                }
            }
            std::io::SeekFrom::Current(p) => {
                let current = unsafe { sys::sftp_tell(file) };
                let target = if p < 0 {
                    current.saturating_sub(p.abs() as u64)
                } else {
                    current.saturating_add(p as u64)
                };
                let res = unsafe { sys::sftp_seek64(file, target) };
                if res == 0 {
                    Ok(target)
                } else {
                    Err(io_err_from_sftp(self.sftp, "seek"))
                }
            }
        }
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        let (_sess, file) = self.lock_session();
        let current = unsafe { sys::sftp_tell(file) };
        Ok(current)
    }
}

/// Change multiple file attributes at once.
/// If a field is_some, then its value will be applied
/// to the file on the server side.  If it is_none, then
/// that particular field will be left unmodified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttributes {
    /// Change the file length
    pub size: Option<u64>,
    /// Change the ownership (chown)
    pub uid_gid: Option<(sys::uid_t, sys::gid_t)>,
    /// Change the permissions (chmod)
    pub permissions: Option<u32>,
    /// Note that the protocol/libssh implementation has
    /// 1-second granularity for access and mtime
    pub atime_mtime: Option<(SystemTime, SystemTime)>,
}

/// Represents metadata about a file.
/// libssh returns this in a couple of contexts, and not all
/// fields are used in all contexts.
pub struct Metadata {
    attr: sys::sftp_attributes,
}

impl Drop for Metadata {
    fn drop(&mut self) {
        unsafe { sys::sftp_attributes_free(self.attr) }
    }
}

impl Metadata {
    fn attr(&self) -> &sys::sftp_attributes_struct {
        unsafe { &*self.attr }
    }

    pub fn len(&self) -> Option<u64> {
        if self.attr().flags & sys::SSH_FILEXFER_ATTR_SIZE != 0 {
            Some(self.attr().size)
        } else {
            None
        }
    }

    fn name_helper(&self, name: *const c_char) -> Option<&str> {
        if name.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(name) }.to_str().ok()
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name_helper(self.attr().name)
    }

    /// libssh docs say that this is the ls -l output on openssh
    /// servers, but is unreliable with other servers
    pub fn long_name(&self) -> Option<&str> {
        self.name_helper(self.attr().longname)
    }

    /// Set in openssh version 4 and up
    pub fn owner(&self) -> Option<&str> {
        self.name_helper(self.attr().owner)
    }

    /// Set in openssh version 4 and up
    pub fn group(&self) -> Option<&str> {
        self.name_helper(self.attr().group)
    }

    /// Flags the indicate which attributes are present.
    /// Is a bitmask of `SSH_FILEXFER_ATTR_XXX` constants
    pub fn flags(&self) -> u32 {
        self.attr().flags
    }

    /// The owner uid of the file
    pub fn uid(&self) -> Option<u32> {
        if self.attr().flags & sys::SSH_FILEXFER_ATTR_UIDGID != 0 {
            Some(self.attr().uid)
        } else {
            None
        }
    }

    /// The owner gid of the file
    pub fn gid(&self) -> Option<u32> {
        if self.attr().flags & sys::SSH_FILEXFER_ATTR_UIDGID != 0 {
            Some(self.attr().gid)
        } else {
            None
        }
    }

    /// The unix mode_t permission bits
    pub fn permissions(&self) -> Option<u32> {
        if self.attr().flags & sys::SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            Some(self.attr().permissions)
        } else {
            None
        }
    }

    /// The type of the file decoded from the permissions
    pub fn file_type(&self) -> Option<FileType> {
        if self.attr().flags & sys::SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            Some(match self.attr().type_ as u32 {
                sys::SSH_FILEXFER_TYPE_SPECIAL => FileType::Special,
                sys::SSH_FILEXFER_TYPE_SYMLINK => FileType::Symlink,
                sys::SSH_FILEXFER_TYPE_REGULAR => FileType::Regular,
                sys::SSH_FILEXFER_TYPE_DIRECTORY => FileType::Directory,
                sys::SSH_FILEXFER_TYPE_UNKNOWN | _ => FileType::Unknown,
            })
        } else {
            None
        }
    }

    /// The last-accessed time
    pub fn accessed(&self) -> Option<SystemTime> {
        let duration = if self.attr().flags & sys::SSH_FILEXFER_ATTR_ACCESSTIME != 0 {
            Duration::from_secs(self.attr().atime64)
                + Duration::from_nanos(
                    if self.attr().flags & sys::SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0 {
                        self.attr().atime_nseconds.into()
                    } else {
                        0
                    },
                )
        } else if self.attr().flags & sys::SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            Duration::from_secs(self.attr().atime.into())
        } else {
            return None;
        };
        SystemTime::UNIX_EPOCH.checked_add(duration)
    }

    /// The file creation time
    pub fn created(&self) -> Option<SystemTime> {
        let duration = if self.attr().flags & sys::SSH_FILEXFER_ATTR_CREATETIME != 0 {
            Duration::from_secs(self.attr().createtime)
                + Duration::from_nanos(
                    if self.attr().flags & sys::SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0 {
                        self.attr().createtime_nseconds.into()
                    } else {
                        0
                    },
                )
        } else {
            return None;
        };
        SystemTime::UNIX_EPOCH.checked_add(duration)
    }

    /// The file modification time
    pub fn modified(&self) -> Option<SystemTime> {
        let duration = if self.attr().flags & sys::SSH_FILEXFER_ATTR_MODIFYTIME != 0 {
            Duration::from_secs(self.attr().mtime64)
                + Duration::from_nanos(
                    if self.attr().flags & sys::SSH_FILEXFER_ATTR_SUBSECOND_TIMES != 0 {
                        self.attr().mtime_nseconds.into()
                    } else {
                        0
                    },
                )
        } else if self.attr().flags & sys::SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            Duration::from_secs(self.attr().mtime.into())
        } else {
            return None;
        };
        SystemTime::UNIX_EPOCH.checked_add(duration)
    }
}

pub struct SftpDir {
    pub(crate) sess: Arc<Mutex<SessionHolder>>,
    pub(crate) dir_inner: sys::sftp_dir,
    pub(crate) sftp: sys::sftp_session,
}

unsafe impl Send for SftpDir {}

impl Drop for SftpDir {
    fn drop(&mut self) {
        let (_sess, dir) = self.lock_session();
        unsafe {
            sys::sftp_closedir(dir);
        }
    }
}

impl SftpDir {
    fn lock_session(&self) -> (MutexGuard<SessionHolder>, sys::sftp_dir) {
        (self.sess.lock().unwrap(), self.dir_inner)
    }

    /// Read the next entry from the directory.
    /// Returns None if there are no more entries.
    pub fn read_dir(&self) -> Option<SshResult<Metadata>> {
        let (_sess, dir) = self.lock_session();
        let attr = unsafe { sys::sftp_readdir(self.sftp, dir) };
        if attr.is_null() {
            if unsafe { sys::sftp_dir_eof(dir) } == 1 {
                None
            } else {
                Some(Err(Error::Sftp(SftpError::from_session(self.sftp))))
            }
        } else {
            Some(Ok(Metadata { attr }))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Special,
    Symlink,
    Regular,
    Directory,
    Unknown,
}
