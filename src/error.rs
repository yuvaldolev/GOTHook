use std::ffi::c_void;
use std::result;

use procfs::ProcError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dladdr failed: {0:p}")]
    Dladdr(*const c_void),

    #[error("failed finding current process in '/proc': {0}")]
    FindCurrentProcess(#[source] ProcError),

    #[error("failed reading process maps: {0}")]
    ReadProcessMaps(#[source] ProcError),

    #[error("failed parsing object file")]
    ParseObjectFile(#[source] object::Error),
}

pub type Result<T> = result::Result<T, Error>;
