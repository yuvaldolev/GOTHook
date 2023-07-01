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

    #[error("failed parsing ELF header: {0}")]
    ParseElfHeader(#[source] object::Error),

    #[error("failed getting ELF endianness: {0}")]
    GetElfEndianness(#[source] object::Error),

    #[error("ELF has no program headers")]
    ElfHasNoProgramHeaders,

    #[error("failed getting number of ELF program headers: {0}")]
    GetElfProgramHeadersNumber(#[source] object::Error),

    #[error("failed reading ELF program headers")]
    ReadElfProgramHeaders,

    #[error("ELF has no dynamic segment")]
    ElfHasNoDynamicSegment,

    #[error("failed reading ELF dynamic segment")]
    ReadElfDynamicSegment,

    #[error("ELF has no PLT relocation table")]
    ElfHasNoPltRelocationTable,

    #[error("invalid ELF relocation kind ({0})"]
    InvalidElfRelocationKind(u64),
}

pub type Result<T> = result::Result<T, Error>;
