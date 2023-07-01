use std::result;
use std::str::Utf8Error;

use nix::errno::Errno;
use procfs::ProcError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dladdr address ({0:p}) failed")]
    Dladdr(*const ()),

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

    #[error("invalid ELF relocation kind ({0})")]
    InvalidElfRelocationKind(u64),

    #[error("failed reading ELF PLT relocation table")]
    ReadElfPltRelocationTable,

    #[error("failed reading ELF dynamic string table")]
    ReadElfDynamicStringTable,

    #[error("failed reading ELF symbol")]
    ReadElfSymbol,

    #[error("failed finding ELF symbol name: {0}")]
    FindElfSymbolName(#[source] object::Error),

    #[error("ELF symbol name is not UTF8: {0}")]
    NonUtf8ElfSymbolName(#[source] Utf8Error),

    #[error("no GOT entry for function [{0}]")]
    NoGotEntryForFunction(String),

    #[error("failed modifying memory page [{1:x}] protection: {0}")]
    ModifyMemoryPageProtection(Errno, u64),
}

pub type Result<T> = result::Result<T, Error>;
