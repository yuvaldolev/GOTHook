use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::slice;
use std::str;

use libc::Dl_info;
use nix::sys::mman::{self, ProtFlags};
use object::elf::{self, Dyn64, FileHeader64, ProgramHeader64, Rela64, Sym64};
use object::endian::Endianness;
use object::read::elf::{Dyn, FileHeader, ProgramHeader, Rela, Sym};
use object::read::StringTable;
use object::ReadRef;
use procfs::process::Process;

use crate::error;

const PAGE_SIZE: usize = 4096;

pub struct GotHook {
    got_entry: u64,
    original_function: u64,
}

impl GotHook {
    pub fn new(function_name: &str, callback: *const ()) -> error::Result<Self> {
        // Retrieve the callback symbolic information.
        let callback_information = Self::get_address_symbolic_information(callback)?;

        // Find the callback ELF in memory.
        let elf_data = Self::find_elf_in_memory(callback_information.dli_fbase as u64)?;

        // Parse the ELF's header.
        let elf_header: &FileHeader64<Endianness> =
            FileHeader64::parse(elf_data).map_err(error::Error::ParseElfHeader)?;

        // Get the ELF's endianness.
        let elf_endian = elf_header
            .endian()
            .map_err(error::Error::GetElfEndianness)?;

        // Locate the ELF's dynamic segment.
        let elf_dynamic_segment = Self::find_elf_dynamic_segment(elf_data, elf_header, elf_endian)?;

        // Locate the ELF's PLT relocation table.
        let elf_plt_relocation_table =
            Self::find_elf_plt_relocation_table(elf_data, elf_dynamic_segment, elf_endian)?;

        // Locate the ELF's dynamic string table.
        let elf_dynamic_string_table =
            Self::find_elf_dynamic_string_table(elf_data, elf_dynamic_segment, elf_endian)?;

        // Locate the function's GOT entry.
        let function_got_entry = Self::find_elf_function_got_entry(
            callback_information.dli_fbase as u64,
            elf_data,
            elf_dynamic_segment,
            elf_plt_relocation_table,
            elf_dynamic_string_table,
            elf_endian,
            function_name,
        )?;

        // Backup the original function.
        let function_got_entry_pointer = function_got_entry as *const *const ();
        let original_function = unsafe { *function_got_entry_pointer };

        // Hook the function with the callback.
        Self::hook_got_entry(function_got_entry, callback)?;

        Ok(Self {
            got_entry: function_got_entry,
            original_function: original_function as u64,
        })
    }

    pub fn get_original_function(&self) -> *const () {
        self.original_function as *const ()
    }

    fn get_address_symbolic_information(address: *const ()) -> error::Result<Dl_info> {
        let mut callback_information = Dl_info {
            dli_fname: ptr::null(),
            dli_fbase: ptr::null_mut(),
            dli_sname: ptr::null(),
            dli_saddr: ptr::null_mut(),
        };

        if 0 == unsafe {
            libc::dladdr(
                address as *const c_void,
                &mut callback_information as *mut Dl_info,
            )
        } {
            return Err(error::Error::Dladdr(address));
        }

        Ok(callback_information)
    }

    fn find_elf_in_memory(base_address: u64) -> error::Result<&'static [u8]> {
        // Locate the current process in '/proc'.
        let process = Process::myself().map_err(error::Error::FindCurrentProcess)?;

        // Search for the ELF file in the process's maps.
        let mut number_of_elf_mappings_found = 0;
        let mut top_address = 0;

        for map in process
            .maps()
            .map_err(error::Error::ReadProcessMaps)?
            .iter()
        {
            // The ELF file is mapped into 4 sequenced mappings.
            // Find the last one to compute the full ELF memory range.
            if 0 == number_of_elf_mappings_found {
                // Check if the current mapping if the ELF file.
                if map.address.0 == base_address {
                    number_of_elf_mappings_found = 1;
                }
            } else if number_of_elf_mappings_found <= 2 {
                // This is a mapping between the first mapping and the last mapping.
                number_of_elf_mappings_found += 1;
            } else {
                // This is the last mapping!
                top_address = map.address.1;
                break;
            }
        }

        // Create a slice that contains the ELF in-memory.
        Ok(unsafe {
            slice::from_raw_parts(
                base_address as *const u8,
                (top_address - base_address) as usize,
            )
        })
    }

    fn find_elf_dynamic_segment<'a>(
        data: &'a [u8],
        header: &'a FileHeader64<Endianness>,
        endian: Endianness,
    ) -> error::Result<&'a [Dyn64<Endianness>]> {
        // Find the dynamic segment program header.
        let program_header = Self::get_elf_segments(data, header, endian)?
            .iter()
            .find(|&s| elf::PT_DYNAMIC == s.p_type(endian))
            .ok_or(error::Error::ElfHasNoDynamicSegment)?;

        // Read the dynamic segment.
        data.read_slice_at(
            program_header.p_vaddr(endian),
            program_header.p_memsz(endian) as usize / mem::size_of::<Dyn64<Endianness>>(),
        )
        .map_err(|_| error::Error::ReadElfDynamicSegment)
    }

    fn find_elf_plt_relocation_table<'a>(
        data: &'a [u8],
        dynamic_segment: &'a [Dyn64<Endianness>],
        endian: Endianness,
    ) -> error::Result<&'a [Rela64<Endianness>]> {
        // Find the PLT relocation table address.
        let address_entry = dynamic_segment
            .iter()
            .find(|&e| {
                e.tag32(endian)
                    .map(|t| elf::DT_JMPREL == t)
                    .unwrap_or(false)
            })
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let address = address_entry.d_val(endian);

        // Get the PLT relocation table size.
        let size_entry = dynamic_segment
            .iter()
            .find(|&e| {
                e.tag32(endian)
                    .map(|t| elf::DT_PLTRELSZ == t)
                    .unwrap_or(false)
            })
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let size = size_entry.d_val(endian);

        // Read the PLT relocation table.
        data.read_slice_at(address, size as usize)
            .map_err(|_| error::Error::ReadElfPltRelocationTable)
    }

    fn find_elf_dynamic_string_table<'a>(
        data: &'a [u8],
        dynamic_segment: &'a [Dyn64<Endianness>],
        endian: Endianness,
    ) -> error::Result<StringTable<'a, &'a [u8]>> {
        // Find the dynamic string table address.
        let address_entry = dynamic_segment
            .iter()
            .find(|&e| {
                e.tag32(endian)
                    .map(|t| elf::DT_STRTAB == t)
                    .unwrap_or(false)
            })
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let address = address_entry.d_val(endian);

        // Find the dynamic string table size.
        let size_entry = dynamic_segment
            .iter()
            .find(|&e| e.tag32(endian).map(|t| elf::DT_STRSZ == t).unwrap_or(false))
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let size = size_entry.d_val(endian);

        // Read the dynamic string table.
        Ok(StringTable::new(data, address, address + size))
    }

    fn find_elf_function_got_entry(
        base_address: u64,
        data: &[u8],
        dynamic_segment: &[Dyn64<Endianness>],
        plt_relocation_table: &[Rela64<Endianness>],
        dynamic_string_table: StringTable,
        endian: Endianness,
        function_name: &str,
    ) -> error::Result<u64> {
        // Find the dynamic symbol table address.
        let dynamic_symbol_table_address_entry = dynamic_segment
            .iter()
            .find(|&e| {
                e.tag32(endian)
                    .map(|t| elf::DT_SYMTAB == t)
                    .unwrap_or(false)
            })
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let dynamic_symbol_table_address = dynamic_symbol_table_address_entry.d_val(endian);

        // Search for the function's PLT relocation entry.
        for relocation in plt_relocation_table.iter() {
            // Skip non jump slot relocations.
            if elf::R_AARCH64_JUMP_SLOT != relocation.r_type(endian, false) {
                continue;
            }

            // Retrieve the relocation's symbol index.
            let symbol_index = relocation.r_sym(endian, false);

            // Read the relocation's symbol.
            let symbol: &Sym64<Endianness> = data
                .read_at(
                    dynamic_symbol_table_address
                        + (symbol_index as u64 * mem::size_of::<Sym64<Endianness>>() as u64),
                )
                .map_err(|_| error::Error::ReadElfSymbol)?;

            // Read the relocation's symbol name.
            let symbol_name = str::from_utf8(
                symbol
                    .name(endian, dynamic_string_table)
                    .map_err(error::Error::FindElfSymbolName)?,
            )
            .map_err(error::Error::NonUtf8ElfSymbolName)?;

            // Skip relocations that aren't the function.
            if symbol_name != function_name {
                continue;
            }

            // Find function's GOT entry address.
            return Ok(base_address + relocation.r_offset(endian));
        }

        Err(error::Error::NoGotEntryForFunction(String::from(
            function_name,
        )))
    }

    fn hook_got_entry(entry_address: u64, callback: *const ()) -> error::Result<()> {
        // Ensure the GOT entry's page is writable.
        // TODO: We really should backup the original page permissions and
        // restore them after the hooking process is complete.
        let got_entry_page = entry_address & (!(PAGE_SIZE as u64 - 1));
        unsafe {
            mman::mprotect(
                got_entry_page as *mut c_void,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .map_err(|e| error::Error::ModifyMemoryPageProtection(e, got_entry_page))?
        };

        // Hook the GOT entry with the callback.
        let entry_pointer = entry_address as *mut *const ();
        unsafe {
            *entry_pointer = callback;
        }

        Ok(())
    }

    fn get_elf_segments<'a>(
        data: &'a [u8],
        header: &'a FileHeader64<Endianness>,
        endian: Endianness,
    ) -> error::Result<&'a [ProgramHeader64<Endianness>]> {
        // Get the ELF's program headers offset.
        let program_headers_offset: u64 = header.e_phoff(endian).into();
        if 0 == program_headers_offset {
            return Err(error::Error::ElfHasNoProgramHeaders);
        }

        // Get the number of program headers in the ELF.
        let program_headers_number = header
            .phnum(endian, data)
            .map_err(error::Error::GetElfProgramHeadersNumber)?;
        if 0 == program_headers_number {
            return Err(error::Error::ElfHasNoProgramHeaders);
        }

        data.read_slice_at(program_headers_offset, program_headers_number)
            .map_err(|_| error::Error::ReadElfProgramHeaders)
    }
}

impl Drop for GotHook {
    fn drop(&mut self) {
        // Restore the GOT entry to the original function.
        let got_entry_pointer = self.got_entry as *mut *const ();
        unsafe {
            *got_entry_pointer = self.original_function as *const ();
        }
    }
}
