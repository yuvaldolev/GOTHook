use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::slice;

use libc::Dl_info;
use object::elf::{self, Dyn64, FileHeader64, ProgramHeader64};
use object::endian::Endianness;
use object::read::elf::{Dyn, FileHeader, ProgramHeader};
use object::ReadRef;
use procfs::process::Process;

use crate::error;

pub struct GotHook;

impl GotHook {
    pub fn new(function_name: &str, callback: *const c_void) -> error::Result<Self> {
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
        let plt_relocation_table =
            Self::find_plt_relocation_table(elf_data, elf_dynamic_segment, elf_endian)?;

        Ok(Self)
    }

    fn get_address_symbolic_information(address: *const c_void) -> error::Result<Dl_info> {
        let mut callback_information = Dl_info {
            dli_fname: ptr::null(),
            dli_fbase: ptr::null_mut(),
            dli_sname: ptr::null(),
            dli_saddr: ptr::null_mut(),
        };

        if 0 == unsafe { libc::dladdr(address, &mut callback_information as *mut Dl_info) } {
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

    fn find_plt_relocation_table(
        data: &[u8],
        dynamic_segment: &[Dyn64<Endianness>],
        endian: Endianness,
    ) -> error::Result<()> {
        // Find the plt relocation table address.
        let jmprel_entry = dynamic_segment
            .iter()
            .find(|&e| {
                e.tag32(endian)
                    .map(|t| elf::DT_JMPREL == t)
                    .unwrap_or(false)
            })
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let address = jmprel_entry.d_val(endian);

        // Determine the kind of the relocations in the PLT relocation table.
        let relocation_kind_entry = dynamic_segment
            .iter()
            .find(|&e| {
                e.tag32(endian)
                    .map(|t| elf::DT_PLTREL == t)
                    .unwrap_or(false)
            })
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let relocation_kind =
            relocation_kind_entry
                .val32(endian)
                .ok_or(error::Error::InvalidElfRelocationKind(
                    relocation_kind_entry.d_val(endian),
                ))?;

        // Get the PLT relocation table size.
        let relocation_table_size_entry = dynamic_segment
            .iter()
            .find(|&e| {
                e.tag32(endian)
                    .map(|t| elf::DT_PLTRELSZ == t)
                    .unwrap_or(false)
            })
            .ok_or(error::Error::ElfHasNoPltRelocationTable)?;
        let relocation_table_size = relocation_table_size_entry.d_val(endian);

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
