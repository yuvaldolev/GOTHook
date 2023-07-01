use std::ffi::c_void;
use std::ptr;
use std::slice;

use libc::Dl_info;
use object::File;
use procfs::process::Process;

use crate::error;

pub struct GotHook;

impl GotHook {
    pub fn new(function_name: &str, callback: *const c_void) -> error::Result<Self> {
        // Parse the callback ELF file.
        let callback_information = Self::get_address_symbolic_information(callback)?;
        let callback_elf_data = Self::find_elf_in_memory(callback_information.dli_fbase as u64)?;
        let callback_elf = File::parse(callback_elf_data).map_err(error::Error::ParseObjectFile)?;

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
}
