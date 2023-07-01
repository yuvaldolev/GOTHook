use std::error::Error;
use std::ffi::{c_char, c_int, CString};
use std::mem;
use std::sync::Mutex;

use nix::fcntl::{self, OFlag};
use nix::sys::sendfile;
use nix::sys::stat::{self, mode_t, Mode};
use nix::unistd;

use gothook::GotHook;

lazy_static::lazy_static! {
    static ref OPEN_HOOK: Mutex<Option<GotHook>> = Mutex::new(None);
}

#[no_mangle]
extern "C" fn open_callback(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    let got_hook = OPEN_HOOK.lock().unwrap();
    if let Some(hook) = &(*got_hook) {
        let original_open = unsafe {
            mem::transmute::<*const (), unsafe extern "C" fn(*const c_char, c_int, mode_t) -> c_int>(
                hook.get_original_function(),
            )
        };

        // Check if the file is being opened as read only.
        if OFlag::O_RDONLY.bits() == flags {
            // File is being opened as read only!
            // Replace it with the pwn file!!!
            let pwned_pathname = CString::new("pwn.txt").unwrap();
            unsafe { original_open(pwned_pathname.as_ptr(), flags, mode) }
        } else {
            unsafe { original_open(pathname, flags, mode) }
        }

        // File isn't opened as read only, invoke the original `open`.
    } else {
        -1
    }
}

#[ctor::ctor]
fn init() {
    let mut open_hook = OPEN_HOOK.lock().unwrap();
    let open_callback_ptr = open_callback as *const ();
    println!("In constructor: hooking open with callback [{open_callback_ptr:p}]");
    *open_hook = Some(GotHook::new("open", open_callback_ptr).unwrap());
}

#[ctor::dtor]
fn fini() {
    println!("In destructor: restoring hooked open");
    let mut open_hook = OPEN_HOOK.lock().unwrap();
    *open_hook = None;
}

fn main() -> Result<(), Box<dyn Error>> {
    // Output the input and output files.
    let input_fd = fcntl::open("input.txt", OFlag::O_RDONLY, Mode::empty())?;
    let output_fd = fcntl::open(
        "output.txt",
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC,
        Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP,
    )?;

    // Get the input file's status.
    let input_stat = stat::fstat(input_fd)?;

    // Copy the input file to the output file.
    sendfile::sendfile(output_fd, input_fd, None, input_stat.st_size as usize)?;

    // Close the files.
    unistd::close(output_fd)?;
    unistd::close(input_fd)?;

    Ok(())
}
