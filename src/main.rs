use std::error::Error;
use std::ffi::{c_char, c_int, c_void};
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
extern "C" fn open_callback(_fd: c_int, _path: *const c_char, _mode: mode_t) {}

#[ctor::ctor]
fn init() {
    let mut open_hook = OPEN_HOOK.lock().unwrap();
    let open_callback_ptr = open_callback as *const c_void;
    println!("In constructor: hooking open with callback [{open_callback_ptr:p}]");
    *open_hook = Some(GotHook::new("open", open_callback_ptr).unwrap());
}

#[ctor::dtor]
fn fini() {
    println!("In destructor!");
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("In main: copying input file to output file");

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
