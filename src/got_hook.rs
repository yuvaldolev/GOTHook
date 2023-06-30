use std::ffi::c_void;

pub struct GotHook;

impl GotHook {
    pub fn new(function_name: &str, callback: *const c_void) -> Self {
        Self
    }
}
