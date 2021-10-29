extern "C" {
    pub fn do_egetkey(request: *const u8, out: *mut u8) -> u32;
    pub fn do_ereport(targetinfo: *const u8, reportdata: *const u8, out: *mut u8) -> u32;
}

macro_rules! bit_error {
    ($err:literal) => {
        1 << $err
    };
}

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_ATTRIBUTE: u32 = bit_error!(1);
pub const STATUS_INVALID_CPUSVN: u32 = bit_error!(5);
pub const STATUS_INVALID_ISVSVN: u32 = bit_error!(6);
pub const STATUS_INVALID_KEYNAME: u32 = bit_error!(8);
