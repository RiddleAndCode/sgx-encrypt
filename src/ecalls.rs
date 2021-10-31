//! Low level `ENCLU` calls for extracting key information from the CPU

use crate::ffi;
use core::fmt;
use core::mem::MaybeUninit;
use sgx_isa::{Keyrequest, Report, Targetinfo};

#[repr(align(16))]
struct Align16<T>(pub T);

#[repr(align(128))]
struct Align128<T>(pub T);

#[repr(align(512))]
struct Align512<T>(pub T);

/// The error status of a malformed `ENCLU` call
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum ECallStatus {
    InvalidAttribute = ffi::STATUS_INVALID_ATTRIBUTE,
    InvalidCPUSVN = ffi::STATUS_INVALID_CPUSVN,
    InvalidISVSVN = ffi::STATUS_INVALID_ISVSVN,
    InvalidKeyname = ffi::STATUS_INVALID_KEYNAME,
    Unknown = u32::MAX,
}

impl From<u32> for ECallStatus {
    fn from(code: u32) -> Self {
        match code {
            ffi::STATUS_INVALID_ATTRIBUTE => ECallStatus::InvalidAttribute,
            ffi::STATUS_INVALID_CPUSVN => ECallStatus::InvalidCPUSVN,
            ffi::STATUS_INVALID_ISVSVN => ECallStatus::InvalidISVSVN,
            ffi::STATUS_INVALID_KEYNAME => ECallStatus::InvalidKeyname,
            _ => ECallStatus::Unknown,
        }
    }
}

impl fmt::Display for ECallStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ECallStatus::InvalidAttribute => f.write_str("ENCLU error: Invalid attribute"),
            ECallStatus::InvalidCPUSVN => f.write_str("ENCLU error: Invalid CPUSVN"),
            ECallStatus::InvalidISVSVN => f.write_str("ENCLU error: Invalid CPUISVN"),
            ECallStatus::InvalidKeyname => f.write_str("ENCLU error: Invalid Keyname"),
            ECallStatus::Unknown => f.write_str("ENCLU error: Unknown"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ECallStatus {}

/// Performs an `ENCLU[EGETKEY]` call. See the [x86
/// instruction](https://www.felixcloutier.com/x86/egetkey) or refer to the SGX SDK docs for more
/// information
pub fn egetkey(request: Keyrequest) -> Result<[u8; 16], ECallStatus> {
    let mut out = MaybeUninit::<Align16<[u8; 16]>>::uninit();
    unsafe {
        let error = ffi::do_egetkey(
            &Align512(request) as *const Align512<_> as *const u8,
            out.as_mut_ptr() as *mut u8,
        );
        match error {
            ffi::STATUS_SUCCESS => Ok(out.assume_init().0),
            error => Err(ECallStatus::from(error)),
        }
    }
}

/// Performs an `ENCLU[EREPORT]` call. See the [x86
/// instruction](https://www.felixcloutier.com/x86/ereport) or refer to the SGX SDK docs for more
/// information
pub fn ereport(targetinfo: Targetinfo, reportdata: [u8; 64]) -> Result<Report, ECallStatus> {
    let mut out = MaybeUninit::<Align512<Report>>::uninit();
    unsafe {
        let error = ffi::do_ereport(
            &Align512(targetinfo) as *const Align512<_> as *const u8,
            &Align128(reportdata) as *const Align128<_> as *const u8,
            out.as_mut_ptr() as *mut u8,
        );
        match error {
            ffi::STATUS_SUCCESS => Ok(out.assume_init().0),
            error => Err(ECallStatus::from(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sgx_isa::*;

    #[test]
    fn empty_seal_key_request() {
        let request = Keyrequest {
            keyname: Keyname::Seal as u16,
            ..Default::default()
        };
        assert!(egetkey(request).is_ok())
    }

    #[test]
    fn report_for_self() {
        assert!(ereport(Default::default(), [0; 64]).is_ok())
    }
}
