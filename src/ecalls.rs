use crate::ffi;
use core::mem::MaybeUninit;
use sgx_isa::{Keyrequest, Report, Targetinfo};

#[repr(align(16))]
pub struct Align16<T>(pub T);

#[repr(align(128))]
pub struct Align128<T>(pub T);

#[repr(align(512))]
pub struct Align512<T>(pub T);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum ECallStatus {
    Success = ffi::STATUS_SUCCESS,
    InvalidAttribute = ffi::STATUS_INVALID_ATTRIBUTE,
    InvalidCPUSVN = ffi::STATUS_INVALID_CPUSVN,
    InvalidISVSVN = ffi::STATUS_INVALID_ISVSVN,
    InvalidKeyname = ffi::STATUS_INVALID_KEYNAME,
    Unknown = u32::MAX,
}

impl From<u32> for ECallStatus {
    fn from(code: u32) -> Self {
        match code {
            0 => ECallStatus::Success,
            ffi::STATUS_INVALID_ATTRIBUTE => ECallStatus::InvalidAttribute,
            ffi::STATUS_INVALID_CPUSVN => ECallStatus::InvalidCPUSVN,
            ffi::STATUS_INVALID_ISVSVN => ECallStatus::InvalidISVSVN,
            ffi::STATUS_INVALID_KEYNAME => ECallStatus::InvalidKeyname,
            _ => ECallStatus::Unknown,
        }
    }
}

pub fn egetkey(request: Keyrequest) -> Result<[u8; 16], ECallStatus> {
    let mut out = MaybeUninit::<Align16<[u8; 16]>>::uninit();
    unsafe {
        let error = ffi::do_egetkey(
            &Align512(request) as *const Align512<_> as *const u8,
            out.as_mut_ptr() as *mut u8,
        );
        match error {
            0 => Ok(out.assume_init().0),
            error => Err(ECallStatus::from(error)),
        }
    }
}

pub fn ereport(targetinfo: Targetinfo, reportdata: [u8; 64]) -> Result<Report, ECallStatus> {
    let mut out = MaybeUninit::<Align512<Report>>::uninit();
    unsafe {
        let error = ffi::do_ereport(
            &Align512(targetinfo) as *const Align512<_> as *const u8,
            &Align128(reportdata) as *const Align128<_> as *const u8,
            out.as_mut_ptr() as *mut u8,
        );
        match error {
            0 => Ok(out.assume_init().0),
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
