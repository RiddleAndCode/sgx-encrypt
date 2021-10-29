use crate::ecalls::{egetkey, ereport};
use cipher::errors::InvalidLength;
use sgx_isa::{Attributes, Keyname, Keypolicy, Keyrequest};

#[derive(Default, Clone, Debug, Copy, Eq, PartialEq)]
pub struct SealKeyrequest {
    pub keypolicy: Keypolicy,
    pub keyid: [u8; 32],
    pub attributes: Attributes,
}

impl SealKeyrequest {
    pub fn from_slice(slice: &[u8]) -> Result<Self, InvalidLength> {
        if slice.len() > 32 {
            Err(InvalidLength)
        } else {
            let mut keyid = [0; 32];
            keyid.copy_from_slice(slice);
            Ok(Self {
                keyid,
                ..Default::default()
            })
        }
    }

    fn egetkey(&self) -> [u8; 16] {
        let report = ereport(Default::default(), [0; 64]).unwrap();
        let keyrequest = Keyrequest {
            keyname: Keyname::Seal as u16,
            keypolicy: self.keypolicy,
            keyid: self.keyid,
            isvsvn: report.isvsvn,
            cpusvn: report.cpusvn,
            miscmask: report.miscselect.bits(),
            attributemask: [self.attributes.flags.bits(), self.attributes.xfrm],
            ..Default::default()
        };
        egetkey(keyrequest).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_seal_key_request() {
        SealKeyrequest::default().egetkey();
    }
}
