use crate::ecalls::{egetkey, ereport};
use sgx_isa::{Attributes, Keyname, Keypolicy, Keyrequest};

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct SealKeyrequest {
    pub keypolicy: Keypolicy,
    pub attributes: Attributes,
}

impl SealKeyrequest {
    pub fn fill(&self, seed: &mut [u8]) {
        let report = ereport(Default::default(), [0; 64]).unwrap();
        let base_keyrequest = Keyrequest {
            keyname: Keyname::Seal as u16,
            keypolicy: self.keypolicy,
            isvsvn: report.isvsvn,
            cpusvn: report.cpusvn,
            miscmask: report.miscselect.bits(),
            attributemask: [self.attributes.flags.bits(), self.attributes.xfrm],
            ..Default::default()
        };

        let mut chunks = seed.chunks_mut(16);
        while let Some(chunk) = chunks.next() {
            let mut keyid = [0; 32];
            keyid[..chunk.len()].copy_from_slice(chunk);
            let keyrequest = Keyrequest {
                keyid,
                ..base_keyrequest
            };
            let key = egetkey(keyrequest).unwrap();
            chunk.copy_from_slice(&key[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_size(size: usize) {
        let req = SealKeyrequest::default();
        let mut key = vec![0; size];
        req.fill(&mut key);
        assert_ne!(key, vec![0; size]);
    }

    #[test]
    fn empty_seal_key_request() {
        check_size(16);
        check_size(32);
        check_size(48);
        check_size(52);
        check_size(64);
        check_size(128);
        check_size(255);
    }
}
