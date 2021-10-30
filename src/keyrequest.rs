use crate::ecalls::{egetkey, ereport};
use generic_array::{ArrayLength, GenericArray};
use sgx_isa::{Attributes, Keyname, Keypolicy, Keyrequest};

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct SealKeyrequest<U: ArrayLength<u8>> {
    pub seed: GenericArray<u8, U>,
    pub keypolicy: Keypolicy,
    pub attributes: Attributes,
}

impl<U: ArrayLength<u8>> SealKeyrequest<U> {
    pub fn key(&self) -> GenericArray<u8, U> {
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

        let mut out: GenericArray<u8, U> = Default::default();
        let mut chunks = self.seed.as_slice().chunks(16);
        let mut offset = 0;
        while let Some(chunk) = chunks.next() {
            let mut keyid = [0; 32];
            keyid[..chunk.len()].copy_from_slice(chunk);
            let keyrequest = Keyrequest {
                keyid,
                ..base_keyrequest
            };
            let key = egetkey(keyrequest).unwrap();
            out[offset..offset + chunk.len()].copy_from_slice(&key[..chunk.len()]);
            offset += chunk.len();
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::typenum::{U16, U32, U48, U52, U64};

    #[test]
    fn empty_seal_key_request() {
        SealKeyrequest::<U16>::default().key();
        SealKeyrequest::<U32>::default().key();
        SealKeyrequest::<U48>::default().key();
        SealKeyrequest::<U52>::default().key();
        SealKeyrequest::<U64>::default().key();
    }
}
