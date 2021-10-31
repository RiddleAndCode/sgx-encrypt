use crate::ecalls::{egetkey, ereport, ECallStatus};
use sgx_isa::{Keyname, Keypolicy, Keyrequest};

/// Options for requesting a key
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KeyOpts {
    pub name: Keyname,
    pub policy: Keypolicy,
}

impl Default for KeyOpts {
    fn default() -> Self {
        Self {
            name: Keyname::Seal,
            policy: Keypolicy::MRSIGNER,
        }
    }
}

/// Fills a key in-place based on a seed
///
/// This function loops over the seed and builds multiple keyrequests based on the seed.
/// Because of the 128 bit nature of the returned keys, the higher the entropy of the seed,
/// the higher entropy of the resulting key
pub fn get_key(opts: KeyOpts, seed: &mut [u8]) -> Result<(), ECallStatus> {
    let report = ereport(Default::default(), [0; 64])?;
    let base_keyrequest = Keyrequest {
        keyname: opts.name as u16,
        keypolicy: opts.policy,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        miscmask: report.miscselect.bits(),
        attributemask: [report.attributes.flags.bits(), report.attributes.xfrm],
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
        let key = egetkey(keyrequest)?;
        chunk.copy_from_slice(&key[..chunk.len()]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_menclave() {
        let mut key = [0; 32];
        get_key(
            KeyOpts {
                policy: Keypolicy::MRENCLAVE,
                ..Default::default()
            },
            &mut key,
        )
        .unwrap();
        assert_ne!(key, [0; 32]);
    }

    #[test]
    fn get_mrsigner() {
        let mut key = [0; 32];
        get_key(
            KeyOpts {
                policy: Keypolicy::MRSIGNER,
                ..Default::default()
            },
            &mut key,
        )
        .unwrap();
        assert_ne!(key, [0; 32]);
    }

    #[test]
    fn get_seal() {
        let mut key = [0; 32];
        get_key(
            KeyOpts {
                name: Keyname::Seal,
                ..Default::default()
            },
            &mut key,
        )
        .unwrap();
        assert_ne!(key, [0; 32]);
    }

    #[test]
    fn get_provision() {
        let mut key = [0; 32];
        let res = get_key(
            KeyOpts {
                name: Keyname::Provision,
                ..Default::default()
            },
            &mut key,
        );
        assert_eq!(res, Err(ECallStatus::InvalidAttribute));
    }

    #[test]
    fn get_provision_seal() {
        let mut key = [0; 32];
        let res = get_key(
            KeyOpts {
                name: Keyname::ProvisionSeal,
                ..Default::default()
            },
            &mut key,
        );
        assert_eq!(res, Err(ECallStatus::InvalidAttribute));
    }

    #[test]
    fn get_einittoken() {
        let mut key = [0; 32];
        let res = get_key(
            KeyOpts {
                name: Keyname::Einittoken,
                ..Default::default()
            },
            &mut key,
        );
        assert_eq!(res, Err(ECallStatus::InvalidAttribute));
    }

    #[test]
    fn get_report() {
        let mut key = [0; 32];
        get_key(
            KeyOpts {
                name: Keyname::Report,
                ..Default::default()
            },
            &mut key,
        )
        .unwrap();
        assert_ne!(key, [0; 32]);
    }

    fn check_size(size: usize) {
        let mut key = vec![0; size];
        get_key(Default::default(), &mut key).unwrap();
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
