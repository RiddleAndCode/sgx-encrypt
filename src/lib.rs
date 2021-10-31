//! A library for simplifying the retrieval of keys in an SGX enclave. The library is both
//! compatible with `no_std` environments as well as the stable rust compiler.
//!
//! ```
//! # use rdrand::RdRand;
//! # use rand::Rng;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut key: [u8; 32] = RdRand::new()?.gen();
//! sgx_keyreq::get_key(Default::default(), &mut key)?;
//! # Ok(())
//! # }
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
#[macro_use]
extern crate alloc;

pub use sgx_isa;

pub mod ecalls;
mod ffi;
mod keyrequest;

pub use keyrequest::{get_key, KeyOpts};
