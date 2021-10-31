# sgx-keyreq

A library for simplifying the retrieval of keys in an SGX enclave. The library is both
compatible with `no_std` environments as well as the stable rust compiler.

```rust
let mut key: [u8; 32] = RdRand::new()?.gen();
sgx_keyreq::get_key(Default::default(), &mut key)?;
```

## Testing

Testing is done with the [Fortanix Rust Enclave Development Platform](https://github.com/fortanix/rust-sgx). After installing the target, to run the tests:

```
cargo +nightly test --target x86_64-fortanix-unknown-sgx
# or
cargo +nightly sgx-test
```

License: MIT OR Apache-2.0
