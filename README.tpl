# {{crate}}

{{readme}}

## Testing

Testing is done with the [Fortanix Rust Enclave Development Platform](https://github.com/fortanix/rust-sgx). After installing the target, to run the tests:

```bash
cargo +nightly test --target x86_64-fortanix-unknown-sgx
# or
cargo +nightly sgx-test
```

License: {{license}}
