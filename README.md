# rwarden

[![Crate](https://img.shields.io/crates/v/rwarden)](https://crates.io/crates/rwarden)
[![Docs](https://img.shields.io/static/v1?label=docs&message=latest&color=yellow)](https://docs.rs/rwarden)
[![License](https://img.shields.io/crates/l/rwarden)](https://github.com/nn1ks/rwarden#license)

A Bitwarden API client for Rust.

This project is not associated with the [Bitwarden](https://bitwarden.com) project nor 8bit Solutions
LLC.

## [Documentation](https://docs.rs/rwarden)

## Tests

**IMPORTANT**: Do not run the test suite on your regular Bitwarden account. The tests will create,
modify, and delete (existing) items.

To run the test suite you have to specify a Bitwarden account via environment variables:

- `RWARDEN_EMAIL`: The email address of the account
- `RWARDEN_PASSWORD`: The password of the account
- `RWARDEN_AUTH_URL`: The URL to the authentication endpoint of the Bitwarden server
- `RWARDEN_BASE_URL`: The URL to the base API endpoint of the Bitwarden server

See the documentation of the [`Urls` struct] for more information on what URLs to specify for the
`RWARDEN_*_URL` environment variables.

[`Urls` struct]: https://docs.rs/rwarden/*/rwarden/struct.Urls.html

### Running the tests

```
cargo test
```

### Running additional tests

Some tests are ignored by default because they interfere with other tests. You can run them manually
with:

```
cargo test cipher_purge -- --include-ignored --exact
```

### Running tests with [vaultwarden]

[vaultwarden]: https://github.com/dani-garcia/vaultwarden

Vaultwarden is missing some features and some tests do not work because of this. To disable the tests
that are incompatible with vaultwarden, run:

```
cargo test --features disable_vaultwarden_incompatible_tests
```

## License

Licensed under either of [Apache License, Version 2.0] or [MIT License] at your option.

[Apache License, Version 2.0]: https://github.com/nn1ks/rwarden/blob/master/LICENSE-APACHE
[MIT License]: https://github.com/nn1ks/rwarden/blob/master/LICENSE-MIT

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
