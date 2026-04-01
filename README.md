# `zk-cred-longfellow`

A Rust implementation of the [Anonymous Credentials from ECDSA][anon-creds-ecdsa] scheme, also known
as Longfellow, following the [draft `libZK` specification][draft-google-cfrg-libzk].

This project is part of [ISRG](https://abetterinternet.org)'s research into
[digital identity][isrg-digital-identity].

[anon-creds-ecdsa]: https://eprint.iacr.org/2024/2010.pdf
[draft-google-cfrg-libzk]: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
[isrg-digital-identity]: https://www.abetterinternet.org/post/humandigitalidentityspace/

## Foreign language bindings

Run `wasm-pack build` to produce a WASM build with JavaScript bindings.

Run the following commands to produce a native build with bindings for Kotlin, Swift, or other
languages.

```bash
cargo build --release --features uniffi
cargo run \
    --features uniffi \
    --bin uniffi-bindgen \
    generate \
    --library target/release/libzk_cred_longfellow.so
    --language <LANGUAGE>
    --out-dir out
```
