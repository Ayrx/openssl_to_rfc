# openssl_to_rfc

[![Crates.io](https://img.shields.io/crates/v/openssl_to_rfc?style=flat-square)](https://crates.io/crates/openssl_to_rfc)

`openssl_to_rfc` converts an OpenSSL cipher suite name like
`ECDH-RSA-AES128-GCM-SHA256` to the equivalent RFC version
`TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256`.

This crate is pure Rust and does not depend on `openssl`.
