//! This crate converts an OpenSSL cipher suite name to the equivalent
//! RFC name.
//!
//! ```
//! use openssl_to_rfc::TLSCipherSuite;
//! let cipher = TLSCipherSuite::from_openssl_name("ECDH-RSA-AES128-GCM-SHA256").unwrap();
//! assert_eq!(cipher, TLSCipherSuite::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
//! ```

mod ssl2;
pub use ssl2::SSLV2CipherSuite;

mod tls;
pub use tls::TLSCipherSuite;

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn round_trip_openssl() {
        for cipher in TLSCipherSuite::iter() {
            let openssl_name = openssl::ssl::cipher_name(&cipher.to_string());

            // We skip the test here if openssl::ssl::cipher_name does not
            // recognize the provided RFC name. This usually happens for very
            // old cipher suites that current OpenSSL no longer supports.
            if openssl_name == "(NONE)" {
                return;
            }

            let c = TLSCipherSuite::from_openssl_name(openssl_name).unwrap();
            assert_eq!(c, cipher);
        }
    }
}
