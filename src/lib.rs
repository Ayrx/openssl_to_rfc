//! This crate provides methods to convert OpenSSL cipher suite names into the
//! equivalent RFC name and vice versa.
//!
//! ```
//! use openssl_to_rfc::TLSCipherSuite;
//!
//! let openssl_name = "ECDH-RSA-AES128-GCM-SHA256";
//! let cipher = TLSCipherSuite::from_openssl_name(openssl_name).unwrap();
//!
//! assert_eq!(cipher, TLSCipherSuite::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
//! assert_eq!(cipher.as_openssl_name(), openssl_name);
//! ```
//!
//! For SSLv2 cipher suites, use the `SSLV2CipherSuite` enum instead.

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

            let c = TLSCipherSuite::from_openssl_name(&openssl_name).unwrap();
            assert_eq!(c, cipher);
        }
    }

    #[test]
    fn round_trip_tls_names() {
        for cipher in TLSCipherSuite::iter() {
            let openssl_name = cipher.as_openssl_name();
            let c = TLSCipherSuite::from_openssl_name(&openssl_name).unwrap();
            assert_eq!(c, cipher);
        }
    }

    #[test]
    fn round_trip_ssl2_names() {
        for cipher in SSLV2CipherSuite::iter() {
            let openssl_name = cipher.as_openssl_name();
            let c = SSLV2CipherSuite::from_openssl_name(&openssl_name).unwrap();
            assert_eq!(c, cipher);
        }
    }
}
