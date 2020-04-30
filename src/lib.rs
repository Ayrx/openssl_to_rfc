//! This crate converts an OpenSSL cipher suite name to the equivalent
//! RFC name.
//!
//! ```
//! use openssl_to_rfc::TLSCipherSuite;
//! let cipher = TLSCipherSuite::from_openssl_name("ECDH-RSA-AES128-GCM-SHA256").unwrap();
//! assert_eq!(cipher, TLSCipherSuite::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
//! ```

use strum_macros::{Display, EnumIter, EnumString};

#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug, Display, EnumIter, EnumString)]
pub enum SSLV2CipherSuite {
    SSL_CK_RC4_128_WITH_MD5,
    SSL_CK_RC4_128_EXPORT40_WITH_MD5,
    SSL_CK_RC2_128_CBC_WITH_MD5,
    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
    SSL_CK_IDEA_128_CBC_WITH_MD5,
    SSL_CK_DES_64_CBC_WITH_MD5,
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
    SSL_CK_RC4_64_WITH_MD5,
    TLS_RSA_WITH_NULL_MD5,
}

impl SSLV2CipherSuite {
    pub fn from_openssl_name(name: &str) -> Option<SSLV2CipherSuite> {
        match name {
            "RC4-MD5" => Some(Self::SSL_CK_RC4_128_WITH_MD5),
            "EXP-RC4-MD5"=> Some(Self::SSL_CK_RC4_128_EXPORT40_WITH_MD5),
            "RC2-CBC-MD5"=> Some(Self::SSL_CK_RC2_128_CBC_WITH_MD5),
            "EXP-RC2-CBC-MD5" => Some(Self::SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5),
            "IDEA-CBC-MD5" => Some(Self::SSL_CK_IDEA_128_CBC_WITH_MD5),
            "DES-CBC-MD5" => Some(Self::SSL_CK_DES_64_CBC_WITH_MD5),
            "DES-CBC3-MD5" => Some(Self::SSL_CK_DES_192_EDE3_CBC_WITH_MD5),
            "RC4-64-MD5" => Some(Self::SSL_CK_RC4_64_WITH_MD5),
            "NULL-MD5" => Some(Self::TLS_RSA_WITH_NULL_MD5),
            _ =>  None,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug, Display, EnumIter, EnumString)]
pub enum TLSCipherSuite {
    TLS_RSA_WITH_NULL_MD5,
    TLS_RSA_WITH_NULL_SHA,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5,
    TLS_RSA_WITH_RC4_128_MD5,
    TLS_RSA_WITH_RC4_128_SHA,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
    TLS_RSA_WITH_IDEA_CBC_SHA,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_RSA_WITH_DES_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_DSS_WITH_DES_CBC_SHA,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_RSA_WITH_DES_CBC_SHA,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_DSS_WITH_DES_CBC_SHA,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_RSA_WITH_DES_CBC_SHA,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
    TLS_DH_anon_WITH_RC4_128_MD5,
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_anon_WITH_DES_CBC_SHA,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
    TLS_KRB5_WITH_DES_CBC_SHA,
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
    TLS_KRB5_WITH_RC4_128_SHA,
    TLS_KRB5_WITH_IDEA_CBC_SHA,
    TLS_KRB5_WITH_DES_CBC_MD5,
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
    TLS_KRB5_WITH_RC4_128_MD5,
    TLS_KRB5_WITH_IDEA_CBC_MD5,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DH_anon_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_DH_anon_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_NULL_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
    TLS_RSA_EXPORT1024_WITH_RC4_56_MD5,
    TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
    TLS_DHE_DSS_WITH_RC4_128_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_anon_WITH_AES_128_CBC_SHA256,
    TLS_DH_anon_WITH_AES_256_CBC_SHA256,
    TLS_GOSTR341094_WITH_28147_CNT_IMIT,
    TLS_GOSTR341001_WITH_28147_CNT_IMIT,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
    TLS_PSK_WITH_RC4_128_SHA,
    TLS_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_PSK_WITH_AES_128_CBC_SHA,
    TLS_PSK_WITH_AES_256_CBC_SHA,
    TLS_RSA_PSK_WITH_RC4_128_SHA,
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_SEED_CBC_SHA,
    TLS_DH_DSS_WITH_SEED_CBC_SHA,
    TLS_DH_RSA_WITH_SEED_CBC_SHA,
    TLS_DHE_DSS_WITH_SEED_CBC_SHA,
    TLS_DHE_RSA_WITH_SEED_CBC_SHA,
    TLS_DH_anon_WITH_SEED_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_anon_WITH_AES_128_GCM_SHA256,
    TLS_DH_anon_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_FALLBACK_SCSV,
    TLS_ECDH_ECDSA_WITH_NULL_SHA,
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_NULL_SHA,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDH_RSA_WITH_NULL_SHA,
    TLS_ECDH_RSA_WITH_RC4_128_SHA,
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_NULL_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDH_anon_WITH_NULL_SHA,
    TLS_ECDH_anon_WITH_RC4_128_SHA,
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_RSA_WITH_AES_128_CCM,
    TLS_RSA_WITH_AES_256_CCM,
    TLS_DHE_RSA_WITH_AES_128_CCM,
    TLS_DHE_RSA_WITH_AES_256_CCM,
    TLS_RSA_WITH_AES_128_CCM_8,
    TLS_RSA_WITH_AES_256_CCM_8,
    TLS_DHE_RSA_WITH_AES_128_CCM_8,
    TLS_DHE_RSA_WITH_AES_256_CCM_8,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    TLS_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
    TLS_DHE_PSK_WITH_AES_128_CCM,
    TLS_PSK_DHE_WITH_AES_128_CCM_8,
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
    TLS_DHE_PSK_WITH_AES_256_CCM,
    TLS_PSK_DHE_WITH_AES_256_CCM_8,
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_PSK_WITH_NULL_SHA,
    TLS_DHE_PSK_WITH_NULL_SHA256,
    TLS_DHE_PSK_WITH_NULL_SHA384,
    TLS_DHE_PSK_WITH_RC4_128_SHA,
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_PSK_WITH_NULL_SHA,
    TLS_ECDHE_PSK_WITH_NULL_SHA256,
    TLS_ECDHE_PSK_WITH_NULL_SHA384,
    TLS_ECDHE_PSK_WITH_RC4_128_SHA,
    TLS_GOSTR341001_WITH_NULL_GOSTR3411,
    TLS_GOSTR341094_WITH_NULL_GOSTR3411,
    TLS_PSK_WITH_AES_128_CBC_SHA256,
    TLS_PSK_WITH_AES_128_CCM,
    TLS_PSK_WITH_AES_128_CCM_8,
    TLS_PSK_WITH_AES_128_GCM_SHA256,
    TLS_PSK_WITH_AES_256_CBC_SHA384,
    TLS_PSK_WITH_AES_256_CCM,
    TLS_PSK_WITH_AES_256_CCM_8,
    TLS_PSK_WITH_AES_256_GCM_SHA384,
    TLS_PSK_WITH_ARIA_128_GCM_SHA256,
    TLS_PSK_WITH_ARIA_256_GCM_SHA384,
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_PSK_WITH_NULL_SHA,
    TLS_PSK_WITH_NULL_SHA256,
    TLS_PSK_WITH_NULL_SHA384,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_RSA_PSK_WITH_NULL_SHA,
    TLS_RSA_PSK_WITH_NULL_SHA256,
    TLS_RSA_PSK_WITH_NULL_SHA384,
}

impl TLSCipherSuite {
    pub fn from_openssl_name(name: &str) -> Option<TLSCipherSuite> {
        match name {
            "NULL-MD5" => Some(Self::TLS_RSA_WITH_NULL_MD5),
            "NULL-SHA" => Some(Self::TLS_RSA_WITH_NULL_SHA),
            "EXP-RC4-MD5" => Some(Self::TLS_RSA_EXPORT_WITH_RC4_40_MD5),
            "RC4-MD5" => Some(Self::TLS_RSA_WITH_RC4_128_MD5),
            "RC4-SHA" => Some(Self::TLS_RSA_WITH_RC4_128_SHA),
            "EXP-RC2-CBC-MD5" => Some(Self::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5),
            "IDEA-CBC-SHA" => Some(Self::TLS_RSA_WITH_IDEA_CBC_SHA),
            "EXP-DES-CBC-SHA" => Some(Self::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA),
            "DES-CBC-SHA" => Some(Self::TLS_RSA_WITH_DES_CBC_SHA),
            "DES-CBC3-SHA" => Some(Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA),
            "EXP-DH-DSS-DES-CBC-SHA" => Some(Self::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA),
            "DH-DSS-DES-CBC-SHA" => Some(Self::TLS_DH_DSS_WITH_DES_CBC_SHA),
            "DH-DSS-DES-CBC3-SHA" => Some(Self::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA),
            "EXP-DH-RSA-DES-CBC-SHA" => Some(Self::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA),
            "DH-RSA-DES-CBC-SHA" => Some(Self::TLS_DH_RSA_WITH_DES_CBC_SHA),
            "DH-RSA-DES-CBC3-SHA" => Some(Self::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA),
            "EXP-EDH-DSS-DES-CBC-SHA" => Some(Self::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA),
            "EDH-DSS-DES-CBC-SHA" => Some(Self::TLS_DHE_DSS_WITH_DES_CBC_SHA),
            "EDH-DSS-DES-CBC3-SHA" => Some(Self::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA),
            "EXP-EDH-RSA-DES-CBC-SHA" => Some(Self::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA),
            "EDH-RSA-DES-CBC-SHA" => Some(Self::TLS_DHE_RSA_WITH_DES_CBC_SHA),
            "EDH-RSA-DES-CBC3-SHA" => Some(Self::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA),
            "EXP-ADH-RC4-MD5" => Some(Self::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5),
            "ADH-RC4-MD5" => Some(Self::TLS_DH_anon_WITH_RC4_128_MD5),
            "EXP-ADH-DES-CBC-SHA" => Some(Self::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA),
            "ADH-DES-CBC-SHA" => Some(Self::TLS_DH_anon_WITH_DES_CBC_SHA),
            "ADH-DES-CBC3-SHA" => Some(Self::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA),
            "KRB5-DES-CBC-SHA" => Some(Self::TLS_KRB5_WITH_DES_CBC_SHA),
            "KRB5-DES-CBC3-SHA" => Some(Self::TLS_KRB5_WITH_3DES_EDE_CBC_SHA),
            "KRB5-RC4-SHA" => Some(Self::TLS_KRB5_WITH_RC4_128_SHA),
            "KRB5-IDEA-CBC-SHA" => Some(Self::TLS_KRB5_WITH_IDEA_CBC_SHA),
            "KRB5-DES-CBC-MD5" => Some(Self::TLS_KRB5_WITH_DES_CBC_MD5),
            "KRB5-DES-CBC3-MD5" => Some(Self::TLS_KRB5_WITH_3DES_EDE_CBC_MD5),
            "KRB5-RC4-MD5" => Some(Self::TLS_KRB5_WITH_RC4_128_MD5),
            "KRB5-IDEA-CBC-MD5" => Some(Self::TLS_KRB5_WITH_IDEA_CBC_MD5),
            "EXP-KRB5-DES-CBC-SHA" => Some(Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA),
            "EXP-KRB5-RC2-CBC-SHA" => Some(Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA),
            "EXP-KRB5-RC4-SHA" => Some(Self::TLS_KRB5_EXPORT_WITH_RC4_40_SHA),
            "EXP-KRB5-DES-CBC-MD5" => Some(Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5),
            "EXP-KRB5-RC2-CBC-MD5" => Some(Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5),
            "EXP-KRB5-RC4-MD5" => Some(Self::TLS_KRB5_EXPORT_WITH_RC4_40_MD5),
            "AES128-SHA" => Some(Self::TLS_RSA_WITH_AES_128_CBC_SHA),
            "DH-DSS-AES128-SHA" => Some(Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA),
            "DH-RSA-AES128-SHA" => Some(Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA),
            "DHE-DSS-AES128-SHA" => Some(Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA),
            "DHE-RSA-AES128-SHA" => Some(Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
            "ADH-AES128-SHA" => Some(Self::TLS_DH_anon_WITH_AES_128_CBC_SHA),
            "AES256-SHA" => Some(Self::TLS_RSA_WITH_AES_256_CBC_SHA),
            "DH-DSS-AES256-SHA" => Some(Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA),
            "DH-RSA-AES256-SHA" => Some(Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA),
            "DHE-DSS-AES256-SHA" => Some(Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA),
            "DHE-RSA-AES256-SHA" => Some(Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA),
            "ADH-AES256-SHA" => Some(Self::TLS_DH_anon_WITH_AES_256_CBC_SHA),
            "NULL-SHA256" => Some(Self::TLS_RSA_WITH_NULL_SHA256),
            "AES128-SHA256" => Some(Self::TLS_RSA_WITH_AES_128_CBC_SHA256),
            "AES256-SHA256" => Some(Self::TLS_RSA_WITH_AES_256_CBC_SHA256),
            "DH-DSS-AES128-SHA256" => Some(Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA256),
            "DH-RSA-AES128-SHA256" => Some(Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA256),
            "DHE-DSS-AES128-SHA256" => Some(Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256),
            "CAMELLIA128-SHA" => Some(Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA),
            "DH-DSS-CAMELLIA128-SHA" => Some(Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA),
            "DH-RSA-CAMELLIA128-SHA" => Some(Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA),
            "DHE-DSS-CAMELLIA128-SHA" => Some(Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA),
            "DHE-RSA-CAMELLIA128-SHA" => Some(Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA),
            "ADH-CAMELLIA128-SHA" => Some(Self::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA),
            "EXP1024-DES-CBC-SHA" => Some(Self::TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA),
            "EXP1024-DHE-DSS-DES-CBC-SHA" => Some(Self::TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA),
            "EXP1024-RC4-SHA" => Some(Self::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA),
            "EXP1024-RC4-MD5" => Some(Self::TLS_RSA_EXPORT1024_WITH_RC4_56_MD5),
            "EXP1024-RC2-CBC-MD5" => Some(Self::TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5),
            "EXP1024-DHE-DSS-RC4-SHA" => Some(Self::TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA),
            "DHE-DSS-RC4-SHA" => Some(Self::TLS_DHE_DSS_WITH_RC4_128_SHA),
            "DHE-RSA-AES128-SHA256" => Some(Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256),
            "DH-DSS-AES256-SHA256" => Some(Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA256),
            "DH-RSA-AES256-SHA256" => Some(Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA256),
            "DHE-DSS-AES256-SHA256" => Some(Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256),
            "DHE-RSA-AES256-SHA256" => Some(Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256),
            "ADH-AES128-SHA256" => Some(Self::TLS_DH_anon_WITH_AES_128_CBC_SHA256),
            "ADH-AES256-SHA256" => Some(Self::TLS_DH_anon_WITH_AES_256_CBC_SHA256),
            "GOST94-GOST89-GOST89" => Some(Self::TLS_GOSTR341094_WITH_28147_CNT_IMIT),
            "GOST2001-GOST89-GOST89" => Some(Self::TLS_GOSTR341001_WITH_28147_CNT_IMIT),
            "CAMELLIA256-SHA" => Some(Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA),
            "DH-DSS-CAMELLIA256-SHA" => Some(Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA),
            "DH-RSA-CAMELLIA256-SHA" => Some(Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA),
            "DHE-DSS-CAMELLIA256-SHA" => Some(Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA),
            "DHE-RSA-CAMELLIA256-SHA" => Some(Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA),
            "ADH-CAMELLIA256-SHA" => Some(Self::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA),
            "PSK-RC4-SHA" => Some(Self::TLS_PSK_WITH_RC4_128_SHA),
            "PSK-3DES-EDE-CBC-SHA" => Some(Self::TLS_PSK_WITH_3DES_EDE_CBC_SHA),
            "PSK-AES128-CBC-SHA" => Some(Self::TLS_PSK_WITH_AES_128_CBC_SHA),
            "PSK-AES256-CBC-SHA" => Some(Self::TLS_PSK_WITH_AES_256_CBC_SHA),
            "RSA-PSK-RC4-SHA" => Some(Self::TLS_RSA_PSK_WITH_RC4_128_SHA),
            "RSA-PSK-3DES-EDE-CBC-SHA" => Some(Self::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA),
            "RSA-PSK-AES128-CBC-SHA" => Some(Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA),
            "RSA-PSK-AES256-CBC-SHA" => Some(Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA),
            "SEED-SHA" => Some(Self::TLS_RSA_WITH_SEED_CBC_SHA),
            "DH-DSS-SEED-SHA" => Some(Self::TLS_DH_DSS_WITH_SEED_CBC_SHA),
            "DH-RSA-SEED-SHA" => Some(Self::TLS_DH_RSA_WITH_SEED_CBC_SHA),
            "DHE-DSS-SEED-SHA" => Some(Self::TLS_DHE_DSS_WITH_SEED_CBC_SHA),
            "DHE-RSA-SEED-SHA" => Some(Self::TLS_DHE_RSA_WITH_SEED_CBC_SHA),
            "ADH-SEED-SHA" => Some(Self::TLS_DH_anon_WITH_SEED_CBC_SHA),
            "AES128-GCM-SHA256" => Some(Self::TLS_RSA_WITH_AES_128_GCM_SHA256),
            "AES256-GCM-SHA384" => Some(Self::TLS_RSA_WITH_AES_256_GCM_SHA384),
            "DHE-RSA-AES128-GCM-SHA256" => Some(Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256),
            "DHE-RSA-AES256-GCM-SHA384" => Some(Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
            "DH-RSA-AES128-GCM-SHA256" => Some(Self::TLS_DH_RSA_WITH_AES_128_GCM_SHA256),
            "DH-RSA-AES256-GCM-SHA384" => Some(Self::TLS_DH_RSA_WITH_AES_256_GCM_SHA384),
            "DHE-DSS-AES128-GCM-SHA256" => Some(Self::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256),
            "DHE-DSS-AES256-GCM-SHA384" => Some(Self::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384),
            "DH-DSS-AES128-GCM-SHA256" => Some(Self::TLS_DH_DSS_WITH_AES_128_GCM_SHA256),
            "DH-DSS-AES256-GCM-SHA384" => Some(Self::TLS_DH_DSS_WITH_AES_256_GCM_SHA384),
            "ADH-AES128-GCM-SHA256" => Some(Self::TLS_DH_anon_WITH_AES_128_GCM_SHA256),
            "ADH-AES256-GCM-SHA384" => Some(Self::TLS_DH_anon_WITH_AES_256_GCM_SHA384),
            "CAMELLIA128-SHA256" => Some(Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256),
            "DH-DSS-CAMELLIA128-SHA256" => Some(Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256),
            "DH-RSA-CAMELLIA128-SHA256" => Some(Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256),
            "DHE-DSS-CAMELLIA128-SHA256" => Some(Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256),
            "DHE-RSA-CAMELLIA128-SHA256" => Some(Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
            "ADH-CAMELLIA128-SHA256" => Some(Self::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256),
            "CAMELLIA256-SHA256" => Some(Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256),
            "DH-DSS-CAMELLIA256-SHA256" => Some(Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256),
            "DH-RSA-CAMELLIA256-SHA256" => Some(Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256),
            "DHE-DSS-CAMELLIA256-SHA256" => Some(Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256),
            "DHE-RSA-CAMELLIA256-SHA256" => Some(Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256),
            "ADH-CAMELLIA256-SHA256" => Some(Self::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256),
            "TLS_FALLBACK_SCSV" => Some(Self::TLS_FALLBACK_SCSV),
            "ECDH-ECDSA-NULL-SHA" => Some(Self::TLS_ECDH_ECDSA_WITH_NULL_SHA),
            "ECDH-ECDSA-RC4-SHA" => Some(Self::TLS_ECDH_ECDSA_WITH_RC4_128_SHA),
            "ECDH-ECDSA-DES-CBC3-SHA" => Some(Self::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA),
            "ECDH-ECDSA-AES128-SHA" => Some(Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA),
            "ECDH-ECDSA-AES256-SHA" => Some(Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA),
            "ECDHE-ECDSA-NULL-SHA" => Some(Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA),
            "ECDHE-ECDSA-RC4-SHA" => Some(Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA),
            "ECDHE-ECDSA-DES-CBC3-SHA" => Some(Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA),
            "ECDHE-ECDSA-AES128-SHA" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
            "ECDHE-ECDSA-AES256-SHA" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
            "ECDH-RSA-NULL-SHA" => Some(Self::TLS_ECDH_RSA_WITH_NULL_SHA),
            "ECDH-RSA-RC4-SHA" => Some(Self::TLS_ECDH_RSA_WITH_RC4_128_SHA),
            "ECDH-RSA-DES-CBC3-SHA" => Some(Self::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA),
            "ECDH-RSA-AES128-SHA" => Some(Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA),
            "ECDH-RSA-AES256-SHA" => Some(Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA),
            "ECDHE-RSA-NULL-SHA" => Some(Self::TLS_ECDHE_RSA_WITH_NULL_SHA),
            "ECDHE-RSA-RC4-SHA" => Some(Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA),
            "ECDHE-RSA-DES-CBC3-SHA" => Some(Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA),
            "ECDHE-RSA-AES128-SHA" => Some(Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
            "ECDHE-RSA-AES256-SHA" => Some(Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
            "AECDH-NULL-SHA" => Some(Self::TLS_ECDH_anon_WITH_NULL_SHA),
            "AECDH-RC4-SHA" => Some(Self::TLS_ECDH_anon_WITH_RC4_128_SHA),
            "AECDH-DES-CBC3-SHA" => Some(Self::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA),
            "AECDH-AES128-SHA" => Some(Self::TLS_ECDH_anon_WITH_AES_128_CBC_SHA),
            "AECDH-AES256-SHA" => Some(Self::TLS_ECDH_anon_WITH_AES_256_CBC_SHA),
            "SRP-3DES-EDE-CBC-SHA" => Some(Self::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA),
            "SRP-RSA-3DES-EDE-CBC-SHA" => Some(Self::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA),
            "SRP-DSS-3DES-EDE-CBC-SHA" => Some(Self::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA),
            "SRP-AES-128-CBC-SHA" => Some(Self::TLS_SRP_SHA_WITH_AES_128_CBC_SHA),
            "SRP-RSA-AES-128-CBC-SHA" => Some(Self::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA),
            "SRP-DSS-AES-128-CBC-SHA" => Some(Self::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA),
            "SRP-AES-256-CBC-SHA" => Some(Self::TLS_SRP_SHA_WITH_AES_256_CBC_SHA),
            "SRP-RSA-AES-256-CBC-SHA" => Some(Self::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA),
            "SRP-DSS-AES-256-CBC-SHA" => Some(Self::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA),
            "ECDHE-ECDSA-AES128-SHA256" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
            "ECDHE-ECDSA-AES256-SHA384" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
            "ECDH-ECDSA-AES128-SHA256" => Some(Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256),
            "ECDH-ECDSA-AES256-SHA384" => Some(Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384),
            "ECDHE-RSA-AES128-SHA256" => Some(Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
            "ECDHE-RSA-AES256-SHA384" => Some(Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
            "ECDH-RSA-AES128-SHA256" => Some(Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256),
            "ECDH-RSA-AES256-SHA384" => Some(Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384),
            "ECDHE-ECDSA-AES128-GCM-SHA256" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            "ECDHE-ECDSA-AES256-GCM-SHA384" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            "ECDH-ECDSA-AES128-GCM-SHA256" => Some(Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256),
            "ECDH-ECDSA-AES256-GCM-SHA384" => Some(Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384),
            "ECDHE-RSA-AES128-GCM-SHA256" => Some(Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            "ECDHE-RSA-AES256-GCM-SHA384" => Some(Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            "ECDH-RSA-AES128-GCM-SHA256" => Some(Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256),
            "ECDH-RSA-AES256-GCM-SHA384" => Some(Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384),
            "ECDHE-ECDSA-CAMELLIA128-SHA256" => Some(Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
            "ECDHE-ECDSA-CAMELLIA256-SHA384" => Some(Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
            "ECDH-ECDSA-CAMELLIA128-SHA256" => Some(Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
            "ECDH-ECDSA-CAMELLIA256-SHA384" => Some(Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
            "ECDHE-RSA-CAMELLIA128-SHA256" => Some(Self::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
            "ECDHE-RSA-CAMELLIA256-SHA384" => Some(Self::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384),
            "ECDH-RSA-CAMELLIA128-SHA256" => Some(Self::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256),
            "ECDH-RSA-CAMELLIA256-SHA384" => Some(Self::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384),
            "ECDHE-RSA-CHACHA20-POLY1305" => Some(Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            "ECDHE-ECDSA-CHACHA20-POLY1305" => Some(Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            "DHE-RSA-CHACHA20-POLY1305" => Some(Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            "ECDHE-RSA-CHACHA20-POLY1305-OLD" => Some(Self::OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            "ECDHE-ECDSA-CHACHA20-POLY1305-OLD" => Some(Self::OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            "DHE-RSA-CHACHA20-POLY1305-OLD" => Some(Self::OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            "DHE-RSA-DES-CBC3-SHA" => Some(Self::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA),
            "DHE-DSS-DES-CBC3-SHA" => Some(Self::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA),
            "AES128-CCM" => Some(Self::TLS_RSA_WITH_AES_128_CCM),
            "AES256-CCM" => Some(Self::TLS_RSA_WITH_AES_256_CCM),
            "DHE-RSA-AES128-CCM" => Some(Self::TLS_DHE_RSA_WITH_AES_128_CCM),
            "DHE-RSA-AES256-CCM" => Some(Self::TLS_DHE_RSA_WITH_AES_256_CCM),
            "AES128-CCM8" => Some(Self::TLS_RSA_WITH_AES_128_CCM_8),
            "AES256-CCM8" => Some(Self::TLS_RSA_WITH_AES_256_CCM_8),
            "DHE-RSA-AES128-CCM8" => Some(Self::TLS_DHE_RSA_WITH_AES_128_CCM_8),
            "DHE-RSA-AES256-CCM8" => Some(Self::TLS_DHE_RSA_WITH_AES_256_CCM_8),
            "ECDHE-ECDSA-AES128-CCM" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM),
            "ECDHE-ECDSA-AES256-CCM" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM),
            "ECDHE-ECDSA-AES128-CCM8" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
            "ECDHE-ECDSA-AES256-CCM8" => Some(Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8),
            "ARIA128-GCM-SHA256" => Some(Self::TLS_RSA_WITH_ARIA_128_GCM_SHA256),
            "ARIA256-GCM-SHA384" => Some(Self::TLS_RSA_WITH_ARIA_256_GCM_SHA384),
            "DHE-DSS-ARIA128-GCM-SHA256" => Some(Self::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256),
            "DHE-DSS-ARIA256-GCM-SHA384" => Some(Self::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384),
            "DHE-PSK-3DES-EDE-CBC-SHA" => Some(Self::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA),
            "DHE-PSK-AES128-CBC-SHA" => Some(Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA),
            "DHE-PSK-AES128-CBC-SHA256" => Some(Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256),
            "DHE-PSK-AES128-CCM" => Some(Self::TLS_DHE_PSK_WITH_AES_128_CCM),
            "DHE-PSK-AES128-CCM8" => Some(Self::TLS_PSK_DHE_WITH_AES_128_CCM_8),
            "DHE-PSK-AES128-GCM-SHA256" => Some(Self::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256),
            "DHE-PSK-AES256-CBC-SHA" => Some(Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA),
            "DHE-PSK-AES256-CBC-SHA384" => Some(Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384),
            "DHE-PSK-AES256-CCM" => Some(Self::TLS_DHE_PSK_WITH_AES_256_CCM),
            "DHE-PSK-AES256-CCM8" => Some(Self::TLS_PSK_DHE_WITH_AES_256_CCM_8),
            "DHE-PSK-AES256-GCM-SHA384" => Some(Self::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384),
            "DHE-PSK-ARIA128-GCM-SHA256" => Some(Self::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256),
            "DHE-PSK-ARIA256-GCM-SHA384" => Some(Self::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384),
            "DHE-PSK-CAMELLIA128-SHA256" => Some(Self::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256),
            "DHE-PSK-CAMELLIA256-SHA384" => Some(Self::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384),
            "DHE-PSK-CHACHA20-POLY1305" => Some(Self::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256),
            "DHE-PSK-NULL-SHA" => Some(Self::TLS_DHE_PSK_WITH_NULL_SHA),
            "DHE-PSK-NULL-SHA256" => Some(Self::TLS_DHE_PSK_WITH_NULL_SHA256),
            "DHE-PSK-NULL-SHA384" => Some(Self::TLS_DHE_PSK_WITH_NULL_SHA384),
            "DHE-PSK-RC4-SHA" => Some(Self::TLS_DHE_PSK_WITH_RC4_128_SHA),
            "DHE-RSA-ARIA128-GCM-SHA256" => Some(Self::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256),
            "DHE-RSA-ARIA256-GCM-SHA384" => Some(Self::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384),
            "ECDHE-ARIA128-GCM-SHA256" => Some(Self::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256),
            "ECDHE-ARIA256-GCM-SHA384" => Some(Self::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384),
            "ECDHE-ECDSA-ARIA128-GCM-SHA256" => Some(Self::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256),
            "ECDHE-ECDSA-ARIA256-GCM-SHA384" => Some(Self::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384),
            "ECDHE-PSK-3DES-EDE-CBC-SHA" => Some(Self::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA),
            "ECDHE-PSK-AES128-CBC-SHA" => Some(Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA),
            "ECDHE-PSK-AES128-CBC-SHA256" => Some(Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256),
            "ECDHE-PSK-AES256-CBC-SHA" => Some(Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA),
            "ECDHE-PSK-AES256-CBC-SHA384" => Some(Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384),
            "ECDHE-PSK-CAMELLIA128-SHA256" => Some(Self::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256),
            "ECDHE-PSK-CAMELLIA256-SHA384" => Some(Self::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384),
            "ECDHE-PSK-CHACHA20-POLY1305" => Some(Self::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256),
            "ECDHE-PSK-NULL-SHA" => Some(Self::TLS_ECDHE_PSK_WITH_NULL_SHA),
            "ECDHE-PSK-NULL-SHA256" => Some(Self::TLS_ECDHE_PSK_WITH_NULL_SHA256),
            "ECDHE-PSK-NULL-SHA384" => Some(Self::TLS_ECDHE_PSK_WITH_NULL_SHA384),
            "ECDHE-PSK-RC4-SHA" => Some(Self::TLS_ECDHE_PSK_WITH_RC4_128_SHA),
            "GOST2001-NULL-GOST94" => Some(Self::TLS_GOSTR341001_WITH_NULL_GOSTR3411),
            "GOST94-NULL-GOST94" => Some(Self::TLS_GOSTR341094_WITH_NULL_GOSTR3411),
            "PSK-AES128-CBC-SHA256" => Some(Self::TLS_PSK_WITH_AES_128_CBC_SHA256),
            "PSK-AES128-CCM" => Some(Self::TLS_PSK_WITH_AES_128_CCM),
            "PSK-AES128-CCM8" => Some(Self::TLS_PSK_WITH_AES_128_CCM_8),
            "PSK-AES128-GCM-SHA256" => Some(Self::TLS_PSK_WITH_AES_128_GCM_SHA256),
            "PSK-AES256-CBC-SHA384" => Some(Self::TLS_PSK_WITH_AES_256_CBC_SHA384),
            "PSK-AES256-CCM" => Some(Self::TLS_PSK_WITH_AES_256_CCM),
            "PSK-AES256-CCM8" => Some(Self::TLS_PSK_WITH_AES_256_CCM_8),
            "PSK-AES256-GCM-SHA384" => Some(Self::TLS_PSK_WITH_AES_256_GCM_SHA384),
            "PSK-ARIA128-GCM-SHA256" => Some(Self::TLS_PSK_WITH_ARIA_128_GCM_SHA256),
            "PSK-ARIA256-GCM-SHA384" => Some(Self::TLS_PSK_WITH_ARIA_256_GCM_SHA384),
            "PSK-CAMELLIA128-SHA256" => Some(Self::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256),
            "PSK-CAMELLIA256-SHA384" => Some(Self::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384),
            "PSK-CHACHA20-POLY1305" => Some(Self::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256),
            "PSK-NULL-SHA" => Some(Self::TLS_PSK_WITH_NULL_SHA),
            "PSK-NULL-SHA256" => Some(Self::TLS_PSK_WITH_NULL_SHA256),
            "PSK-NULL-SHA384" => Some(Self::TLS_PSK_WITH_NULL_SHA384),
            "RSA-PSK-AES128-CBC-SHA256" => Some(Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256),
            "RSA-PSK-AES128-GCM-SHA256" => Some(Self::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256),
            "RSA-PSK-AES256-CBC-SHA384" => Some(Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384),
            "RSA-PSK-AES256-GCM-SHA384" => Some(Self::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384),
            "RSA-PSK-ARIA128-GCM-SHA256" => Some(Self::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256),
            "RSA-PSK-ARIA256-GCM-SHA384" => Some(Self::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384),
            "RSA-PSK-CAMELLIA128-SHA256" => Some(Self::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256),
            "RSA-PSK-CAMELLIA256-SHA384" => Some(Self::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384),
            "RSA-PSK-CHACHA20-POLY1305" => Some(Self::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256),
            "RSA-PSK-NULL-SHA" => Some(Self::TLS_RSA_PSK_WITH_NULL_SHA),
            "RSA-PSK-NULL-SHA256" => Some(Self::TLS_RSA_PSK_WITH_NULL_SHA256),
            "RSA-PSK-NULL-SHA384" => Some(Self::TLS_RSA_PSK_WITH_NULL_SHA384),
            _ => None,
        }
    }
}

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
