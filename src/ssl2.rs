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

    pub fn into_openssl_name(&self) -> &str {
        match *self {
            Self::SSL_CK_RC4_128_WITH_MD5 => "RC4-MD5",
            Self::SSL_CK_RC4_128_EXPORT40_WITH_MD5 => "EXP-RC4-MD5",
            Self::SSL_CK_RC2_128_CBC_WITH_MD5 => "RC2-CBC-MD5",
            Self::SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 => "EXP-RC2-CBC-MD5",
            Self::SSL_CK_IDEA_128_CBC_WITH_MD5 => "IDEA-CBC-MD5",
            Self::SSL_CK_DES_64_CBC_WITH_MD5 => "DES-CBC-MD5",
            Self::SSL_CK_DES_192_EDE3_CBC_WITH_MD5 => "DES-CBC3-MD5",
            Self::SSL_CK_RC4_64_WITH_MD5 => "RC4-64-MD5",
            Self::TLS_RSA_WITH_NULL_MD5 => "NULL-MD5",
        }
    }
}
