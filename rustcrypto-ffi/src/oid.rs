#![allow(dead_code)]

use const_oid::ObjectIdentifier;

pub(crate) const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
pub(crate) const OID_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
pub(crate) const OID_HMAC_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");
pub(crate) const OID_AES128_GCM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.6");
pub(crate) const OID_AES192_GCM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.26");
pub(crate) const OID_AES256_GCM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_oid_matches_rfc_8410() {
        assert_eq!(OID_ED25519.to_string(), "1.3.101.112");
        assert_eq!(OID_ED25519, ed25519::pkcs8::ALGORITHM_OID);
    }

    #[test]
    fn secp256k1_oid_matches_k256() {
        assert_eq!(OID_SECP256K1.to_string(), "1.3.132.0.10");
    }

    #[test]
    fn hmac_sha256_oid_matches_rfc_4231() {
        assert_eq!(OID_HMAC_SHA256.to_string(), "1.2.840.113549.2.9");
    }

    #[test]
    fn aes_gcm_oids_match_rfc_5084() {
        assert_eq!(OID_AES128_GCM.to_string(), "2.16.840.1.101.3.4.1.6");
        assert_eq!(OID_AES192_GCM.to_string(), "2.16.840.1.101.3.4.1.26");
        assert_eq!(OID_AES256_GCM.to_string(), "2.16.840.1.101.3.4.1.46");
    }
}
