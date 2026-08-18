use crate::{
    P256_MESSAGE_DIGEST_LEN, P256_PUBLIC_KEY_COMPRESSED_LEN, P256_PUBLIC_KEY_UNCOMPRESSED_LEN,
    P256_SECRET_KEY_LEN, P256_SIGNATURE_LEN, RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    RUSTCRYPTO_ERR_INVALID_SECRET_KEY, RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, aead_common,
};
use ::p256::{
    PublicKey, SecretKey,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::hazmat::{PrehashSigner, PrehashVerifier},
    },
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use ::sha2::{Digest, Sha256};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn secret_key_bytes<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], c_int> {
    aead_common::fixed_input(
        input,
        input_len,
        P256_SECRET_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    )
}

fn sec1_public_key_bytes<'a>(
    input: *const u8,
    input_len: usize,
    expected_len: usize,
) -> Result<&'a [u8], c_int> {
    aead_common::fixed_input(
        input,
        input_len,
        expected_len,
        RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    )
}

fn signature_bytes<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], c_int> {
    aead_common::fixed_input(
        input,
        input_len,
        P256_SIGNATURE_LEN,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    )
}

fn raw_secret_key(input: *const u8, input_len: usize) -> Result<SecretKey, c_int> {
    let bytes = secret_key_bytes(input, input_len)?;
    SecretKey::from_slice(bytes).map_err(|_| RUSTCRYPTO_ERR_INVALID_SECRET_KEY)
}

fn digest_message(
    message: *const u8,
    message_len: usize,
) -> Result<[u8; P256_MESSAGE_DIGEST_LEN], c_int> {
    let message = aead_common::optional_input(message, message_len)?;
    let digest = Sha256::digest(message);
    let mut output = [0u8; P256_MESSAGE_DIGEST_LEN];
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

pub(crate) fn public_key_from_secret_key_impl(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    let compressed = match compressed {
        0 => false,
        1 => true,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let required_len = if compressed {
        P256_PUBLIC_KEY_COMPRESSED_LEN
    } else {
        P256_PUBLIC_KEY_UNCOMPRESSED_LEN
    };

    if output_len < required_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let secret_key = match raw_secret_key(secret_key, secret_key_len) {
        Ok(secret_key) => secret_key,
        Err(err) => return err,
    };

    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(compressed);
    let output = unsafe { core::slice::from_raw_parts_mut(output, required_len) };
    output.copy_from_slice(encoded.as_bytes());
    RUSTCRYPTO_OK
}

pub(crate) fn ecdsa_sign_prehash_impl(
    message_digest: *const u8,
    message_digest_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < P256_SIGNATURE_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let message_digest = match aead_common::fixed_input(
        message_digest,
        message_digest_len,
        P256_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let secret_key = match raw_secret_key(secret_key, secret_key_len) {
        Ok(secret_key) => secret_key,
        Err(err) => return err,
    };

    let signing_key = match SigningKey::from_bytes(&secret_key.to_bytes()) {
        Ok(signing_key) => signing_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };
    let signature: Signature = match signing_key.sign_prehash(message_digest) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    };

    let output = unsafe { core::slice::from_raw_parts_mut(output, P256_SIGNATURE_LEN) };
    output.copy_from_slice(signature.to_bytes().as_ref());
    RUSTCRYPTO_OK
}

pub(crate) fn ecdsa_verify_prehash_impl(
    message_digest: *const u8,
    message_digest_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let message_digest = match aead_common::fixed_input(
        message_digest,
        message_digest_len,
        P256_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let compressed = match public_key_format {
        0 => false,
        1 => true,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };
    let expected_len = if compressed {
        P256_PUBLIC_KEY_COMPRESSED_LEN
    } else {
        P256_PUBLIC_KEY_UNCOMPRESSED_LEN
    };

    let public_key_bytes = match sec1_public_key_bytes(public_key, public_key_len, expected_len) {
        Ok(public_key_bytes) => public_key_bytes,
        Err(err) => return err,
    };

    let signature = match signature_bytes(signature, signature_len) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let public_key = match PublicKey::from_sec1_bytes(public_key_bytes) {
        Ok(public_key) => public_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };
    let verifying_key =
        match VerifyingKey::from_encoded_point(&public_key.to_encoded_point(compressed)) {
            Ok(verifying_key) => verifying_key,
            Err(_) => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
        };
    let signature = match Signature::from_slice(signature) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    match verifying_key.verify_prehash(message_digest, &signature) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

pub(crate) fn ecdsa_sign_message_impl(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let message_digest = match digest_message(message, message_len) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };
    ecdsa_sign_prehash_impl(
        message_digest.as_ptr(),
        message_digest.len(),
        secret_key,
        secret_key_len,
        output,
        output_len,
    )
}

pub(crate) fn ecdsa_verify_message_impl(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let message_digest = match digest_message(message, message_len) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };
    ecdsa_verify_prehash_impl(
        message_digest.as_ptr(),
        message_digest.len(),
        public_key,
        public_key_len,
        public_key_format,
        signature,
        signature_len,
    )
}

pub(crate) fn private_key_to_pkcs8_der_impl(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let secret_key = match raw_secret_key(secret_key, secret_key_len) {
        Ok(secret_key) => secret_key,
        Err(err) => return err,
    };

    let der = match secret_key.to_pkcs8_der() {
        Ok(der) => der,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let der_bytes = der.as_bytes();
    let output = match aead_common::output_buffer(output, output_len, der_bytes.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(der_bytes);
    unsafe {
        *written_len = der_bytes.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn private_key_from_pkcs8_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let der = match aead_common::optional_input(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };
    let secret_key = match SecretKey::from_pkcs8_der(der) {
        Ok(secret_key) => secret_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let output = match aead_common::output_buffer(output, output_len, P256_SECRET_KEY_LEN) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(secret_key.to_bytes().as_ref());
    RUSTCRYPTO_OK
}

pub(crate) fn public_key_to_spki_der_impl(
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let compressed = match public_key_format {
        0 => false,
        1 => true,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };
    let expected_len = if compressed {
        P256_PUBLIC_KEY_COMPRESSED_LEN
    } else {
        P256_PUBLIC_KEY_UNCOMPRESSED_LEN
    };
    let public_key_bytes = match sec1_public_key_bytes(public_key, public_key_len, expected_len) {
        Ok(public_key_bytes) => public_key_bytes,
        Err(err) => return err,
    };
    let public_key = match PublicKey::from_sec1_bytes(public_key_bytes) {
        Ok(public_key) => public_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };
    let der = match public_key.to_public_key_der() {
        Ok(der) => der,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let der_bytes = der.as_bytes();
    let output = match aead_common::output_buffer(output, output_len, der_bytes.len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(der_bytes);
    unsafe {
        *written_len = der_bytes.len();
    }
    RUSTCRYPTO_OK
}

pub(crate) fn public_key_from_spki_der_impl(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    output_format: c_int,
) -> c_int {
    let der = match aead_common::optional_input(der, der_len) {
        Ok(der) => der,
        Err(err) => return err,
    };
    let public_key = match PublicKey::from_public_key_der(der) {
        Ok(public_key) => public_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let compressed = match output_format {
        0 => false,
        1 => true,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };
    let encoded = public_key.to_encoded_point(compressed);
    let output = match aead_common::output_buffer(output, output_len, encoded.as_bytes().len()) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(encoded.as_bytes());
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_public_key_from_secret_key(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_from_secret_key_impl(secret_key, secret_key_len, output, output_len, compressed)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_ecdsa_sign_sha256(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ecdsa_sign_message_impl(
            message,
            message_len,
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_ecdsa_verify_sha256(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ecdsa_verify_message_impl(
            message,
            message_len,
            public_key,
            public_key_len,
            public_key_format,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_ecdsa_sign_prehash(
    message_digest: *const u8,
    message_digest_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ecdsa_sign_prehash_impl(
            message_digest,
            message_digest_len,
            secret_key,
            secret_key_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_ecdsa_verify_prehash(
    message_digest: *const u8,
    message_digest_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        ecdsa_verify_prehash_impl(
            message_digest,
            message_digest_len,
            public_key,
            public_key_len,
            public_key_format,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_private_key_to_pkcs8_der(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_to_pkcs8_der_impl(secret_key, secret_key_len, output, output_len, written_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_private_key_from_pkcs8_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        private_key_from_pkcs8_der_impl(der, der_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_public_key_to_spki_der(
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_to_spki_der_impl(
            public_key,
            public_key_len,
            public_key_format,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_p256_public_key_from_spki_der(
    der: *const u8,
    der_len: usize,
    output: *mut u8,
    output_len: usize,
    output_format: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_from_spki_der_impl(der, der_len, output, output_len, output_format)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        P256_PRIVATE_KEY_DER_MAX_LEN, P256_PUBLIC_KEY_COMPRESSED_LEN, P256_PUBLIC_KEY_DER_MAX_LEN,
        P256_SIGNATURE_LEN, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    };

    fn hex_bytes(hex: &str) -> Vec<u8> {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit"),
            }
        }

        assert_eq!(hex.len() % 2, 0);
        let bytes = hex.as_bytes();
        let mut output = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0;
        while index < bytes.len() {
            output.push((nibble(bytes[index]) << 4) | nibble(bytes[index + 1]));
            index += 2;
        }
        output
    }

    #[test]
    fn public_key_from_secret_key_matches_secret_key_one() {
        let secret_key =
            hex_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let mut output = [0u8; P256_PUBLIC_KEY_COMPRESSED_LEN];

        let status = public_key_from_secret_key_impl(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
            1,
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        let mut der = [0u8; P256_PUBLIC_KEY_DER_MAX_LEN];
        let mut written = 0usize;
        let status = public_key_to_spki_der_impl(
            output.as_ptr(),
            output.len(),
            1,
            der.as_mut_ptr(),
            der.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert!(written > 0);
    }

    #[test]
    fn ecdsa_sign_sha256_matches_rfc6979_vector() {
        let secret_key =
            hex_bytes("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let mut public_key = [0u8; P256_PUBLIC_KEY_COMPRESSED_LEN];
        let status = public_key_from_secret_key_impl(
            secret_key.as_ptr(),
            secret_key.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            1,
        );
        assert_eq!(status, RUSTCRYPTO_OK);

        let mut signature = [0u8; P256_SIGNATURE_LEN];
        let status = ecdsa_sign_message_impl(
            b"sample".as_ptr(),
            6,
            secret_key.as_ptr(),
            secret_key.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );
        assert_eq!(status, RUSTCRYPTO_OK);

        let status = ecdsa_verify_message_impl(
            b"sample".as_ptr(),
            6,
            public_key.as_ptr(),
            public_key.len(),
            1,
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &signature,
            hex_bytes(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
                 f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            )
            .as_slice()
        );
        let status = ecdsa_verify_message_impl(
            b"sample".as_ptr(),
            6,
            public_key.as_ptr(),
            public_key.len(),
            1,
            signature.as_ptr(),
            signature.len(),
        );
        assert_eq!(status, RUSTCRYPTO_OK);
    }

    #[test]
    fn pkcs8_round_trip_private_key() {
        let secret_key =
            hex_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let mut der = [0u8; P256_PRIVATE_KEY_DER_MAX_LEN];
        let mut written = 0usize;

        let status = private_key_to_pkcs8_der_impl(
            secret_key.as_ptr(),
            secret_key.len(),
            der.as_mut_ptr(),
            der.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);

        let mut output = [0u8; P256_SECRET_KEY_LEN];
        let status = private_key_from_pkcs8_der_impl(
            der.as_ptr(),
            written,
            output.as_mut_ptr(),
            output.len(),
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(&output, secret_key.as_slice());
    }

    #[test]
    fn spki_round_trip_public_key() {
        let secret_key =
            hex_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let mut public_key = [0u8; P256_PUBLIC_KEY_COMPRESSED_LEN];
        let status = public_key_from_secret_key_impl(
            secret_key.as_ptr(),
            secret_key.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            1,
        );
        assert_eq!(status, RUSTCRYPTO_OK);

        let mut der = [0u8; P256_PUBLIC_KEY_DER_MAX_LEN];
        let mut written = 0usize;
        let status = public_key_to_spki_der_impl(
            public_key.as_ptr(),
            public_key.len(),
            1,
            der.as_mut_ptr(),
            der.len(),
            &mut written,
        );
        assert_eq!(status, RUSTCRYPTO_OK);

        let mut output = [0u8; P256_PUBLIC_KEY_COMPRESSED_LEN];
        let status = public_key_from_spki_der_impl(
            der.as_ptr(),
            written,
            output.as_mut_ptr(),
            output.len(),
            1,
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(&output, public_key.as_slice());
    }

    #[test]
    fn raw_sign_rejects_short_output_buffer() {
        let secret_key =
            hex_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let mut output = [0u8; P256_SIGNATURE_LEN - 1];
        let status = ecdsa_sign_message_impl(
            b"abc".as_ptr(),
            3,
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
        );
        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }
}
