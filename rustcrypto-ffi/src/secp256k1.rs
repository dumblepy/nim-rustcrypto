use crate::{
    RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST, RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    RUSTCRYPTO_ERR_INVALID_SECRET_KEY, RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_NULL_OUTPUT,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
    SECP256K1_MESSAGE_DIGEST_LEN, SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
    SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN, SECP256K1_SECRET_KEY_LEN, SECP256K1_SIGNATURE_LEN,
    aead_common,
};
use ::digest::Digest;
use ::k256::SecretKey;
use ::k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ::k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use ::k256::elliptic_curve::sec1::ToEncodedPoint;
use ::sha2::Sha256;
use ::sha3::{Keccak256, Sha3_256};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) fn public_key_from_secret_key_impl(
    input: *const u8,
    input_len: usize,
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
        SECP256K1_PUBLIC_KEY_COMPRESSED_LEN
    } else {
        SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN
    };

    if output_len < required_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    if input_len == 0 {
        return RUSTCRYPTO_ERR_INVALID_SECRET_KEY;
    }

    if input.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }

    if input_len != SECP256K1_SECRET_KEY_LEN {
        return RUSTCRYPTO_ERR_INVALID_SECRET_KEY;
    }

    let secret_key_bytes = unsafe { core::slice::from_raw_parts(input, input_len) };
    let secret_key = match SecretKey::from_slice(secret_key_bytes) {
        Ok(secret_key) => secret_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(compressed);
    let encoded_bytes = encoded_point.as_bytes();
    let output = unsafe { core::slice::from_raw_parts_mut(output, required_len) };

    output.copy_from_slice(encoded_bytes);
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_public_key_from_secret_key(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_from_secret_key_impl(input, input_len, output, output_len, compressed)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn secp256k1_ecdsa_sign_message_impl<D: Digest>(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let message_digest = D::digest(message);
    let message_digest: &[u8] = message_digest.as_ref();

    secp256k1_ecdsa_sign_prehash_impl(
        message_digest.as_ptr(),
        message_digest.len(),
        secret_key,
        secret_key_len,
        output,
        output_len,
    )
}

fn secp256k1_ecdsa_verify_message_impl<D: Digest>(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let message_digest = D::digest(message);
    let message_digest: &[u8] = message_digest.as_ref();

    secp256k1_ecdsa_verify_prehash_impl(
        message_digest.as_ptr(),
        message_digest.len(),
        public_key,
        public_key_len,
        public_key_format,
        signature,
        signature_len,
    )
}

fn secp256k1_ecdsa_sign_prehash_impl(
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

    if output_len < SECP256K1_SIGNATURE_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let message_digest = match aead_common::fixed_input(
        message_digest,
        message_digest_len,
        SECP256K1_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let secret_key_bytes = match aead_common::fixed_input(
        secret_key,
        secret_key_len,
        SECP256K1_SECRET_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    ) {
        Ok(secret_key_bytes) => secret_key_bytes,
        Err(err) => return err,
    };

    let signing_key = match SigningKey::from_slice(secret_key_bytes) {
        Ok(signing_key) => signing_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let signature: Signature = match signing_key.sign_prehash(message_digest) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    };

    let output = unsafe { core::slice::from_raw_parts_mut(output, SECP256K1_SIGNATURE_LEN) };
    let signature_bytes = signature.to_bytes();
    output.copy_from_slice(signature_bytes.as_ref());
    RUSTCRYPTO_OK
}

fn secp256k1_ecdsa_sign_recoverable_prehash_impl(
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

    if output_len < SECP256K1_SIGNATURE_LEN + 1 {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let message_digest = match aead_common::fixed_input(
        message_digest,
        message_digest_len,
        SECP256K1_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let secret_key_bytes = match aead_common::fixed_input(
        secret_key,
        secret_key_len,
        SECP256K1_SECRET_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    ) {
        Ok(secret_key_bytes) => secret_key_bytes,
        Err(err) => return err,
    };

    let signing_key = match SigningKey::from_slice(secret_key_bytes) {
        Ok(signing_key) => signing_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let (signature, recovery_id) = match signing_key.sign_prehash_recoverable(message_digest) {
        Ok(result) => result,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    };

    let output = unsafe { core::slice::from_raw_parts_mut(output, SECP256K1_SIGNATURE_LEN + 1) };
    let signature_bytes = signature.to_bytes();
    output[..SECP256K1_SIGNATURE_LEN].copy_from_slice(signature_bytes.as_ref());
    output[SECP256K1_SIGNATURE_LEN] = u8::from(recovery_id);
    RUSTCRYPTO_OK
}

fn secp256k1_ecdsa_verify_prehash_impl(
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
        SECP256K1_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let public_key_format = match public_key_format {
        0 => SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN,
        1 => SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
        _ => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let public_key_bytes = match aead_common::fixed_input(
        public_key,
        public_key_len,
        public_key_format,
        RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    ) {
        Ok(public_key_bytes) => public_key_bytes,
        Err(err) => return err,
    };

    let signature = match aead_common::fixed_input(
        signature,
        signature_len,
        SECP256K1_SIGNATURE_LEN,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key_bytes) {
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

fn secp256k1_ecdsa_recover_public_key_impl(
    message_digest: *const u8,
    message_digest_len: usize,
    recoverable_signature: *const u8,
    recoverable_signature_len: usize,
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
        SECP256K1_PUBLIC_KEY_COMPRESSED_LEN
    } else {
        SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN
    };

    if output_len < required_len {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let message_digest = match aead_common::fixed_input(
        message_digest,
        message_digest_len,
        SECP256K1_MESSAGE_DIGEST_LEN,
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
    ) {
        Ok(message_digest) => message_digest,
        Err(err) => return err,
    };

    let recoverable_signature = match aead_common::fixed_input(
        recoverable_signature,
        recoverable_signature_len,
        SECP256K1_SIGNATURE_LEN + 1,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let signature = match Signature::from_slice(&recoverable_signature[..SECP256K1_SIGNATURE_LEN]) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    let recovery_id = match RecoveryId::try_from(recoverable_signature[SECP256K1_SIGNATURE_LEN]) {
        Ok(recovery_id) => recovery_id,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    let verifying_key =
        match VerifyingKey::recover_from_prehash(message_digest, &signature, recovery_id) {
            Ok(verifying_key) => verifying_key,
            Err(_) => return RUSTCRYPTO_ERR_VERIFICATION_FAILED,
        };

    let encoded_point = verifying_key.to_encoded_point(compressed);
    let encoded_bytes = encoded_point.as_bytes();
    let output = unsafe { core::slice::from_raw_parts_mut(output, required_len) };
    output.copy_from_slice(encoded_bytes);
    RUSTCRYPTO_OK
}

fn secp256k1_ecdsa_signature_to_der_impl(
    signature: *const u8,
    signature_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    if written_len.is_null() {
        return crate::RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let signature = match aead_common::fixed_input(
        signature,
        signature_len,
        SECP256K1_SIGNATURE_LEN,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let signature = match Signature::from_slice(signature) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    let der = signature.to_der();
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

fn secp256k1_ecdsa_signature_from_der_impl(
    der_signature: *const u8,
    der_signature_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let der_signature = match aead_common::optional_input(der_signature, der_signature_len) {
        Ok(der_signature) => der_signature,
        Err(err) => return err,
    };

    let signature = match Signature::from_der(der_signature) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    let output = match aead_common::output_buffer(output, output_len, SECP256K1_SIGNATURE_LEN) {
        Ok(output) => output,
        Err(err) => return err,
    };
    let raw_bytes = signature.to_bytes();
    output.copy_from_slice(raw_bytes.as_ref());
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_prehash(
    message_digest: *const u8,
    message_digest_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_prehash_impl(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_sha256(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_message_impl::<Sha256>(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_sha3_256(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_message_impl::<Sha3_256>(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_keccak_256(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_message_impl::<Keccak256>(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_sign_recoverable_prehash(
    message_digest: *const u8,
    message_digest_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_sign_recoverable_prehash_impl(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_prehash(
    message_digest: *const u8,
    message_digest_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_prehash_impl(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_sha256(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_message_impl::<Sha256>(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_sha3_256(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_message_impl::<Sha3_256>(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_verify_keccak_256(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    public_key_format: c_int,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_verify_message_impl::<Keccak256>(
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
pub extern "C" fn rustcrypto_secp256k1_ecdsa_recover_public_key(
    message_digest: *const u8,
    message_digest_len: usize,
    recoverable_signature: *const u8,
    recoverable_signature_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_recover_public_key_impl(
            message_digest,
            message_digest_len,
            recoverable_signature,
            recoverable_signature_len,
            output,
            output_len,
            compressed,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_signature_to_der(
    signature: *const u8,
    signature_len: usize,
    output: *mut u8,
    output_len: usize,
    written_len: *mut usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_signature_to_der_impl(
            signature,
            signature_len,
            output,
            output_len,
            written_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_ecdsa_signature_from_der(
    der_signature: *const u8,
    der_signature_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        secp256k1_ecdsa_signature_from_der_impl(
            der_signature,
            der_signature_len,
            output,
            output_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST, RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
        SECP256K1_MESSAGE_DIGEST_LEN, SECP256K1_PUBLIC_KEY_COMPRESSED_LEN,
        SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN, SECP256K1_SECRET_KEY_LEN, SECP256K1_SIGNATURE_LEN,
    };

    fn basepoint_secret_key() -> [u8; SECP256K1_SECRET_KEY_LEN] {
        let mut secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        secret_key[SECP256K1_SECRET_KEY_LEN - 1] = 1;
        secret_key
    }

    fn sha256_digest(message: &[u8]) -> [u8; SECP256K1_MESSAGE_DIGEST_LEN] {
        let digest = Sha256::digest(message);
        let mut output = [0u8; SECP256K1_MESSAGE_DIGEST_LEN];
        output.copy_from_slice(digest.as_ref());
        output
    }

    #[test]
    fn sign_recoverable_prehash_and_recover_public_key_round_trip() {
        let message_digest = sha256_digest(b"abc");
        let secret_key = basepoint_secret_key();
        let mut signature = [0u8; SECP256K1_SIGNATURE_LEN + 1];
        let mut compressed_public_key = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];
        let mut uncompressed_public_key = [0u8; SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN];

        assert_eq!(
            secp256k1_ecdsa_sign_recoverable_prehash_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                signature.as_mut_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_OK,
        );

        assert_eq!(
            secp256k1_ecdsa_recover_public_key_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                signature.as_ptr(),
                signature.len(),
                compressed_public_key.as_mut_ptr(),
                compressed_public_key.len(),
                1,
            ),
            RUSTCRYPTO_OK,
        );
        assert_eq!(
            secp256k1_ecdsa_recover_public_key_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                signature.as_ptr(),
                signature.len(),
                uncompressed_public_key.as_mut_ptr(),
                uncompressed_public_key.len(),
                0,
            ),
            RUSTCRYPTO_OK,
        );
        assert_eq!(
            compressed_public_key,
            [
                0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
                0x5b, 0x16, 0xf8, 0x17, 0x98,
            ],
        );
        assert_eq!(
            uncompressed_public_key,
            [
                0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
                0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d,
                0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54,
                0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
            ],
        );
    }

    #[test]
    fn recover_public_key_rejects_invalid_inputs() {
        let message_digest = sha256_digest(b"abc");
        let secret_key = basepoint_secret_key();
        let mut signature = [0u8; SECP256K1_SIGNATURE_LEN + 1];
        let mut output = [0u8; SECP256K1_PUBLIC_KEY_COMPRESSED_LEN];

        assert_eq!(
            secp256k1_ecdsa_sign_recoverable_prehash_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                signature.as_mut_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_OK,
        );

        assert_eq!(
            secp256k1_ecdsa_recover_public_key_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                signature.as_ptr(),
                signature.len() - 1,
                output.as_mut_ptr(),
                output.len(),
                1,
            ),
            RUSTCRYPTO_ERR_INVALID_SIGNATURE,
        );
        assert_eq!(
            secp256k1_ecdsa_recover_public_key_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                signature.as_ptr(),
                signature.len(),
                core::ptr::null_mut(),
                output.len(),
                1,
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT,
        );
        assert_eq!(
            secp256k1_ecdsa_recover_public_key_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                signature.as_ptr(),
                signature.len(),
                output.as_mut_ptr(),
                output.len() - 1,
                1,
            ),
            RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        );
        signature[SECP256K1_SIGNATURE_LEN] = 0xff;
        assert_eq!(
            secp256k1_ecdsa_recover_public_key_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                signature.as_ptr(),
                signature.len(),
                output.as_mut_ptr(),
                output.len(),
                1,
            ),
            RUSTCRYPTO_ERR_INVALID_SIGNATURE,
        );
        assert_eq!(
            secp256k1_ecdsa_recover_public_key_impl(
                core::ptr::null(),
                SECP256K1_MESSAGE_DIGEST_LEN,
                signature.as_ptr(),
                signature.len(),
                output.as_mut_ptr(),
                output.len(),
                1,
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        );
    }

    #[test]
    fn sign_recoverable_prehash_rejects_invalid_inputs() {
        let message_digest = sha256_digest(b"abc");
        let secret_key = basepoint_secret_key();
        let mut output = [0u8; SECP256K1_SIGNATURE_LEN + 1];

        assert_eq!(
            secp256k1_ecdsa_sign_recoverable_prehash_impl(
                message_digest.as_ptr(),
                message_digest.len() - 1,
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_MESSAGE_DIGEST,
        );
        assert_eq!(
            secp256k1_ecdsa_sign_recoverable_prehash_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                secret_key.as_ptr(),
                secret_key.len() - 1,
                output.as_mut_ptr(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
        );
        assert_eq!(
            secp256k1_ecdsa_sign_recoverable_prehash_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                core::ptr::null_mut(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT,
        );
        assert_eq!(
            secp256k1_ecdsa_sign_recoverable_prehash_impl(
                message_digest.as_ptr(),
                message_digest.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len() - 1,
            ),
            RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        );
    }
}
