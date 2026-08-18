use crate::{
    RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT, RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    RUSTCRYPTO_ERR_INVALID_SIGNATURE, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, SECP256K1_SCHNORR_PUBLIC_KEY_LEN,
    SECP256K1_SCHNORR_SIGNATURE_LEN, SECP256K1_SECRET_KEY_LEN, aead_common,
};
use ::k256::schnorr::signature::{Signer, Verifier};
use ::k256::schnorr::{Signature, SigningKey, VerifyingKey};
use core::convert::TryFrom;
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn public_key_from_secret_key_impl(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < SECP256K1_SCHNORR_PUBLIC_KEY_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let secret_key = match aead_common::fixed_input(
        secret_key,
        secret_key_len,
        SECP256K1_SECRET_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    ) {
        Ok(secret_key) => secret_key,
        Err(err) => return err,
    };

    let signing_key = match SigningKey::from_bytes(secret_key) {
        Ok(signing_key) => signing_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let public_key = signing_key.verifying_key().to_bytes();
    let output =
        unsafe { core::slice::from_raw_parts_mut(output, SECP256K1_SCHNORR_PUBLIC_KEY_LEN) };
    output.copy_from_slice(public_key.as_ref());
    RUSTCRYPTO_OK
}

fn sign_impl(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < SECP256K1_SCHNORR_SIGNATURE_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let secret_key = match aead_common::fixed_input(
        secret_key,
        secret_key_len,
        SECP256K1_SECRET_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    ) {
        Ok(secret_key) => secret_key,
        Err(err) => return err,
    };

    let signing_key = match SigningKey::from_bytes(secret_key) {
        Ok(signing_key) => signing_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    };

    let signature: Signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();
    let output =
        unsafe { core::slice::from_raw_parts_mut(output, SECP256K1_SCHNORR_SIGNATURE_LEN) };
    output.copy_from_slice(signature_bytes.as_ref());
    RUSTCRYPTO_OK
}

fn verify_impl(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let public_key = match aead_common::fixed_input(
        public_key,
        public_key_len,
        SECP256K1_SCHNORR_PUBLIC_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    ) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };

    let signature = match aead_common::fixed_input(
        signature,
        signature_len,
        SECP256K1_SCHNORR_SIGNATURE_LEN,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    ) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let public_key = match VerifyingKey::from_bytes(public_key) {
        Ok(public_key) => public_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let signature = match Signature::try_from(signature) {
        Ok(signature) => signature,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    };

    match public_key.verify(message, &signature) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_schnorr_public_key_from_secret_key(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        public_key_from_secret_key_impl(secret_key, secret_key_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_secp256k1_schnorr_sign(
    message: *const u8,
    message_len: usize,
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        sign_impl(
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
pub extern "C" fn rustcrypto_secp256k1_schnorr_verify(
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        verify_impl(
            message,
            message_len,
            public_key,
            public_key_len,
            signature,
            signature_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT, RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
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
        let mut output = Vec::with_capacity(hex.len() / 2);

        for chunk in hex.as_bytes().chunks_exact(2) {
            output.push((nibble(chunk[0]) << 4) | nibble(chunk[1]));
        }

        output
    }

    fn basepoint_secret_key() -> [u8; SECP256K1_SECRET_KEY_LEN] {
        let mut secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        secret_key[SECP256K1_SECRET_KEY_LEN - 1] = 1;
        secret_key
    }

    #[test]
    fn public_key_from_secret_key_matches_the_expected_x_only_encoding() {
        let secret_key = basepoint_secret_key();
        let mut output = [0u8; SECP256K1_SCHNORR_PUBLIC_KEY_LEN];

        let status = public_key_from_secret_key_impl(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output[..],
            hex_bytes("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .as_slice(),
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let message = b"abc";
        let secret_key = basepoint_secret_key();
        let public_key = {
            let mut output = [0u8; SECP256K1_SCHNORR_PUBLIC_KEY_LEN];
            let status = public_key_from_secret_key_impl(
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len(),
            );
            assert_eq!(status, RUSTCRYPTO_OK);
            output
        };
        let mut signature = [0u8; SECP256K1_SCHNORR_SIGNATURE_LEN];

        let status = sign_impl(
            message.as_ptr(),
            message.len(),
            secret_key.as_ptr(),
            secret_key.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            verify_impl(
                message.as_ptr(),
                message.len(),
                public_key.as_ptr(),
                public_key.len(),
                signature.as_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_OK,
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let message = b"abc";
        let secret_key = basepoint_secret_key();
        let public_key = {
            let mut output = [0u8; SECP256K1_SCHNORR_PUBLIC_KEY_LEN];
            let status = public_key_from_secret_key_impl(
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len(),
            );
            assert_eq!(status, RUSTCRYPTO_OK);
            output
        };
        let mut signature = [0u8; SECP256K1_SCHNORR_SIGNATURE_LEN];

        let status = sign_impl(
            message.as_ptr(),
            message.len(),
            secret_key.as_ptr(),
            secret_key.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        signature[0] ^= 0x01;

        assert_eq!(
            verify_impl(
                message.as_ptr(),
                message.len(),
                public_key.as_ptr(),
                public_key.len(),
                signature.as_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_ERR_VERIFICATION_FAILED,
        );
    }

    #[test]
    fn public_key_from_secret_key_rejects_invalid_inputs() {
        let secret_key = [0u8; SECP256K1_SECRET_KEY_LEN];
        let mut output = [0u8; SECP256K1_SCHNORR_PUBLIC_KEY_LEN];

        assert_eq!(
            public_key_from_secret_key_impl(
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
        );
        assert_eq!(
            public_key_from_secret_key_impl(
                core::ptr::null(),
                SECP256K1_SECRET_KEY_LEN,
                output.as_mut_ptr(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        );
        assert_eq!(
            public_key_from_secret_key_impl(
                secret_key.as_ptr(),
                secret_key.len(),
                core::ptr::null_mut(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT,
        );
        assert_eq!(
            public_key_from_secret_key_impl(
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len() - 1,
            ),
            RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        );
    }

    #[test]
    fn sign_rejects_invalid_inputs() {
        let secret_key = basepoint_secret_key();
        let message = b"abc";
        let mut output = [0u8; SECP256K1_SCHNORR_SIGNATURE_LEN];

        assert_eq!(
            sign_impl(
                message.as_ptr(),
                message.len(),
                secret_key.as_ptr(),
                secret_key.len() - 1,
                output.as_mut_ptr(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
        );
        assert_eq!(
            sign_impl(
                core::ptr::null(),
                1,
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        );
        assert_eq!(
            sign_impl(
                message.as_ptr(),
                message.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                core::ptr::null_mut(),
                output.len(),
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT,
        );
        assert_eq!(
            sign_impl(
                message.as_ptr(),
                message.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                output.as_mut_ptr(),
                output.len() - 1,
            ),
            RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        );
    }

    #[test]
    fn verify_rejects_invalid_inputs() {
        let message = b"abc";
        let secret_key = basepoint_secret_key();
        let mut public_key = [0u8; SECP256K1_SCHNORR_PUBLIC_KEY_LEN];
        let mut signature = [0u8; SECP256K1_SCHNORR_SIGNATURE_LEN];

        assert_eq!(
            public_key_from_secret_key_impl(
                secret_key.as_ptr(),
                secret_key.len(),
                public_key.as_mut_ptr(),
                public_key.len(),
            ),
            RUSTCRYPTO_OK,
        );
        assert_eq!(
            sign_impl(
                message.as_ptr(),
                message.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                signature.as_mut_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_OK,
        );

        assert_eq!(
            verify_impl(
                core::ptr::null(),
                1,
                public_key.as_ptr(),
                public_key.len(),
                signature.as_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        );
        assert_eq!(
            verify_impl(
                message.as_ptr(),
                message.len(),
                core::ptr::null(),
                public_key.len(),
                signature.as_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        );
        assert_eq!(
            verify_impl(
                message.as_ptr(),
                message.len(),
                public_key.as_ptr(),
                public_key.len() - 1,
                signature.as_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
        );
        assert_eq!(
            verify_impl(
                message.as_ptr(),
                message.len(),
                public_key.as_ptr(),
                public_key.len(),
                signature.as_ptr(),
                signature.len() - 1,
            ),
            RUSTCRYPTO_ERR_INVALID_SIGNATURE,
        );

        public_key = [0u8; SECP256K1_SCHNORR_PUBLIC_KEY_LEN];
        assert_eq!(
            verify_impl(
                message.as_ptr(),
                message.len(),
                public_key.as_ptr(),
                public_key.len(),
                signature.as_ptr(),
                signature.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
        );
    }
}
