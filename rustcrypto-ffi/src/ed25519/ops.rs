use crate::{
    ED25519_PRIVATE_KEY_LEN, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT, RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    RUSTCRYPTO_ERR_INVALID_SIGNATURE, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, aead_common,
};
use core::convert::TryInto;
use core::ffi::c_int;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn secret_key_bytes(
    secret_key: *const u8,
    secret_key_len: usize,
) -> Result<[u8; ED25519_PRIVATE_KEY_LEN], c_int> {
    let secret_key = aead_common::fixed_input(
        secret_key,
        secret_key_len,
        ED25519_PRIVATE_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_SECRET_KEY,
    )?;

    secret_key
        .try_into()
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_SECRET_KEY)
}

fn public_key_bytes(
    public_key: *const u8,
    public_key_len: usize,
) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], c_int> {
    let public_key = aead_common::fixed_input(
        public_key,
        public_key_len,
        ED25519_PUBLIC_KEY_LEN,
        RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    )?;

    public_key
        .try_into()
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT)
}

fn signature_bytes(
    signature: *const u8,
    signature_len: usize,
) -> Result<[u8; ED25519_SIGNATURE_LEN], c_int> {
    let signature = aead_common::fixed_input(
        signature,
        signature_len,
        ED25519_SIGNATURE_LEN,
        RUSTCRYPTO_ERR_INVALID_SIGNATURE,
    )?;

    signature
        .try_into()
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_SIGNATURE)
}

pub(crate) fn public_key_from_secret_key_impl(
    secret_key: *const u8,
    secret_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < ED25519_PUBLIC_KEY_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let secret_key = match secret_key_bytes(secret_key, secret_key_len) {
        Ok(secret_key) => secret_key,
        Err(err) => return err,
    };

    let signing_key = SigningKey::from_bytes(&secret_key);
    let public_key = signing_key.verifying_key();
    let public_key_bytes = public_key.to_bytes();
    let output = unsafe { core::slice::from_raw_parts_mut(output, ED25519_PUBLIC_KEY_LEN) };
    output.copy_from_slice(&public_key_bytes);
    RUSTCRYPTO_OK
}

pub(crate) fn sign_impl(
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

    if output_len < ED25519_SIGNATURE_LEN {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let secret_key = match secret_key_bytes(secret_key, secret_key_len) {
        Ok(secret_key) => secret_key,
        Err(err) => return err,
    };

    let signing_key = SigningKey::from_bytes(&secret_key);
    let signature: Signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();
    let output = unsafe { core::slice::from_raw_parts_mut(output, ED25519_SIGNATURE_LEN) };
    output.copy_from_slice(signature_bytes.as_ref());
    RUSTCRYPTO_OK
}

pub(crate) fn verify_impl(
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

    let public_key = match public_key_bytes(public_key, public_key_len) {
        Ok(public_key) => public_key,
        Err(err) => return err,
    };

    let signature = match signature_bytes(signature, signature_len) {
        Ok(signature) => signature,
        Err(err) => return err,
    };

    let public_key = match VerifyingKey::from_bytes(&public_key) {
        Ok(public_key) => public_key,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT,
    };

    let signature = Signature::from_bytes(&signature);

    match public_key.verify(message, &signature) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_ed25519_public_key_from_secret_key(
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
pub extern "C" fn rustcrypto_ed25519_sign(
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
pub extern "C" fn rustcrypto_ed25519_verify(
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
    use crate::RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT;

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
    fn public_key_from_secret_key_matches_rfc_8032_vector() {
        let secret_key = hex_bytes(
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
        );
        let mut output = [0u8; ED25519_PUBLIC_KEY_LEN];

        let status = public_key_from_secret_key_impl(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .as_slice()
        );
    }

    #[test]
    fn sign_matches_rfc_8032_vector() {
        let secret_key = hex_bytes(
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
        );
        let mut output = [0u8; ED25519_SIGNATURE_LEN];

        let status = sign_impl(
            b"".as_ptr(),
            0,
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            &output,
            hex_bytes(
                "e5564300c360ac729086e2cc806e828a\
                 84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46b\
                 d25bf5f0595bbe24655141438e7a100b"
            )
            .as_slice()
        );
    }

    #[test]
    fn verify_accepts_rfc_8032_vector() {
        let public_key = hex_bytes(
            "d75a980182b10ab7d54bfed3c964073a\
             0ee172f3daa62325af021a68f707511a",
        );
        let signature = hex_bytes(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        );

        let status = verify_impl(
            b"".as_ptr(),
            0,
            public_key.as_ptr(),
            public_key.len(),
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let public_key = hex_bytes(
            "d75a980182b10ab7d54bfed3c964073a\
             0ee172f3daa62325af021a68f707511a",
        );
        let mut signature = hex_bytes(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        );
        signature[0] ^= 0x01;

        let status = verify_impl(
            b"".as_ptr(),
            0,
            public_key.as_ptr(),
            public_key.len(),
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);
    }

    #[test]
    fn verify_rejects_invalid_public_key() {
        let signature = hex_bytes(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        );
        let public_key = [0u8; ED25519_PUBLIC_KEY_LEN];

        let status = verify_impl(
            b"".as_ptr(),
            0,
            public_key.as_ptr(),
            public_key.len(),
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);
    }

    #[test]
    fn verify_rejects_wrong_public_key_length() {
        let signature = hex_bytes(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        );
        let public_key = [0u8; ED25519_PUBLIC_KEY_LEN - 1];

        let status = verify_impl(
            b"".as_ptr(),
            0,
            public_key.as_ptr(),
            public_key.len(),
            signature.as_ptr(),
            signature.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PUBLIC_KEY_FORMAT);
    }

    #[test]
    fn public_key_from_secret_key_rejects_short_output_buffer() {
        let secret_key = hex_bytes(
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
        );
        let mut output = [0u8; ED25519_PUBLIC_KEY_LEN - 1];

        let status = public_key_from_secret_key_impl(
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, crate::RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn sign_rejects_short_output_buffer() {
        let secret_key = hex_bytes(
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
        );
        let mut output = [0u8; ED25519_SIGNATURE_LEN - 1];

        let status = sign_impl(
            b"".as_ptr(),
            0,
            secret_key.as_ptr(),
            secret_key.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, crate::RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }
}
