use crate::{HMAC_SHA256_MAC_LEN, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_OK, aead_common};
use ::hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use ::sha2::Sha256;
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) fn hmac_sha256_impl(
    key: *const u8,
    key_len: usize,
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    if output_len < HMAC_SHA256_MAC_LEN {
        return crate::RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }

    let key = match aead_common::optional_input(key, key_len) {
        Ok(key) => key,
        Err(err) => return err,
    };

    let message = match aead_common::optional_input(message, message_len) {
        Ok(message) => message,
        Err(err) => return err,
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return crate::RUSTCRYPTO_ERR_PANIC,
    };

    mac.update(message);
    let mac_bytes = mac.finalize().into_bytes();
    let output = unsafe { core::slice::from_raw_parts_mut(output, HMAC_SHA256_MAC_LEN) };
    output.copy_from_slice(mac_bytes.as_ref());
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_hmac_sha256(
    key: *const u8,
    key_len: usize,
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hmac_sha256_impl(key, key_len, message, message_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HMAC_SHA256_MAC_LEN, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
        RUSTCRYPTO_OK,
    };

    fn digest_hex(bytes: &[u8]) -> String {
        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            output.push(char::from(HEX_DIGITS[(byte >> 4) as usize]));
            output.push(char::from(HEX_DIGITS[(byte & 0x0f) as usize]));
        }
        output
    }

    #[test]
    fn hmac_sha256_empty_key_and_message_matches_known_vector() {
        let mut output = [0u8; HMAC_SHA256_MAC_LEN];

        let status = rustcrypto_hmac_sha256(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }

    #[test]
    fn hmac_sha256_rejects_short_output_buffer() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let mut output = [0u8; HMAC_SHA256_MAC_LEN - 1];

        let status = rustcrypto_hmac_sha256(
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn hmac_sha256_rejects_null_output() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";

        let status = rustcrypto_hmac_sha256(
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            core::ptr::null_mut(),
            HMAC_SHA256_MAC_LEN,
        );

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
    }
}
