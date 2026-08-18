use crate::{BLAKE2B_512_DIGEST_LEN, BLAKE2S_256_DIGEST_LEN, RUSTCRYPTO_OK, aead_common};
use ::blake2::{Blake2b512, Blake2s256, Digest as Blake2Digest};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) fn blake2b_512_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let input = match aead_common::optional_input(input, input_len) {
        Ok(input) => input,
        Err(err) => return err,
    };

    let output = match aead_common::output_buffer(output, output_len, BLAKE2B_512_DIGEST_LEN) {
        Ok(output) => output,
        Err(err) => return err,
    };

    let mut hasher = Blake2b512::new();
    hasher.update(input);
    let digest = hasher.finalize();
    output.copy_from_slice(digest.as_ref());
    RUSTCRYPTO_OK
}

pub(crate) fn blake2s_256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let input = match aead_common::optional_input(input, input_len) {
        Ok(input) => input,
        Err(err) => return err,
    };

    let output = match aead_common::output_buffer(output, output_len, BLAKE2S_256_DIGEST_LEN) {
        Ok(output) => output,
        Err(err) => return err,
    };

    let mut hasher = Blake2s256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    output.copy_from_slice(digest.as_ref());
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_blake2b_512(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        blake2b_512_impl(input, input_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_blake2s_256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        blake2s_256_impl(input, input_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BLAKE2B_512_DIGEST_LEN, BLAKE2S_256_DIGEST_LEN, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
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
    fn blake2b_512_abc_matches_rfc_7693_vector() {
        let input = b"abc";
        let mut output = [0u8; BLAKE2B_512_DIGEST_LEN];

        let status = rustcrypto_blake2b_512(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        );
    }

    #[test]
    fn blake2s_256_abc_matches_rfc_7693_vector() {
        let input = b"abc";
        let mut output = [0u8; BLAKE2S_256_DIGEST_LEN];

        let status = rustcrypto_blake2s_256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        );
    }

    #[test]
    fn blake2b_512_rejects_short_output_buffer() {
        let input = b"abc";
        let mut output = [0u8; BLAKE2B_512_DIGEST_LEN - 1];

        let status = rustcrypto_blake2b_512(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn blake2s_256_rejects_null_input_with_data() {
        let mut output = [0u8; BLAKE2S_256_DIGEST_LEN];

        let status =
            rustcrypto_blake2s_256(core::ptr::null(), 1, output.as_mut_ptr(), output.len());

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }
}
