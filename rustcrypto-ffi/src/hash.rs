use crate::{
    KECCAK_256_DIGEST_LEN, RUSTCRYPTO_OK, SHA3_256_DIGEST_LEN, SHA256_DIGEST_LEN, aead_common,
};
use ::sha2::Sha256;
use ::sha3::{Keccak256, Sha3_256};
use core::ffi::c_int;
use digest::Digest;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn hash_one_shot<D>(input: &[u8], output: &mut [u8]) -> c_int
where
    D: Digest,
{
    let mut hasher = D::new();
    hasher.update(input);
    let digest = hasher.finalize();
    output.copy_from_slice(digest.as_ref());
    RUSTCRYPTO_OK
}

fn hash_impl<D>(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    digest_len: usize,
) -> c_int
where
    D: Digest,
{
    let input = match aead_common::optional_input(input, input_len) {
        Ok(input) => input,
        Err(err) => return err,
    };

    let output = match aead_common::output_buffer(output, output_len, digest_len) {
        Ok(output) => output,
        Err(err) => return err,
    };

    hash_one_shot::<D>(input, output)
}

pub(crate) fn sha256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    hash_impl::<Sha256>(input, input_len, output, output_len, SHA256_DIGEST_LEN)
}

pub(crate) fn sha3_256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    hash_impl::<Sha3_256>(input, input_len, output, output_len, SHA3_256_DIGEST_LEN)
}

pub(crate) fn keccak_256_impl(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    hash_impl::<Keccak256>(input, input_len, output, output_len, KECCAK_256_DIGEST_LEN)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_sha256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        sha256_impl(input, input_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_sha3_256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        sha3_256_impl(input, input_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_keccak_256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        keccak_256_impl(input, input_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KECCAK_256_DIGEST_LEN, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
        RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK, SHA3_256_DIGEST_LEN, SHA256_DIGEST_LEN,
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
    fn sha256_abc_matches_known_vector() {
        let input = b"abc";
        let mut output = [0u8; SHA256_DIGEST_LEN];

        let status = rustcrypto_sha256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty_matches_known_vector() {
        let mut output = [0u8; SHA256_DIGEST_LEN];

        let status = rustcrypto_sha256(core::ptr::null(), 0, output.as_mut_ptr(), output.len());

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_rejects_null_input_with_data() {
        let mut output = [0u8; SHA256_DIGEST_LEN];

        let status = rustcrypto_sha256(core::ptr::null(), 1, output.as_mut_ptr(), output.len());

        assert_eq!(status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }

    #[test]
    fn sha256_rejects_short_output_buffer() {
        let input = b"abc";
        let mut output = [0u8; SHA256_DIGEST_LEN - 1];

        let status = rustcrypto_sha256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
    }

    #[test]
    fn sha3_256_abc_matches_known_vector() {
        let input = b"abc";
        let mut output = [0u8; SHA3_256_DIGEST_LEN];

        let status = rustcrypto_sha3_256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn keccak_256_abc_matches_known_vector() {
        let input = b"abc";
        let mut output = [0u8; KECCAK_256_DIGEST_LEN];

        let status = rustcrypto_keccak_256(
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        );

        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(
            digest_hex(&output),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }
}
