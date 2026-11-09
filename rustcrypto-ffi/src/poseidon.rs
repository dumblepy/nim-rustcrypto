//! Poseidon hash over BN254 `Fr` (C ABI).
//!
//! # Compatibility profile
//!
//! - Field: BN254 scalar field `Fr`.
//! - Parameters: `light-poseidon` 0.4.1 `bn254_x5` (x^5 S-box, 8 full rounds, partial rounds
//!   per width), matching the Circom `Poseidon` constants for widths 2..=13.
//! - Input encoding: each input is a canonical 32-byte big-endian `Fr` (see [`crate::bn254`]).
//! - Input count: 1..=12.
//! - Output: 32-byte canonical big-endian `Fr`.
//!
//! The parameter set and encoding are part of the API compatibility contract. A Poseidon
//! implementation with different constants or a different domain tag is **not** interchangeable.

use crate::bn254::{fr_from_be, fr_to_be};
use crate::{
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_OK, aead_common,
};
use ark_bn254::Fr;
use core::ffi::c_int;
use light_poseidon::{Poseidon, PoseidonHasher};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub const POSEIDON_BN254_MAX_INPUTS: usize = 12;

fn poseidon_hash_impl(
    inputs: *const u8,
    inputs_len: usize,
    input_count: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if input_count == 0 || input_count > POSEIDON_BN254_MAX_INPUTS {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    let expected_len = match input_count.checked_mul(32) {
        Some(len) => len,
        None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
    };
    if inputs_len != expected_len {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    if inputs.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }
    let input_bytes = unsafe { core::slice::from_raw_parts(inputs, inputs_len) };
    let output = match aead_common::output_buffer(output, output_len, 32) {
        Ok(output) => output,
        Err(err) => return err,
    };

    let mut fields = Vec::with_capacity(input_count);
    for chunk in input_bytes.chunks_exact(32) {
        match fr_from_be(chunk) {
            Ok(value) => fields.push(value),
            Err(err) => return err,
        }
    }

    let mut hasher = match Poseidon::<Fr>::new_circom(input_count) {
        Ok(hasher) => hasher,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    let digest = match hasher.hash(&fields) {
        Ok(digest) => digest,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
    };
    output.copy_from_slice(&fr_to_be(&digest));
    RUSTCRYPTO_OK
}

/// Computes the Poseidon/BN254 (x^5, Circom-compatible) hash of `input_count` field elements.
///
/// `inputs` must point to `input_count * 32` bytes; `output` must be at least 32 bytes.
/// The function never exposes Rust-owned memory to the caller.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_poseidon_bn254_hash(
    inputs: *const u8,
    inputs_len: usize,
    input_count: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        poseidon_hash_impl(inputs, inputs_len, input_count, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn254::{fr_from_be, fr_to_be};

    fn hash_fields(values: &[Fr]) -> Fr {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend_from_slice(&fr_to_be(value));
        }
        let mut out = [0u8; 32];
        let status = poseidon_hash_impl(
            bytes.as_ptr(),
            bytes.len(),
            values.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        fr_from_be(&out).unwrap()
    }

    #[test]
    fn matches_documented_light_poseidon_vector() {
        // light-poseidon README vector: two inputs of 32 repeated bytes (1 and 2).
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];
        let mut inputs = Vec::new();
        inputs.extend_from_slice(&input1);
        inputs.extend_from_slice(&input2);
        let mut out = [0u8; 32];
        assert_eq!(
            poseidon_hash_impl(inputs.as_ptr(), inputs.len(), 2, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_OK
        );
        const EXPECTED: [u8; 32] = [
            0x0d, 0x54, 0xe1, 0x93, 0x8f, 0x8a, 0x8c, 0x1c, 0x7d, 0xeb, 0x5e, 0x03, 0x55, 0xf2, 0x63,
            0x19, 0x20, 0x7b, 0x84, 0xfe, 0x9c, 0xa2, 0xce, 0x1b, 0x26, 0xe7, 0x35, 0xc8, 0x29, 0x82,
            0x19, 0x90,
        ];
        assert_eq!(out, EXPECTED);
    }

    #[test]
    fn deterministic_and_arity_separated() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_eq!(hash_fields(&[a, b]), hash_fields(&[a, b]));
        assert_ne!(hash_fields(&[a, b]), hash_fields(&[a]));
        assert_ne!(hash_fields(&[a, b]), hash_fields(&[b, a]));
    }

    #[test]
    fn rejects_bad_counts_and_non_canonical_inputs() {
        let mut out = [0u8; 32];
        assert_eq!(
            poseidon_hash_impl(std::ptr::null(), 0, 0, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
        assert_eq!(
            poseidon_hash_impl(std::ptr::null(), 0, 13, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );

        let non_canonical = vec![0xffu8; 32];
        assert_eq!(
            poseidon_hash_impl(
                non_canonical.as_ptr(),
                non_canonical.len(),
                1,
                out.as_mut_ptr(),
                out.len()
            ),
            crate::RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );
    }
}
