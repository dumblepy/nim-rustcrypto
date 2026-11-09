//! PLONK/BN254 verification (C ABI).
//!
//! # Fixed profile (v1)
//!
//! This module verifies the **genshi-core 0.3.0 PLONKish profile**, not generic
//! "PLONK" and not gnark's PLONK wire format:
//!
//! - Curve / field: BN254 (`ark-bn254` 0.5), scalar field `Fr`.
//! - Arithmetization: 4-wire PLONKish with selector commitments.
//! - Polynomial commitment: KZG with a universal SRS.
//! - Transcript: genshi's Keccak-based Fiat-Shamir transcript
//!   (`b"genshi_plonk"` domain separator), **not** the gnark/halo2 transcript.
//! - Proof / VK serialization: genshi-core's canonical big-endian encoding.
//!
//! # Wire format v1
//!
//! ## Given by the caller
//!
//! ```text
//! verifyingKey v1:
//!   magic       8 bytes  "RCPLK1\0\0"
//!   srs_g2     G2 (128)  KZG SRS [1]_2
//!   srs_g2_tau G2 (128)  KZG SRS [tau]_2
//!   vk_len     u32 BE   (must be 880)
//!   vk_blob    880 bytes (genshi-core `vk_to_bytes`)
//!
//! proof v1:
//!   genshi-core `proof_to_bytes`; exact length is `1028 + 64 * num_t_comms`
//!   where `num_t_comms` is the little-endian u32 at offset 320. Trailing bytes
//!   are rejected and `num_t_comms` is bounded.
//! ```
//!
//! The verifying key carries the two SRS G2 elements needed by KZG. They must
//! come from the same trusted setup that produced the commitments; the caller
//! is responsible for trusting the SRS / verifying key pair.
//!
//! Public inputs are canonical 32-byte big-endian `Fr` values in circuit order.
//!
//! # Compatibility warning
//!
//! A proof produced by a different PLONK implementation (gnark, snarkjs,
//! dusk-plonk, ...) is **not** accepted by this profile. Those systems differ
//! in KZG SRS handling, transcript, selector layout, and proof serialization.

use crate::bn254::g2_from_bytes;
use crate::{
    RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT, RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, aead_common,
};
use core::ffi::c_int;
use genshi_core::proving::{
    serialization,
    srs::SRS,
    types::{Proof, VerificationKey},
    verifier,
};
use genshi_math::G2Affine as GenshiG2Affine;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub const PLONK_BN254_VK_V1_MAGIC: &[u8; 8] = b"RCPLK1\0\0";
pub const PLONK_BN254_VK_BLOB_LEN: usize = 880;
pub const PLONK_BN254_VK_V1_HEADER_LEN: usize = 8 + 128 + 128 + 4;
pub const PLONK_BN254_VK_V1_LEN: usize = PLONK_BN254_VK_V1_HEADER_LEN + PLONK_BN254_VK_BLOB_LEN;
pub const PLONK_BN254_PROOF_V1_MIN_LEN: usize = 1028;
pub const PLONK_BN254_MAX_T_COMMS: usize = 1024;
pub const PLONK_BN254_MAX_PUBLIC_INPUTS: usize = 4096;
pub const PLONK_BN254_MAX_DOMAIN_SIZE: usize = 1 << 24;

fn parse_vk(bytes: &[u8]) -> Result<(VerificationKey, SRS), c_int> {
    if bytes.len() != PLONK_BN254_VK_V1_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    if &bytes[..8] != PLONK_BN254_VK_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let srs_g2 = g2_from_bytes(&bytes[8..136], false)?;
    let srs_g2_tau = g2_from_bytes(&bytes[136..264], false)?;
    let vk_len = u32::from_be_bytes(
        bytes[264..268]
            .try_into()
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?,
    ) as usize;
    if vk_len != PLONK_BN254_VK_BLOB_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let vk = serialization::vk_from_bytes(&bytes[268..]).map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;

    if vk.num_public_inputs > PLONK_BN254_MAX_PUBLIC_INPUTS {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    if vk.domain_size < 2
        || vk.domain_size > PLONK_BN254_MAX_DOMAIN_SIZE
        || !vk.domain_size.is_power_of_two()
    {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }

    let srs = SRS {
        g1_powers: Vec::new(),
        g2: GenshiG2Affine::from_ark(srs_g2),
        g2_tau: GenshiG2Affine::from_ark(srs_g2_tau),
    };
    Ok((vk, srs))
}

fn proof_num_t_comms(bytes: &[u8]) -> Result<usize, c_int> {
    if bytes.len() < PLONK_BN254_PROOF_V1_MIN_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    let num_t = u32::from_le_bytes(
        bytes[320..324]
            .try_into()
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT)?,
    ) as usize;
    if num_t > PLONK_BN254_MAX_T_COMMS {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    Ok(num_t)
}

fn parse_proof(bytes: &[u8]) -> Result<Proof, c_int> {
    let num_t = proof_num_t_comms(bytes)?;
    let expected_len = PLONK_BN254_PROOF_V1_MIN_LEN + num_t * 64;
    if bytes.len() != expected_len {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    serialization::proof_from_bytes(bytes).map_err(|_| RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT)
}

fn verify_impl(
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    inputs_ptr: *const u8,
    inputs_len: usize,
    input_count: usize,
) -> c_int {
    if vk_len != PLONK_BN254_VK_V1_LEN {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    let vk_bytes = match aead_common::optional_input(vk_ptr, vk_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    if proof_len < PLONK_BN254_PROOF_V1_MIN_LEN {
        return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT;
    }
    let proof_bytes = match aead_common::optional_input(proof_ptr, proof_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    if input_count > PLONK_BN254_MAX_PUBLIC_INPUTS {
        return RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT;
    }
    let expected_inputs_len = match input_count.checked_mul(32) {
        Some(len) => len,
        None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
    };
    if inputs_len != expected_inputs_len {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    let input_bytes = if input_count == 0 {
        &[]
    } else {
        if inputs_ptr.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        match aead_common::optional_input(inputs_ptr, inputs_len) {
            Ok(bytes) => bytes,
            Err(err) => return err,
        }
    };

    let (vk, srs) = match parse_vk(vk_bytes) {
        Ok(parsed) => parsed,
        Err(err) => return err,
    };
    if vk.num_public_inputs != input_count {
        return RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT;
    }
    let proof = match parse_proof(proof_bytes) {
        Ok(proof) => proof,
        Err(err) => return err,
    };

    let mut public_inputs = Vec::with_capacity(input_count);
    for chunk in input_bytes.chunks_exact(32) {
        let chunk: &[u8; 32] = match chunk.try_into() {
            Ok(chunk) => chunk,
            Err(_) => return RUSTCRYPTO_ERR_INVALID_LENGTH,
        };
        match genshi_math::Fr::from_be_bytes_canonical(chunk) {
            Some(value) => public_inputs.push(value),
            None => return RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
        }
    }

    if verifier::verify(&proof, &vk, &public_inputs, &srs) {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

fn validate_vk_impl(vk_ptr: *const u8, vk_len: usize) -> c_int {
    if vk_len != PLONK_BN254_VK_V1_LEN {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    let bytes = match aead_common::optional_input(vk_ptr, vk_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match parse_vk(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

fn validate_proof_impl(proof_ptr: *const u8, proof_len: usize) -> c_int {
    if proof_len < PLONK_BN254_PROOF_V1_MIN_LEN {
        return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT;
    }
    let bytes = match aead_common::optional_input(proof_ptr, proof_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match parse_proof(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

/// Verifies a genshi-core PLONK/BN254 proof against the v1 verifying key.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_plonk_bn254_verify(
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    inputs_ptr: *const u8,
    inputs_len: usize,
    input_count: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        verify_impl(
            vk_ptr,
            vk_len,
            proof_ptr,
            proof_len,
            inputs_ptr,
            inputs_len,
            input_count,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates the v1 PLONK/BN254 verifying key encoding.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_plonk_bn254_vk_validate(vk_ptr: *const u8, vk_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_vk_impl(vk_ptr, vk_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates the v1 PLONK/BN254 proof encoding without verification.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_plonk_bn254_proof_validate(proof_ptr: *const u8, proof_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_proof_impl(proof_ptr, proof_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

pub(crate) fn encode_plonk_vk(vk: &VerificationKey, srs: &SRS) -> Vec<u8> {
    let mut out = Vec::with_capacity(PLONK_BN254_VK_V1_LEN);
    out.extend_from_slice(PLONK_BN254_VK_V1_MAGIC);
    out.extend_from_slice(&crate::bn254::g2_to_bytes(&srs.g2.to_ark()));
    out.extend_from_slice(&crate::bn254::g2_to_bytes(&srs.g2_tau.to_ark()));
    out.extend_from_slice(&(PLONK_BN254_VK_BLOB_LEN as u32).to_be_bytes());
    out.extend_from_slice(&serialization::vk_to_bytes(vk));
    out
}

pub(crate) fn encode_plonk_proof(proof: &Proof) -> Vec<u8> {
    serialization::proof_to_bytes(proof)
}

pub(crate) fn encode_plonk_public_inputs(inputs: &[genshi_math::Fr]) -> Vec<u8> {
    serialization::public_inputs_to_bytes_be(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use genshi_core::proving::srs::SRS;

    #[test]
    fn rejects_malformed_encodings_without_panicking() {
        assert!(matches!(
            parse_vk(&[]),
            Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)
        ));
        assert!(matches!(
            parse_vk(&vec![0u8; PLONK_BN254_VK_V1_LEN]),
            Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)
        ));
        assert_eq!(proof_num_t_comms(&[]), Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT));
        assert_eq!(
            proof_num_t_comms(&vec![0u8; PLONK_BN254_PROOF_V1_MIN_LEN]),
            Ok(0)
        );
        let _ = SRS {
            g1_powers: Vec::new(),
            g2: GenshiG2Affine::generator(),
            g2_tau: GenshiG2Affine::generator(),
        };
    }
}
