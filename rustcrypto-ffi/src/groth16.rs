//! Groth16 verification over BN254 (C ABI).
//!
//! # Wire format v1
//!
//! ## Proof (256 bytes)
//!
//! ```text
//! A: G1 (64) || B: G2 (128) || C: G1 (64)
//! ```
//!
//! ## Verifying key
//!
//! ```text
//! magic:       8 bytes  "RCG16V1\0"
//! alpha_g1:    G1  (64)
//! beta_g2:     G2 (128)
//! gamma_g2:    G2 (128)
//! delta_g2:    G2 (128)
//! ic_count:    u32 big-endian (1..=4096)
//! ic:          ic_count * G1 (64 each)
//! ```
//!
//! The total length is `460 + 64 * ic_count`; trailing bytes are rejected.
//! Public inputs are canonical 32-byte big-endian `Fr` values and their count must be
//! exactly `ic_count - 1`, in the order used by the circuit.
//!
//! All G1/G2 points use the encoding from [`crate::bn254`]: canonical big-endian
//! coordinates, on-curve and prime-order subgroup checked, point at infinity allowed only
//! in the proof (not in the verifying key).
//!
//! # Security notes
//!
//! Verification with an arbitrary verifying key only proves that the proof is valid for
//! **that key**. Deciding whether a verifying key (and therefore the circuit) is approved
//! is the caller's responsibility. This library does not maintain a registry of trusted
//! circuits.

use crate::bn254::{
    BN254_G1_LEN, BN254_G2_LEN, g1_from_bytes, g2_from_bytes, g1_to_bytes, g2_to_bytes, fr_from_be,
};
use crate::{
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK, aead_common,
};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub const GROTH16_BN254_PROOF_V1_LEN: usize = BN254_G1_LEN + BN254_G2_LEN + BN254_G1_LEN;
pub const GROTH16_BN254_VK_V1_HEADER_LEN: usize = 8;
pub const GROTH16_BN254_MAX_IC_LEN: usize = 4096;
pub const GROTH16_BN254_MAX_PUBLIC_INPUTS: usize = GROTH16_BN254_MAX_IC_LEN - 1;
pub const GROTH16_BN254_VK_V1_FIXED_LEN: usize =
    GROTH16_BN254_VK_V1_HEADER_LEN + BN254_G1_LEN + 3 * BN254_G2_LEN + 4;
pub const GROTH16_BN254_VK_V1_MAX_LEN: usize =
    GROTH16_BN254_VK_V1_FIXED_LEN + GROTH16_BN254_MAX_IC_LEN * BN254_G1_LEN;

const VK_MAGIC: &[u8; GROTH16_BN254_VK_V1_HEADER_LEN] = b"RCG16V1\0";

fn parse_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, c_int> {
    if bytes.len() < GROTH16_BN254_VK_V1_FIXED_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    if &bytes[..GROTH16_BN254_VK_V1_HEADER_LEN] != VK_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }

    let ic_count_offset = GROTH16_BN254_VK_V1_FIXED_LEN - 4;
    let ic_count = u32::from_be_bytes(
        bytes[ic_count_offset..GROTH16_BN254_VK_V1_FIXED_LEN]
            .try_into()
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?,
    ) as usize;
    if ic_count == 0 || ic_count > GROTH16_BN254_MAX_IC_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let expected_len = GROTH16_BN254_VK_V1_FIXED_LEN + ic_count * BN254_G1_LEN;
    if bytes.len() != expected_len {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }

    let alpha_g1 = g1_from_bytes(&bytes[8..72], false)?;
    let beta_g2 = g2_from_bytes(&bytes[72..200], false)?;
    let gamma_g2 = g2_from_bytes(&bytes[200..328], false)?;
    let delta_g2 = g2_from_bytes(&bytes[328..456], false)?;

    let mut gamma_abc_g1 = Vec::with_capacity(ic_count);
    let mut offset = GROTH16_BN254_VK_V1_FIXED_LEN;
    for _ in 0..ic_count {
        gamma_abc_g1.push(g1_from_bytes(&bytes[offset..offset + BN254_G1_LEN], false)?);
        offset += BN254_G1_LEN;
    }

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

fn parse_proof(bytes: &[u8]) -> Result<Proof<Bn254>, c_int> {
    if bytes.len() != GROTH16_BN254_PROOF_V1_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    let a = g1_from_bytes(&bytes[..BN254_G1_LEN], true)?;
    let b = g2_from_bytes(&bytes[64..192], true)?;
    let c = g1_from_bytes(&bytes[192..256], true)?;
    Ok(Proof { a, b, c })
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
    if vk_len == 0 || vk_len > GROTH16_BN254_VK_V1_MAX_LEN {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    let vk_bytes = match aead_common::optional_input(vk_ptr, vk_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    if proof_len != GROTH16_BN254_PROOF_V1_LEN {
        return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT;
    }
    let proof_bytes = match aead_common::optional_input(proof_ptr, proof_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    if input_count > GROTH16_BN254_MAX_PUBLIC_INPUTS {
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
        if inputs_ptr.is_null() {
            &[]
        } else {
            match aead_common::optional_input(inputs_ptr, inputs_len) {
                Ok(bytes) => bytes,
                Err(err) => return err,
            }
        }
    } else {
        if inputs_ptr.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        match aead_common::optional_input(inputs_ptr, inputs_len) {
            Ok(bytes) => bytes,
            Err(err) => return err,
        }
    };

    let vk = match parse_vk(vk_bytes) {
        Ok(vk) => vk,
        Err(err) => return err,
    };
    if vk.gamma_abc_g1.len() != input_count + 1 {
        return RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT;
    }
    let proof = match parse_proof(proof_bytes) {
        Ok(proof) => proof,
        Err(err) => return err,
    };

    let mut public_inputs = Vec::with_capacity(input_count);
    for chunk in input_bytes.chunks_exact(32) {
        match fr_from_be(chunk) {
            Ok(value) => public_inputs.push(value),
            Err(err) => return err,
        }
    }

    let prepared_vk = prepare_verifying_key(&vk);
    match Groth16::<Bn254>::verify_proof(&prepared_vk, &proof, &public_inputs) {
        Ok(true) => RUSTCRYPTO_OK,
        Ok(false) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

fn validate_vk_impl(vk_ptr: *const u8, vk_len: usize) -> c_int {
    if vk_len == 0 || vk_len > GROTH16_BN254_VK_V1_MAX_LEN {
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
    if proof_len != GROTH16_BN254_PROOF_V1_LEN {
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

/// Verifies a Groth16/BN254 proof.
///
/// Returns [`crate::RUSTCRYPTO_OK`] when the proof is valid, or
/// [`crate::RUSTCRYPTO_ERR_VERIFICATION_FAILED`] when the proof is structurally valid but
/// does not verify. Malformed inputs return a distinct error code.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_groth16_bn254_verify(
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

/// Validates the v1 verifying key encoding without performing a pairing check.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_groth16_bn254_vk_validate(vk_ptr: *const u8, vk_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_vk_impl(vk_ptr, vk_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates the v1 proof encoding without performing a pairing check.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_groth16_bn254_proof_validate(proof_ptr: *const u8, proof_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_proof_impl(proof_ptr, proof_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

pub(crate) fn encode_public_inputs(inputs: &[ark_bn254::Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inputs.len() * 32);
    for input in inputs {
        out.extend_from_slice(&crate::bn254::fr_to_be(input));
    }
    out
}

pub(crate) fn encode_vk(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(GROTH16_BN254_VK_V1_FIXED_LEN + vk.gamma_abc_g1.len() * BN254_G1_LEN);
    out.extend_from_slice(VK_MAGIC);
    out.extend_from_slice(&g1_to_bytes(&vk.alpha_g1));
    out.extend_from_slice(&g2_to_bytes(&vk.beta_g2));
    out.extend_from_slice(&g2_to_bytes(&vk.gamma_g2));
    out.extend_from_slice(&g2_to_bytes(&vk.delta_g2));
    out.extend_from_slice(&(vk.gamma_abc_g1.len() as u32).to_be_bytes());
    for point in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_to_bytes(point));
    }
    out
}

pub(crate) fn encode_proof(proof: &Proof<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(GROTH16_BN254_PROOF_V1_LEN);
    out.extend_from_slice(&g1_to_bytes(&proof.a));
    out.extend_from_slice(&g2_to_bytes(&proof.b));
    out.extend_from_slice(&g1_to_bytes(&proof.c));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn254::fr_to_be;
    use crate::RUSTCRYPTO_ERR_INVALID_CURVE_POINT;
    use ark_bn254::Fr;
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use ark_std::rand::SeedableRng;

    #[derive(Clone)]
    struct MulCircuit {
        a: Option<u64>,
        b: Option<u64>,
    }

    impl ConstraintSynthesizer<Fr> for MulCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(self.a.unwrap())))?;
            let b = cs.new_input_variable(|| Ok(Fr::from(self.b.unwrap())))?;
            cs.enforce_constraint(lc!() + a, lc!() + a, lc!() + b)?;
            Ok(())
        }
    }

    fn fixture() -> (VerifyingKey<Bn254>, Proof<Bn254>, Vec<Fr>) {
        let circuit = MulCircuit {
            a: Some(3),
            b: Some(9),
        };
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&params, circuit, &mut rng).unwrap();
        let vk = params.vk.clone();
        (vk, proof, vec![Fr::from(9u64)])
    }

    #[test]
    fn verifies_generated_proof_and_rejects_tampering() {
        let (vk, proof, inputs) = fixture();
        let mut vk_bytes = encode_vk(&vk);
        let mut proof_bytes = encode_proof(&proof);
        let mut input_bytes = Vec::new();
        for input in &inputs {
            input_bytes.extend_from_slice(&fr_to_be(input));
        }

        assert_eq!(
            verify_impl(
                vk_bytes.as_ptr(),
                vk_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                input_bytes.as_ptr(),
                input_bytes.len(),
                inputs.len(),
            ),
            RUSTCRYPTO_OK
        );

        // Wrong public input.
        input_bytes[31] = 10;
        assert_eq!(
            verify_impl(
                vk_bytes.as_ptr(),
                vk_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                input_bytes.as_ptr(),
                input_bytes.len(),
                inputs.len(),
            ),
            RUSTCRYPTO_ERR_VERIFICATION_FAILED
        );
        input_bytes[31] = 9;

        // Tampered proof point must not verify and must not panic.
        proof_bytes[63] ^= 1;
        assert_eq!(
            verify_impl(
                vk_bytes.as_ptr(),
                vk_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                input_bytes.as_ptr(),
                input_bytes.len(),
                inputs.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_CURVE_POINT
        );
        proof_bytes[63] ^= 1;

        // Wrong verifying key magic.
        vk_bytes[0] ^= 1;
        assert_eq!(validate_vk_impl(vk_bytes.as_ptr(), vk_bytes.len()), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
        vk_bytes[0] ^= 1;

        // Public input count must match IC length.
        assert_eq!(
            verify_impl(
                vk_bytes.as_ptr(),
                vk_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                input_bytes.as_ptr(),
                input_bytes.len(),
                0,
            ),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );

        // Trailing bytes are rejected.
        let mut long_vk = vk_bytes.clone();
        long_vk.push(0);
        assert_eq!(validate_vk_impl(long_vk.as_ptr(), long_vk.len()), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);

        // Non-canonical field element in public inputs.
        let mut bad_input = [0xffu8; 32];
        assert_eq!(
            verify_impl(
                vk_bytes.as_ptr(),
                vk_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                bad_input.as_mut_ptr(),
                bad_input.len(),
                1,
            ),
            crate::RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );
    }

    #[test]
    fn rejects_null_and_zero_length_inputs() {
        assert_eq!(
            verify_impl(std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0, 0),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
        );
        assert_eq!(
            verify_impl(std::ptr::null(), 1, std::ptr::null(), 0, std::ptr::null(), 0, 0),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            validate_proof_impl(std::ptr::null(), 0),
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
        );
    }
}
