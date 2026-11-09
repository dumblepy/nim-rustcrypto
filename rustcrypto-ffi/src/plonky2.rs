//! Plonky2 / Goldilocks / FRI verification (C ABI).
//!
//! # Fixed profile (v1)
//!
//! - Backend: `plonky2` 1.1.0 (Polygon Zero), stable Rust.
//! - Field: Goldilocks (64-bit), extension degree `D = 2`.
//! - Hash / FRI config: `PoseidonGoldilocksConfig` and `CircuitConfig` as stored in
//!   `CommonCircuitData`; the library does not impose a circuit config.
//! - Serialization: plonky2's own byte encodings:
//!   - `proofWithPublicInputs`: `ProofWithPublicInputs::to_bytes()`
//!   - `verifierOnlyCircuitData`: `VerifierOnlyCircuitData::to_bytes()`
//!   - `commonCircuitData`: `CommonCircuitData::to_bytes(&DefaultGateSerializer)`
//!
//! All public inputs are committed inside `ProofWithPublicInputs`; there is no separate
//! public-input argument. The proof is parsed against the supplied common circuit data.
//!
//! # Compatibility warning
//!
//! Plonky2 proofs are configuration- and version-dependent. A proof produced by a
//! different plonky2 commit, gate set, hash configuration, FRI configuration, or `D`
//! is not interchangeable. The caller must pin the circuit data together with the
//! expected circuit digest; this library only checks that the supplied triple is
//! internally consistent and verifies.
//!
//! This module has no relation to [`crate::plonk_bn254`].

use crate::{
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY, RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_OK, aead_common,
};
use core::ffi::c_int;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::{
    CommonCircuitData, PoseidonGoldilocksConfig, ProofWithPublicInputs, VerifierCircuitData,
    VerifierOnlyCircuitData,
};
use qp_plonky2_verifier::util::serialization::DefaultGateSerializer;
use std::panic::{AssertUnwindSafe, catch_unwind};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

pub const PLONKY2_MAX_BLOB_LEN: usize = 16 * 1024 * 1024;
pub const PLONKY2_MAX_DEGREE_BITS: usize = 28;
pub const PLONKY2_MAX_GATES: usize = 4096;
pub const PLONKY2_MAX_PUBLIC_INPUTS: usize = 1 << 20;

fn read_blob<'a>(ptr: *const u8, len: usize, error: c_int) -> Result<&'a [u8], c_int> {
    if len == 0 || len > PLONKY2_MAX_BLOB_LEN {
        return Err(error);
    }
    aead_common::optional_input(ptr, len)
}

fn verify_impl(
    proof_ptr: *const u8,
    proof_len: usize,
    verifier_ptr: *const u8,
    verifier_len: usize,
    common_ptr: *const u8,
    common_len: usize,
) -> c_int {
    let proof_bytes = match read_blob(proof_ptr, proof_len, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let verifier_bytes = match read_blob(verifier_ptr, verifier_len, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let common_bytes = match read_blob(common_ptr, common_len, RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };

    let common = match CommonCircuitData::<F, D>::from_bytes(common_bytes.to_vec(), &DefaultGateSerializer) {
        Ok(common) => common,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    };
    if common.degree_bits() == 0
        || common.degree_bits() > PLONKY2_MAX_DEGREE_BITS
        || common.gates.len() > PLONKY2_MAX_GATES
        || common.num_public_inputs > PLONKY2_MAX_PUBLIC_INPUTS
    {
        return RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA;
    }

    let verifier_only = match VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_bytes.to_vec()) {
        Ok(verifier) => verifier,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    };
    let proof = match ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.to_vec(), &common) {
        Ok(proof) => proof,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    };

    let data = VerifierCircuitData {
        verifier_only,
        common,
    };
    match data.verify(proof) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

fn validate_common_impl(common_ptr: *const u8, common_len: usize) -> c_int {
    let bytes = match read_blob(common_ptr, common_len, RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match CommonCircuitData::<F, D>::from_bytes(bytes.to_vec(), &DefaultGateSerializer) {
        Ok(common)
            if common.degree_bits() > 0
                && common.degree_bits() <= PLONKY2_MAX_DEGREE_BITS
                && common.gates.len() <= PLONKY2_MAX_GATES
                && common.num_public_inputs <= PLONKY2_MAX_PUBLIC_INPUTS =>
        {
            RUSTCRYPTO_OK
        }
        _ => RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    }
}

fn validate_verifier_impl(verifier_ptr: *const u8, verifier_len: usize) -> c_int {
    let bytes = match read_blob(verifier_ptr, verifier_len, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match VerifierOnlyCircuitData::<C, D>::from_bytes(bytes.to_vec()) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    }
}

/// Verifies a Plonky2 proof with public inputs against the supplied verifier/common circuit data.
///
/// Returns [`crate::RUSTCRYPTO_OK`] for a valid proof and
/// [`crate::RUSTCRYPTO_ERR_VERIFICATION_FAILED`] for a structurally valid but invalid proof.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_plonky2_verify(
    proof_ptr: *const u8,
    proof_len: usize,
    verifier_ptr: *const u8,
    verifier_len: usize,
    common_ptr: *const u8,
    common_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        verify_impl(proof_ptr, proof_len, verifier_ptr, verifier_len, common_ptr, common_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates plonky2 `verifierOnlyCircuitData` bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_plonky2_verifier_validate(
    verifier_ptr: *const u8,
    verifier_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_verifier_impl(verifier_ptr, verifier_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates plonky2 `commonCircuitData` bytes and its resource bounds.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_plonky2_common_validate(common_ptr: *const u8, common_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_common_impl(common_ptr, common_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::util::serialization::DefaultGateSerializer as ProverGateSerializer;

    fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.mul(a, b);
        builder.register_public_input(c);
        let data = builder.build::<C>();
        let proof = data
            .prove({
                let mut witness = PartialWitness::new();
                witness.set_target(a, F::from_canonical_u64(3)).unwrap();
                witness.set_target(b, F::from_canonical_u64(5)).unwrap();
                witness
            })
            .unwrap();
        data.verify(proof.clone()).unwrap();
        (
            proof.to_bytes(),
            data.verifier_only.to_bytes().unwrap(),
            data.common.to_bytes(&ProverGateSerializer).unwrap(),
        )
    }

    #[test]
    fn verifies_generated_proof_and_rejects_tampering() {
        let (proof, verifier, common) = fixture();
        assert_eq!(
            verify_impl(
                proof.as_ptr(),
                proof.len(),
                verifier.as_ptr(),
                verifier.len(),
                common.as_ptr(),
                common.len(),
            ),
            RUSTCRYPTO_OK
        );

        let mut bad_proof = proof.clone();
        let last = bad_proof.len() - 1;
        bad_proof[last] ^= 1;
        let status = verify_impl(
            bad_proof.as_ptr(),
            bad_proof.len(),
            verifier.as_ptr(),
            verifier.len(),
            common.as_ptr(),
            common.len(),
        );
        assert!(
            status == RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT || status == RUSTCRYPTO_ERR_VERIFICATION_FAILED,
            "unexpected status {status}"
        );
    }
}
