//! Deterministic fixture encoding helpers.
//!
//! These helpers are intentionally not part of the C ABI. They exist so that the
//! repository's fixture generator and integration tests use exactly the same v1
//! wire format as the verifier.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};

/// Encodes a Groth16 verifying key in the v1 format.
pub fn encode_vk(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    crate::groth16::encode_vk(vk)
}

/// Encodes a Groth16 proof in the v1 format.
pub fn encode_proof(proof: &Proof<Bn254>) -> Vec<u8> {
    crate::groth16::encode_proof(proof)
}

/// Encodes public inputs as canonical big-endian BN254 `Fr` values.
pub fn encode_public_inputs(inputs: &[Fr]) -> Vec<u8> {
    crate::groth16::encode_public_inputs(inputs)
}

/// Encodes a genshi-core PLONK verifying key in the v1 format.
pub fn encode_plonk_vk(
    vk: &genshi_core::proving::types::VerificationKey,
    srs: &genshi_core::proving::srs::SRS,
) -> Vec<u8> {
    crate::plonk_bn254::encode_plonk_vk(vk, srs)
}

/// Encodes a genshi-core PLONK proof in the v1 format.
pub fn encode_plonk_proof(proof: &genshi_core::proving::types::Proof) -> Vec<u8> {
    crate::plonk_bn254::encode_plonk_proof(proof)
}

/// Encodes PLONK public inputs as canonical big-endian `Fr` values.
pub fn encode_plonk_public_inputs(inputs: &[genshi_math::Fr]) -> Vec<u8> {
    crate::plonk_bn254::encode_plonk_public_inputs(inputs)
}
