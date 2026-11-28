//! Browser/Worker wasm-bindgen adapter for the external `ChainCircuit`.
//!
//! The circuit and the cryptographic adapter live in
//! `halo2-ipa-external-circuit` / `rustcrypto-ffi`. This crate is a thin
//! wrapper around the **compile-time registry** API
//! (`prepare::<ChainCircuit>`, `prove::<ChainCircuit>`, `verify::<ChainCircuit>`);
//! it does not reimplement any Halo2, keygen, proving, or verification logic.
//!
//! `prepare` returns the same simple framing as the built-in browser adapter:
//!
//! ```text
//! vk_len u32 BE | vk (V2 envelope) | pk (V2 envelope)
//! ```
//!
//! `prove` takes ownership of the witness `Vec<u8>` and zeroizes it on return.
//! `verify` returns `true`/`false` for a valid/invalid proof and throws for
//! malformed envelopes or a wrong circuit id/key, mirroring the C ABI status
//! split. All length, canonical-Fr, trailing-byte, and circuit-id validation is
//! performed by the registry before any indexing.

use halo2_ipa_external_circuit::{
    CHAIN_CIRCUIT_ID, CHAIN_CIRCUIT_VERSION, ChainCircuit, INSTANCE_VALUES, WITNESS_VALUES,
};
use rust_crypto_ffi::RUSTCRYPTO_ERR_VERIFICATION_FAILED;
use rust_crypto_ffi::halo2_ipa::HALO2_IPA_BN254_MAX_PROOF_LEN;
use rust_crypto_ffi::halo2_ipa_registry::{
    ApprovedCircuit, prepare as registry_prepare, prove as registry_prove,
    verify as registry_verify, vk_digest,
};
use wasm_bindgen::prelude::*;

/// Wire/adapter ABI version for the browser worker protocol.
#[wasm_bindgen]
pub fn abi_version() -> u32 {
    1
}

/// Registry id of the only circuit this adapter can execute.
#[wasm_bindgen]
pub fn circuit_id() -> u32 {
    CHAIN_CIRCUIT_ID
}

/// Application-pinned circuit version.
#[wasm_bindgen]
pub fn circuit_version() -> u32 {
    CHAIN_CIRCUIT_VERSION
}

/// Number of public instance values (17).
#[wasm_bindgen]
pub fn instance_values() -> u32 {
    INSTANCE_VALUES as u32
}

/// Number of public instance columns (1).
#[wasm_bindgen]
pub fn instance_columns() -> u32 {
    ChainCircuit::profile().instance_column_lengths.len() as u32
}

/// Number of private witness field elements (16).
#[wasm_bindgen]
pub fn witness_values() -> u32 {
    WITNESS_VALUES as u32
}

/// Exact witness encoding length in bytes (16 * 32).
#[wasm_bindgen]
pub fn witness_bytes() -> u32 {
    ChainCircuit::profile().witness_len as u32
}

/// Profile minimum `k`.
#[wasm_bindgen]
pub fn min_k() -> u32 {
    ChainCircuit::profile().min_k
}

/// Profile maximum `k`.
#[wasm_bindgen]
pub fn max_k() -> u32 {
    ChainCircuit::profile().max_k
}

/// Upper bound used by callers that want a proof buffer hint.
#[wasm_bindgen]
pub fn max_proof_len() -> u32 {
    HALO2_IPA_BN254_MAX_PROOF_LEN as u32
}

fn status_error(operation: &str, code: i32) -> JsValue {
    JsValue::from_str(&format!(
        "halo2-ipa external-chain {operation} failed: status {code}"
    ))
}

fn frame_keys(vk: &[u8], pk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let vk_len = u32::try_from(vk.len())
        .map_err(|_| JsValue::from_str("halo2-ipa external-chain prepare failed: vk too large"))?;
    let total = 4usize
        .checked_add(vk.len())
        .and_then(|len| len.checked_add(pk.len()))
        .ok_or_else(|| {
            JsValue::from_str("halo2-ipa external-chain prepare failed: length overflow")
        })?;
    let mut framed = Vec::with_capacity(total);
    framed.extend_from_slice(&vk_len.to_be_bytes());
    framed.extend_from_slice(vk);
    framed.extend_from_slice(pk);
    Ok(framed)
}

/// Deterministically keygens the external `ChainCircuit` for `k` and returns
/// `vk_len u32 BE | vk | pk`. No trusted setup and no randomness.
#[wasm_bindgen]
pub fn prepare(k: u32) -> Result<Vec<u8>, JsValue> {
    let (vk, pk) =
        registry_prepare::<ChainCircuit>(k).map_err(|code| status_error("prepare", code))?;
    frame_keys(&vk, &pk)
}

/// Proves with the V2 PK, a 16-value canonical BE `Fr` witness, and the V1
/// instances blob. The caller-owned witness buffer is zeroized on return.
///
/// Uses the browser CSPRNG through `prove::<ChainCircuit>` (`OsRng`).
#[wasm_bindgen]
pub fn prove(pk: &[u8], witness: Vec<u8>, instances: &[u8]) -> Result<Vec<u8>, JsValue> {
    let witness = zeroize::Zeroizing::new(witness);
    registry_prove::<ChainCircuit>(pk, witness.as_slice(), instances)
        .map_err(|code| status_error("prove", code))
}

/// Verifies a proof for this circuit's VK and the caller-supplied expected
/// public instances.
///
/// `Ok(true)` on success, `Ok(false)` on a cryptographic verification failure,
/// `Err` for malformed/foreign inputs or other statuses.
#[wasm_bindgen]
pub fn verify(vk: &[u8], proof: &[u8], instances: &[u8]) -> Result<bool, JsValue> {
    match registry_verify::<ChainCircuit>(vk, proof, instances) {
        Ok(()) => Ok(true),
        Err(RUSTCRYPTO_ERR_VERIFICATION_FAILED) => Ok(false),
        Err(other) => Err(status_error("verify", other)),
    }
}

/// SHA-256 of the V2 VK envelope, for application-side pinning.
#[wasm_bindgen]
pub fn vk_sha256(vk: &[u8]) -> Vec<u8> {
    vk_digest(vk).to_vec()
}
