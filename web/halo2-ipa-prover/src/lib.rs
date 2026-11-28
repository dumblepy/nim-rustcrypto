//! Browser/Node Web Worker adapter for the Halo2 IPA/BN254 C ABI.
//!
//! The cryptography is not reimplemented here. This crate path-includes the
//! reviewed `rustcrypto-ffi` modules and exposes thin `wasm-bindgen` wrappers
//! around the existing C ABI. Proving needs the browser CSPRNG (`getrandom`
//! with the `js` feature); verification is entropy-free.
//!
//! `prepare` returns a deliberately simple framing:
//!
//! ```text
//! vk_len u32 BE | vk (v1 blob) | pk (v1 blob)
//! ```
//!
//! `prove` allocates the maximum proof buffer once and calls the C ABI. This
//! avoids the "sizing call then prove again" pattern, which would generate two
//! independent (blinded) proofs.

#[path = "../../../rustcrypto-ffi/src/status.rs"]
mod status;
pub use status::*;

// `halo2_ipa` only needs the status codes above plus its own `halo2-axiom`
// types. The `bn254` / `aead_common` modules are intentionally not included:
// they are not used by the IPA path and would add unrelated C ABI exports and
// dependencies to this minimal browser wasm.
#[allow(dead_code)]
#[path = "../../../rustcrypto-ffi/src/halo2_ipa.rs"]
mod halo2_ipa;

use wasm_bindgen::prelude::*;

/// Wire/adapter ABI version for the browser worker protocol.
#[wasm_bindgen]
pub fn abi_version() -> u32 {
    1
}

/// The only approved circuit id (`y = x^3 + x + 5`).
#[wasm_bindgen]
pub fn circuit_id() -> u32 {
    halo2_ipa::HALO2_IPA_BN254_CIRCUIT_CUBIC_V1
}

/// Upper bound used by the prover output allocation (4 MiB).
#[wasm_bindgen]
pub fn max_proof_len() -> u32 {
    halo2_ipa::HALO2_IPA_BN254_MAX_PROOF_LEN as u32
}

fn status_error(operation: &str, code: i32) -> JsValue {
    JsValue::from_str(&format!("halo2-ipa {operation} failed: status {code}"))
}

/// Deterministically derives IPA params from `k`, keygens the registered
/// circuit, and returns `vk_len u32 BE | vk | pk`. No trusted setup, no
/// randomness.
#[wasm_bindgen]
pub fn prepare(circuit: u32, k: u32) -> Result<Vec<u8>, JsValue> {
    let (vk, pk) = halo2_ipa::generate_key_material_v1(circuit, k)
        .map_err(|code| status_error("prepare", code))?;
    let vk_len = u32::try_from(vk.len())
        .map_err(|_| JsValue::from_str("halo2-ipa prepare failed: vk too large"))?;
    let total = 4usize
        .checked_add(vk.len())
        .and_then(|len| len.checked_add(pk.len()))
        .ok_or_else(|| JsValue::from_str("halo2-ipa prepare failed: length overflow"))?;
    let mut framed = Vec::with_capacity(total);
    framed.extend_from_slice(&vk_len.to_be_bytes());
    framed.extend_from_slice(&vk);
    framed.extend_from_slice(&pk);
    Ok(framed)
}

/// Proves with the v1 PK, a 32-byte canonical BE `Fr` witness, and the v1
/// instances blob. The caller-owned witness copy is zeroized on return.
#[wasm_bindgen]
pub fn prove(pk: &[u8], witness: Vec<u8>, instances: &[u8]) -> Result<Vec<u8>, JsValue> {
    let witness = zeroize::Zeroizing::new(witness);
    let mut proof = vec![0u8; halo2_ipa::HALO2_IPA_BN254_MAX_PROOF_LEN];
    let mut proof_len = 0usize;
    let status = halo2_ipa::rustcrypto_halo2_ipa_bn254_prove(
        pk.as_ptr(),
        pk.len(),
        witness.as_ptr(),
        witness.len(),
        instances.as_ptr(),
        instances.len(),
        proof.as_mut_ptr(),
        proof.len(),
        &mut proof_len,
    );
    if status != RUSTCRYPTO_OK {
        return Err(status_error("prove", status));
    }
    if proof_len > proof.len() {
        return Err(JsValue::from_str(
            "halo2-ipa prove failed: output length exceeds buffer",
        ));
    }
    proof.truncate(proof_len);
    Ok(proof)
}

/// Verifies a v1 proof. `Ok(true)` on success, `Ok(false)` on a verification
/// failure, `Err` for malformed inputs / other statuses.
#[wasm_bindgen]
pub fn verify(vk: &[u8], proof: &[u8], instances: &[u8]) -> Result<bool, JsValue> {
    let status = halo2_ipa::rustcrypto_halo2_ipa_bn254_verify(
        vk.as_ptr(),
        vk.len(),
        proof.as_ptr(),
        proof.len(),
        instances.as_ptr(),
        instances.len(),
    );
    match status {
        RUSTCRYPTO_OK => Ok(true),
        RUSTCRYPTO_ERR_VERIFICATION_FAILED => Ok(false),
        other => Err(status_error("verify", other)),
    }
}
