#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use rust_crypto_ffi::bulletproofs_r1cs::*;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

fn status(error: Error) -> JsValue {
    JsValue::from(error as i32)
}

#[wasm_bindgen]
pub fn prove(
    circuit: &[u8],
    public: &[u8],
    witness: &mut [u8],
    context: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let result = CircuitDefinition::from_bytes(circuit)
        .and_then(|circuit| circuit.prove(PublicInputs(public), Witness(witness), context));
    witness.zeroize();
    result.map_err(status)
}

#[wasm_bindgen(js_name = proveWithBlindings)]
pub fn prove_with_blindings(
    circuit: &[u8],
    public: &[u8],
    witness: &mut [u8],
    blindings: &mut [u8],
    context: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let result = CircuitDefinition::from_bytes(circuit).and_then(|circuit| {
        circuit.prove_with_blindings(
            PublicInputs(public),
            Witness(witness),
            Blindings(blindings),
            context,
        )
    });
    witness.zeroize();
    blindings.zeroize();
    result.map_err(status)
}

#[wasm_bindgen]
pub fn verify(
    circuit: &[u8],
    public: &[u8],
    context: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    CircuitDefinition::from_bytes(circuit)
        .and_then(|circuit| circuit.verify(PublicInputs(public), context, Proof(proof)))
        .map_err(status)
}

#[wasm_bindgen(js_name = verifyWithCommitments)]
pub fn verify_with_commitments(
    circuit: &[u8],
    public: &[u8],
    context: &[u8],
    proof: &[u8],
    expected: &[u8],
) -> Result<bool, JsValue> {
    CircuitDefinition::from_bytes(circuit)
        .and_then(|circuit| {
            circuit.verify_with_commitments(
                PublicInputs(public),
                context,
                Proof(proof),
                Commitments(expected),
            )
        })
        .map_err(status)
}

#[wasm_bindgen(js_name = proofCommitments)]
pub fn commitments(proof: &[u8]) -> Result<Vec<u8>, JsValue> {
    proof_commitments(Proof(proof))
        .map(|commitments| commitments.0.to_vec())
        .map_err(status)
}
