#[path = "../../../rustcrypto-ffi/src/status.rs"]
mod status;
pub use status::*;
#[path = "../../../rustcrypto-ffi/src/aead_common.rs"]
mod aead_common;
#[allow(dead_code)]
#[path = "../../../rustcrypto-ffi/src/bn254.rs"]
mod bn254;
#[allow(dead_code)]
#[path = "../../../rustcrypto-ffi/src/groth16.rs"]
mod groth16;
#[allow(dead_code)]
#[path = "../../../rustcrypto-ffi/src/groth16_prover.rs"]
mod groth16_prover;
use groth16_prover::{Circuit, prove as prove_core};
use wasm_bindgen::prelude::*;

/// Browser/Node client only: every proof obtains fresh entropy through getrandom's
/// Web Crypto backend. No seed parameter or deterministic fallback is exposed.
#[wasm_bindgen]
pub fn prove(
    circuit: &[u8],
    key: &[u8],
    public_inputs: &[u8],
    witness: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let witness = zeroize::Zeroizing::new(witness);
    let fail = |code| JsValue::from_str(&format!("Groth16 prover error: {code}"));
    let circuit = Circuit::from_bytes(circuit).map_err(fail)?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut())
        .map_err(|_| JsValue::from_str("Web Crypto entropy unavailable"))?;
    let mut rng = groth16_prover::ProverRng::from_entropy(&seed);
    prove_core(&circuit, key, public_inputs, &witness, &mut rng).map_err(fail)
}
