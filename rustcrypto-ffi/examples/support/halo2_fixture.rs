//! Shared Halo2 v1 fixture smoke checks for native and wasm examples.

use rust_crypto_ffi::halo2::{
    rustcrypto_halo2_kzg_bn254_instances_validate, rustcrypto_halo2_kzg_bn254_params_validate,
    rustcrypto_halo2_kzg_bn254_verify, rustcrypto_halo2_kzg_bn254_vk_validate,
};

const FIXTURE: &str = include_str!("../../../tests/fixtures/halo2_kzg_bn254_v1.hex");

const RUSTCRYPTO_OK: i32 = 0;
const RUSTCRYPTO_ERR_VERIFICATION_FAILED: i32 = 8;
const RUSTCRYPTO_ERR_INVALID_LENGTH: i32 = 9;
const RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT: i32 = 22;
const RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY: i32 = 23;

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd-length fixture value");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("invalid fixture hex"))
        .collect()
}

fn fixture_value(name: &str) -> Vec<u8> {
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .map(unhex)
        .unwrap_or_else(|| panic!("missing fixture value {name}"))
}

fn verify(params: &[u8], vk: &[u8], proof: &[u8], instances: &[u8]) -> i32 {
    rustcrypto_halo2_kzg_bn254_verify(
        params.as_ptr(),
        params.len(),
        vk.as_ptr(),
        vk.len(),
        proof.as_ptr(),
        proof.len(),
        instances.as_ptr(),
        instances.len(),
    )
}

/// Returns 0 when every check passes, otherwise a bit mask of failed checks.
///
/// Checked on native and in `wasm32-wasip1` / `wasm32-unknown-unknown` runtimes.
pub fn smoke() -> i32 {
    let params = fixture_value("PARAMS");
    let vk = fixture_value("VK");
    let proof = fixture_value("PROOF");
    let instances = fixture_value("INSTANCES");

    let mut failures = 0;

    if rustcrypto_halo2_kzg_bn254_params_validate(params.as_ptr(), params.len()) != RUSTCRYPTO_OK
        || rustcrypto_halo2_kzg_bn254_vk_validate(vk.as_ptr(), vk.len()) != RUSTCRYPTO_OK
        || rustcrypto_halo2_kzg_bn254_instances_validate(instances.as_ptr(), instances.len())
            != RUSTCRYPTO_OK
    {
        failures |= 1;
    }

    if verify(&params, &vk, &proof, &instances) != RUSTCRYPTO_OK {
        failures |= 2;
    }

    let mut wrong = instances.clone();
    match wrong.last_mut() {
        Some(last) => *last ^= 1,
        None => failures |= 4,
    }
    if verify(&params, &vk, &proof, &wrong) != RUSTCRYPTO_ERR_VERIFICATION_FAILED {
        failures |= 4;
    }

    let mut trailing = proof.clone();
    trailing.push(0);
    if verify(&params, &vk, &trailing, &instances) != RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT {
        failures |= 8;
    }

    let mut short_vk = vk.clone();
    short_vk.pop();
    if verify(&params, &short_vk, &proof, &instances) != RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY {
        failures |= 16;
    }

    let mut short_proof = proof.clone();
    short_proof.pop();
    if verify(&params, &vk, &short_proof, &instances) != RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT {
        failures |= 32;
    }

    let mut trailing_instances = instances.clone();
    trailing_instances.push(0);
    if verify(&params, &vk, &proof, &trailing_instances) != RUSTCRYPTO_ERR_INVALID_LENGTH {
        failures |= 64;
    }

    let mut bad_params = params.clone();
    match bad_params.last_mut() {
        Some(last) => *last ^= 1,
        None => failures |= 128,
    }
    if verify(&bad_params, &vk, &proof, &instances) == RUSTCRYPTO_OK {
        failures |= 128;
    }

    let mut noncanonical = instances.clone();
    for byte in noncanonical.iter_mut().rev().take(32) {
        *byte = 0xff;
    }
    if verify(&params, &vk, &proof, &noncanonical) == RUSTCRYPTO_OK {
        failures |= 256;
    }

    failures
}
