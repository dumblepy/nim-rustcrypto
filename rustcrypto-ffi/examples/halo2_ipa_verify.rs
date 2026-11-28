//! Halo2 IPA/BN254 v1 fixture smoke test for native and wasm32-wasip1.
//!
//! Usage: `cargo run --example halo2_ipa_verify`
//!
//! Loads the committed fixture at compile time and calls the same C ABI that
//! the Nim wrapper uses. The verifier path consumes no randomness, filesystem,
//! clock, threads, or network: it only regenerates `ParamsIPA::new(k)` from the
//! `k` embedded in the verifying key header.
//!
//! Returns a non-zero exit status when any check fails. The check set is
//! deliberately panic-free so that it is safe under `panic = "abort"` in wasm.

use rust_crypto_ffi::halo2_ipa::{
    rustcrypto_halo2_ipa_bn254_instances_validate, rustcrypto_halo2_ipa_bn254_proof_validate,
    rustcrypto_halo2_ipa_bn254_verify, rustcrypto_halo2_ipa_bn254_vk_validate,
};

const FIXTURE: &str = include_str!("../../tests/fixtures/halo2_ipa_bn254_v1.hex");

const RUSTCRYPTO_OK: i32 = 0;
const RUSTCRYPTO_ERR_VERIFICATION_FAILED: i32 = 8;
const RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT: i32 = 20;

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for index in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(text.get(index..index + 2)?, 16).ok()?);
    }
    Some(out)
}

fn fixture_value(name: &str) -> Option<Vec<u8>> {
    let prefix = format!("{name}=");
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(unhex)
}

fn verify(vk: &[u8], proof: &[u8], instances: &[u8]) -> i32 {
    rustcrypto_halo2_ipa_bn254_verify(
        vk.as_ptr(),
        vk.len(),
        proof.as_ptr(),
        proof.len(),
        instances.as_ptr(),
        instances.len(),
    )
}

/// Returns 0 when every check passes, otherwise a bit mask of failed checks.
pub(crate) fn smoke() -> i32 {
    let (Some(vk), Some(proof), Some(instances)) = (
        fixture_value("VK"),
        fixture_value("PROOF"),
        fixture_value("INSTANCES"),
    ) else {
        return 1;
    };

    let mut failures = 0;

    if rustcrypto_halo2_ipa_bn254_vk_validate(vk.as_ptr(), vk.len()) != RUSTCRYPTO_OK
        || rustcrypto_halo2_ipa_bn254_proof_validate(proof.as_ptr(), proof.len()) != RUSTCRYPTO_OK
        || rustcrypto_halo2_ipa_bn254_instances_validate(instances.as_ptr(), instances.len())
            != RUSTCRYPTO_OK
    {
        failures |= 1 << 0;
    }

    if verify(&vk, &proof, &instances) != RUSTCRYPTO_OK {
        failures |= 1 << 1;
    }
    // The verifier must be side-effect free.
    if verify(&vk, &proof, &instances) != RUSTCRYPTO_OK {
        failures |= 1 << 2;
    }

    // y = 35 -> 34 is still a canonical Fr value, so this must fail verification.
    let mut wrong_instances = instances.clone();
    match wrong_instances.last_mut() {
        Some(last) => *last ^= 1,
        None => failures |= 1 << 3,
    }
    if verify(&vk, &proof, &wrong_instances) != RUSTCRYPTO_ERR_VERIFICATION_FAILED {
        failures |= 1 << 3;
    }

    // A tampered transcript must never be accepted (status may be 8 or 22).
    let mut tampered_proof = proof.clone();
    match tampered_proof.last_mut() {
        Some(last) => *last ^= 1,
        None => failures |= 1 << 4,
    }
    if verify(&vk, &tampered_proof, &instances) == RUSTCRYPTO_OK {
        failures |= 1 << 4;
    }

    let mut truncated_proof = proof.clone();
    truncated_proof.pop();
    if verify(&vk, &truncated_proof, &instances) == RUSTCRYPTO_OK {
        failures |= 1 << 5;
    }

    let mut bad_magic_instances = instances.clone();
    if let Some(first) = bad_magic_instances.first_mut() {
        *first ^= 1;
    } else {
        failures |= 1 << 6;
    }
    if verify(&vk, &proof, &bad_magic_instances) == RUSTCRYPTO_OK {
        failures |= 1 << 6;
    }

    // Non-canonical Fr (0xff * 32) must be rejected before any curve work.
    let mut noncanonical = instances.clone();
    for byte in noncanonical.iter_mut().rev().take(32) {
        *byte = 0xff;
    }
    if verify(&vk, &proof, &noncanonical) != RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT {
        failures |= 1 << 7;
    }

    let mut truncated_vk = vk.clone();
    truncated_vk.pop();
    if verify(&truncated_vk, &proof, &instances) == RUSTCRYPTO_OK {
        failures |= 1 << 8;
    }

    failures
}

fn main() {
    let failures = smoke();
    if failures != 0 {
        eprintln!("halo2 ipa bn254 fixture smoke failed: bits {failures:#b}");
        std::process::exit(1);
    }
    println!("halo2 ipa bn254 fixture smoke: ok");
}
