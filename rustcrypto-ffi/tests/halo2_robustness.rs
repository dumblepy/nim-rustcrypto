//! Bounded robustness tests for the Halo2 KZG/BN254 v1 C ABI.
//!
//! These tests exercise only the public `extern "C"` entry points:
//! `rustcrypto_halo2_kzg_bn254_verify`, `..._params_validate`,
//! `..._vk_validate`, and `..._instances_validate`.
//!
//! The suite is deliberately deterministic and bounded:
//! - the only large allocation is one shared `MAX_PROOF_LEN + 1` scratch
//!   buffer used by the over-size cases;
//! - the mutation loop uses a fixed-seed xorshift64 PRNG and a fixed
//!   iteration count.

use core::ffi::c_int;
use rust_crypto_ffi::halo2::{
    HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN, HALO2_KZG_BN254_MAX_INSTANCE_COLUMNS,
    HALO2_KZG_BN254_MAX_PROOF_LEN, HALO2_KZG_BN254_MAX_PROTOCOL_LEN, HALO2_KZG_BN254_PARAMS_V1_LEN,
    HALO2_KZG_BN254_VK_V1_HEADER_LEN, rustcrypto_halo2_kzg_bn254_instances_validate,
    rustcrypto_halo2_kzg_bn254_params_validate, rustcrypto_halo2_kzg_bn254_verify,
    rustcrypto_halo2_kzg_bn254_vk_validate,
};
use rust_crypto_ffi::{
    RUSTCRYPTO_ERR_INVALID_CURVE_POINT, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_PANIC, RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_OK,
};

const FIXTURE: &str = include_str!("../../tests/fixtures/halo2_kzg_bn254_v1.hex");

struct Fixture {
    params: Vec<u8>,
    vk: Vec<u8>,
    proof: Vec<u8>,
    instances: Vec<u8>,
}

impl Fixture {
    fn load() -> Self {
        let params = fixture_value(FIXTURE, "PARAMS");
        let vk = fixture_value(FIXTURE, "VK");
        let proof = fixture_value(FIXTURE, "PROOF");
        let instances = fixture_value(FIXTURE, "INSTANCES");

        // The tests rely on the committed v1 fixture being structurally valid.
        assert_eq!(params.len(), HALO2_KZG_BN254_PARAMS_V1_LEN);
        assert!(vk.len() > HALO2_KZG_BN254_VK_V1_HEADER_LEN);
        assert!(!proof.is_empty());
        assert!(instances.len() > HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN);

        Self {
            params,
            vk,
            proof,
            instances,
        }
    }

    fn verify(&self) -> c_int {
        verify(&self.params, &self.vk, &self.proof, &self.instances)
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd-length hex fixture value");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex fixture value"))
        .collect()
}

fn fixture_value(fixture: &str, name: &str) -> Vec<u8> {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .map(unhex)
        .unwrap_or_else(|| panic!("missing fixture value {name}"))
}

/// Call `rustcrypto_halo2_kzg_bn254_verify` through the public C ABI.
fn verify_raw(
    params_ptr: *const u8,
    params_len: usize,
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    rustcrypto_halo2_kzg_bn254_verify(
        params_ptr,
        params_len,
        vk_ptr,
        vk_len,
        proof_ptr,
        proof_len,
        instances_ptr,
        instances_len,
    )
}

/// Convenience wrapper for the common "all inputs are real slices" case.
fn verify(params: &[u8], vk: &[u8], proof: &[u8], instances: &[u8]) -> c_int {
    verify_raw(
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

#[test]
fn rejects_null_pointers_with_non_zero_length() {
    let fx = Fixture::load();

    // Valid lengths, so all earlier length gates pass and the NULL check is
    // actually reached.
    let statuses = [
        (
            "params",
            verify_raw(
                core::ptr::null(),
                fx.params.len(),
                fx.vk.as_ptr(),
                fx.vk.len(),
                fx.proof.as_ptr(),
                fx.proof.len(),
                fx.instances.as_ptr(),
                fx.instances.len(),
            ),
        ),
        (
            "vk",
            verify_raw(
                fx.params.as_ptr(),
                fx.params.len(),
                core::ptr::null(),
                fx.vk.len(),
                fx.proof.as_ptr(),
                fx.proof.len(),
                fx.instances.as_ptr(),
                fx.instances.len(),
            ),
        ),
        (
            "proof",
            verify_raw(
                fx.params.as_ptr(),
                fx.params.len(),
                fx.vk.as_ptr(),
                fx.vk.len(),
                core::ptr::null(),
                fx.proof.len(),
                fx.instances.as_ptr(),
                fx.instances.len(),
            ),
        ),
        (
            "instances",
            verify_raw(
                fx.params.as_ptr(),
                fx.params.len(),
                fx.vk.as_ptr(),
                fx.vk.len(),
                fx.proof.as_ptr(),
                fx.proof.len(),
                core::ptr::null(),
                fx.instances.len(),
            ),
        ),
    ];

    for (name, status) in statuses {
        assert_eq!(
            status, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
            "NULL {name} with non-zero length must return NULL_INPUT_WITH_DATA, got {status}"
        );
    }
}

#[test]
fn rejects_zero_lengths() {
    let fx = Fixture::load();

    assert_eq!(
        verify_raw(
            core::ptr::null(),
            0,
            fx.vk.as_ptr(),
            fx.vk.len(),
            fx.proof.as_ptr(),
            fx.proof.len(),
            fx.instances.as_ptr(),
            fx.instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH,
        "zero-length params"
    );

    assert_eq!(
        verify_raw(
            fx.params.as_ptr(),
            fx.params.len(),
            core::ptr::null(),
            0,
            fx.proof.as_ptr(),
            fx.proof.len(),
            fx.instances.as_ptr(),
            fx.instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "zero-length vk"
    );

    assert_eq!(
        verify_raw(
            fx.params.as_ptr(),
            fx.params.len(),
            fx.vk.as_ptr(),
            fx.vk.len(),
            core::ptr::null(),
            0,
            fx.instances.as_ptr(),
            fx.instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
        "zero-length proof"
    );

    assert_eq!(
        verify_raw(
            fx.params.as_ptr(),
            fx.params.len(),
            fx.vk.as_ptr(),
            fx.vk.len(),
            fx.proof.as_ptr(),
            fx.proof.len(),
            core::ptr::null(),
            0,
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH,
        "zero-length instances"
    );
}

#[test]
fn rejects_oversized_lengths() {
    let fx = Fixture::load();

    // A single large scratch buffer shared by all over-size cases. This is the
    // largest allocation in the test binary: MAX_PROOF_LEN + 1 (~16 MiB + 1).
    let scratch = vec![0u8; HALO2_KZG_BN254_MAX_PROOF_LEN + 1];

    // params length != 328.
    assert_eq!(
        verify_raw(
            scratch.as_ptr(),
            HALO2_KZG_BN254_PARAMS_V1_LEN + 1,
            fx.vk.as_ptr(),
            fx.vk.len(),
            fx.proof.as_ptr(),
            fx.proof.len(),
            fx.instances.as_ptr(),
            fx.instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH,
        "oversized params"
    );

    // vk length > 12 + 2 MiB. The gate must fire before any pointer read.
    let oversized_vk_len = HALO2_KZG_BN254_VK_V1_HEADER_LEN + HALO2_KZG_BN254_MAX_PROTOCOL_LEN + 1;
    assert!(oversized_vk_len <= scratch.len());
    assert_eq!(
        verify_raw(
            fx.params.as_ptr(),
            fx.params.len(),
            scratch.as_ptr(),
            oversized_vk_len,
            fx.proof.as_ptr(),
            fx.proof.len(),
            fx.instances.as_ptr(),
            fx.instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "oversized vk"
    );

    // proof length > 16 MiB.
    assert_eq!(
        verify_raw(
            fx.params.as_ptr(),
            fx.params.len(),
            fx.vk.as_ptr(),
            fx.vk.len(),
            scratch.as_ptr(),
            HALO2_KZG_BN254_MAX_PROOF_LEN + 1,
            fx.instances.as_ptr(),
            fx.instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
        "oversized proof"
    );

    // instances length > 16 MiB.
    assert_eq!(
        verify_raw(
            fx.params.as_ptr(),
            fx.params.len(),
            fx.vk.as_ptr(),
            fx.vk.len(),
            fx.proof.as_ptr(),
            fx.proof.len(),
            scratch.as_ptr(),
            HALO2_KZG_BN254_MAX_PROOF_LEN + 1,
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH,
        "oversized instances"
    );
}

#[test]
fn rejects_truncated_buffers() {
    let fx = Fixture::load();

    assert_eq!(
        verify(
            &fx.params[..HALO2_KZG_BN254_PARAMS_V1_LEN - 1],
            &fx.vk,
            &fx.proof,
            &fx.instances,
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH,
        "params truncated by one byte"
    );

    for vk_len in [11, HALO2_KZG_BN254_VK_V1_HEADER_LEN, fx.vk.len() - 1] {
        assert_eq!(
            verify(&fx.params, &fx.vk[..vk_len], &fx.proof, &fx.instances),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
            "vk truncated to {vk_len} bytes"
        );
    }

    // A truncated proof is rejected by the transcript reader / trailing-byte
    // check. The concrete status is INVALID_PROOF_FORMAT; the assertion below
    // documents that a non-zero rejection is required even if the transcript
    // implementation changes which parse stage fails.
    let truncated_proof_status = verify(
        &fx.params,
        &fx.vk,
        &fx.proof[..fx.proof.len() - 1],
        &fx.instances,
    );
    assert_eq!(
        truncated_proof_status, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
        "proof truncated by one byte must be rejected with INVALID_PROOF_FORMAT, got {truncated_proof_status}"
    );

    for instances_len in [
        11,
        HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN,
        fx.instances.len() - 1,
    ] {
        assert_eq!(
            verify(
                &fx.params,
                &fx.vk,
                &fx.proof,
                &fx.instances[..instances_len]
            ),
            RUSTCRYPTO_ERR_INVALID_LENGTH,
            "instances truncated to {instances_len} bytes"
        );
    }
}

#[test]
fn rejects_trailing_bytes() {
    let fx = Fixture::load();

    let mut vk = fx.vk.clone();
    vk.push(0);
    assert_eq!(
        verify(&fx.params, &vk, &fx.proof, &fx.instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "vk with one trailing byte"
    );

    let mut proof = fx.proof.clone();
    proof.push(0);
    assert_eq!(
        verify(&fx.params, &fx.vk, &proof, &fx.instances),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
        "proof with one trailing byte"
    );

    let mut instances = fx.instances.clone();
    instances.push(0);
    assert_eq!(
        verify(&fx.params, &fx.vk, &fx.proof, &instances),
        RUSTCRYPTO_ERR_INVALID_LENGTH,
        "instances with one trailing byte"
    );
}

fn vk_with_protocol_len(vk: &[u8], protocol_len: u32) -> Vec<u8> {
    let mut out = vk.to_vec();
    out[8..HALO2_KZG_BN254_VK_V1_HEADER_LEN].copy_from_slice(&protocol_len.to_be_bytes());
    out
}

#[test]
fn rejects_malformed_protocol_length_header() {
    let fx = Fixture::load();

    let zero = vk_with_protocol_len(&fx.vk, 0);
    assert_eq!(
        verify(&fx.params, &zero, &fx.proof, &fx.instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "protocol_len = 0"
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_vk_validate(zero.as_ptr(), zero.len()),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "protocol_len = 0 (vk_validate)"
    );

    let too_large = vk_with_protocol_len(&fx.vk, HALO2_KZG_BN254_MAX_PROTOCOL_LEN as u32 + 1);
    assert_eq!(
        verify(&fx.params, &too_large, &fx.proof, &fx.instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "protocol_len = MAX + 1"
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_vk_validate(too_large.as_ptr(), too_large.len()),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "protocol_len = MAX + 1 (vk_validate)"
    );

    // Actual protocol length minus one, plus an extra byte so the total length
    // stays the same as the original VK. The header and body disagree.
    let actual_protocol_len = fx.vk.len() - HALO2_KZG_BN254_VK_V1_HEADER_LEN;
    let mut off_by_one = vk_with_protocol_len(&fx.vk, (actual_protocol_len - 1) as u32);
    off_by_one.push(0);
    assert_eq!(
        off_by_one.len(),
        fx.vk.len() + 1,
        "sanity: trailing byte appended"
    );
    assert_eq!(
        verify(&fx.params, &off_by_one, &fx.proof, &fx.instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "protocol_len = actual - 1 with trailing byte"
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_vk_validate(off_by_one.as_ptr(), off_by_one.len()),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
        "protocol_len = actual - 1 with trailing byte (vk_validate)"
    );
}

#[test]
fn rejects_invalid_instance_layout() {
    let fx = Fixture::load();

    let mut too_many_columns = fx.instances.clone();
    let column_count = (HALO2_KZG_BN254_MAX_INSTANCE_COLUMNS + 1) as u32;
    too_many_columns[8..HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN]
        .copy_from_slice(&column_count.to_be_bytes());
    assert_eq!(
        verify(&fx.params, &fx.vk, &fx.proof, &too_many_columns),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
        "column_count = MAX + 1"
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_instances_validate(
            too_many_columns.as_ptr(),
            too_many_columns.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
        "column_count = MAX + 1 (instances_validate)"
    );

    let mut huge_value_count = fx.instances.clone();
    huge_value_count
        [HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN..HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        verify(&fx.params, &fx.vk, &fx.proof, &huge_value_count),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
        "value_count = 0xFFFFFFFF"
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_instances_validate(
            huge_value_count.as_ptr(),
            huge_value_count.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
        "value_count = 0xFFFFFFFF (instances_validate)"
    );
}

#[test]
fn rejects_non_canonical_instance_value_and_corrupted_params() {
    let fx = Fixture::load();

    let mut non_canonical = fx.instances.clone();
    let last_value = non_canonical.len() - 32;
    non_canonical[last_value..].fill(0xFF);
    assert_eq!(
        verify(&fx.params, &fx.vk, &fx.proof, &non_canonical),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
        "non-canonical Fr in the last 32-byte instance value"
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_instances_validate(non_canonical.as_ptr(), non_canonical.len(),),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
        "non-canonical Fr in the last 32-byte instance value (instances_validate)"
    );

    // Corrupt the last byte of tau_g2 (the final G2 point in params). Any
    // structural corruption must be rejected; depending on whether the byte
    // lands on a non-canonical/degenerate coordinate or still decodes as a
    // point, the implementation returns INVALID_CURVE_POINT (21) or
    // VERIFICATION_FAILED (8).
    let mut corrupted_params = fx.params.clone();
    let last = corrupted_params.len() - 1;
    corrupted_params[last] ^= 0x01;
    let status = verify(&corrupted_params, &fx.vk, &fx.proof, &fx.instances);
    assert_ne!(status, RUSTCRYPTO_OK, "corrupted params must be rejected");
    assert_ne!(
        status, RUSTCRYPTO_ERR_PANIC,
        "corrupted params must not panic"
    );
    assert!(
        status == RUSTCRYPTO_ERR_VERIFICATION_FAILED
            || status == RUSTCRYPTO_ERR_INVALID_CURVE_POINT,
        "corrupted params returned unexpected status {status}"
    );

    let params_status = rustcrypto_halo2_kzg_bn254_params_validate(
        corrupted_params.as_ptr(),
        corrupted_params.len(),
    );
    assert_ne!(
        params_status, RUSTCRYPTO_OK,
        "corrupted params must fail params_validate"
    );
    assert_ne!(
        params_status, RUSTCRYPTO_ERR_PANIC,
        "corrupted params must not panic params_validate"
    );
}

#[test]
fn direct_validators_accept_fixture_and_reject_malformed_inputs() {
    let fx = Fixture::load();

    // params_validate
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_params_validate(fx.params.as_ptr(), fx.params.len()),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_params_validate(core::ptr::null(), fx.params.len()),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_params_validate(core::ptr::null(), 0),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_params_validate(fx.params.as_ptr(), fx.params.len() - 1),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    // Use a real 329-byte buffer: never pass a length larger than the actual
    // allocation, even though the implementation has an early length gate.
    let oversized_params = [0u8; HALO2_KZG_BN254_PARAMS_V1_LEN + 1];
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_params_validate(
            oversized_params.as_ptr(),
            oversized_params.len()
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // vk_validate
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_vk_validate(fx.vk.as_ptr(), fx.vk.len()),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_vk_validate(core::ptr::null(), fx.vk.len()),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );
    for vk_len in [0, 11, HALO2_KZG_BN254_VK_V1_HEADER_LEN, fx.vk.len() - 1] {
        assert_eq!(
            rustcrypto_halo2_kzg_bn254_vk_validate(fx.vk.as_ptr(), vk_len),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
            "vk_validate length {vk_len}"
        );
    }
    let mut trailing_vk = fx.vk.clone();
    trailing_vk.push(0);
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_vk_validate(trailing_vk.as_ptr(), trailing_vk.len()),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );

    // instances_validate
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_instances_validate(fx.instances.as_ptr(), fx.instances.len()),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_instances_validate(core::ptr::null(), fx.instances.len()),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );
    for instances_len in [
        0,
        11,
        HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN,
        fx.instances.len() - 1,
    ] {
        assert_eq!(
            rustcrypto_halo2_kzg_bn254_instances_validate(fx.instances.as_ptr(), instances_len),
            RUSTCRYPTO_ERR_INVALID_LENGTH,
            "instances_validate length {instances_len}"
        );
    }
    let mut trailing_instances = fx.instances.clone();
    trailing_instances.push(0);
    assert_eq!(
        rustcrypto_halo2_kzg_bn254_instances_validate(
            trailing_instances.as_ptr(),
            trailing_instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
}

/// Small deterministic xorshift64* style PRNG for the mutation fuzz loop.
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        assert_ne!(seed, 0, "xorshift64 seed must be non-zero");
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0);
        (self.next_u64() % bound as u64) as usize
    }
}

#[test]
fn bounded_mutation_fuzz_is_total_and_never_panics() {
    let fx = Fixture::load();
    assert_eq!(
        fx.verify(),
        RUSTCRYPTO_OK,
        "valid fixture must verify before fuzzing"
    );

    const ITERATIONS: usize = 2000;
    const ALLOWED: [c_int; 9] = [0, 3, 8, 9, 20, 21, 22, 23, 24];

    let mut rng = XorShift64::new(0x9E37_79B9_7F4A_7C15);
    for iteration in 0..ITERATIONS {
        let mut params = fx.params.clone();
        let mut vk = fx.vk.clone();
        let mut proof = fx.proof.clone();
        let mut instances = fx.instances.clone();

        // Mutate 1-4 random bytes, mixing the four input buffers.
        let mut trace = Vec::new();
        let mutations = 1 + rng.below(4);
        for _ in 0..mutations {
            let target = rng.below(4);
            let buffer = match target {
                0 => &mut params,
                1 => &mut vk,
                2 => &mut proof,
                _ => &mut instances,
            };
            let index = rng.below(buffer.len());
            let delta = (rng.next_u32() as u8) | 1;
            buffer[index] ^= delta;
            trace.push((["params", "vk", "proof", "instances"][target], index, delta));
        }

        let status = verify(&params, &vk, &proof, &instances);
        assert_ne!(
            status, RUSTCRYPTO_ERR_PANIC,
            "iteration {iteration}: FFI layer converted a panic to RUSTCRYPTO_ERR_PANIC (mutations: {trace:?})"
        );
        assert!(
            ALLOWED.contains(&status),
            "iteration {iteration}: unexpected status {status} (allowed {ALLOWED:?}, mutations: {trace:?})"
        );
    }
}

#[test]
fn repeated_verification_is_stable() {
    let fx = Fixture::load();
    for iteration in 0..100 {
        assert_eq!(
            fx.verify(),
            RUSTCRYPTO_OK,
            "valid fixture failed on verification iteration {iteration}"
        );
    }
}

#[test]
fn regression_mutated_protocol_query_is_rejected_without_panicking() {
    // This exact one-byte VK mutation used to reach
    // `snark-verifier`'s `evaluations.remove(query).unwrap()` and panic.
    // `parse_protocol` now rejects the inconsistent protocol shape first.
    let fx = Fixture::load();
    let mut vk = fx.vk.clone();
    vk[444] ^= 0x39;
    let status = verify(&fx.params, &vk, &fx.proof, &fx.instances);
    assert_ne!(status, RUSTCRYPTO_ERR_PANIC);
    assert_ne!(status, RUSTCRYPTO_OK);
}
