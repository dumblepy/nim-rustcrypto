//! Deterministic codec fuzz / DoS / panic-resistance tests for the Halo2 IPA
//! BN254 C ABI and the compile-time external-circuit registry.
//!
//! These tests only use committed fixtures and the public entry points. There
//! is no external fuzz crate: mutations are driven by a fixed-seed xorshift64
//! PRNG, so failures are reproducible. Real proving/keygen is deliberately
//! avoided inside the mutation loops; a single small keygen per test that
//! needs key material is performed outside the loop.
//!
//! The suite has two layers:
//!
//! 1. Built-in C ABI: malformed/truncated/oversized envelopes, header field
//!    corruption, non-canonical field elements, null/zero-length pointers,
//!    revision confusion, and deterministic payload mutations.
//! 2. Generic registry: profile validation plus `validate_*` / `prepare` /
//!    `prove` / `verify` against a small in-test `ApprovedCircuit`.
//!
//! Every call must return a documented status code; `RUSTCRYPTO_ERR_PANIC` and
//! any undocumented value fail the test.

use core::ffi::c_int;

use rust_crypto_ffi::halo2_ipa::{
    HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE,
    HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1, HALO2_IPA_BN254_INSTANCES_V1_MAGIC,
    HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS, HALO2_IPA_BN254_MAX_INSTANCE_VALUES,
    HALO2_IPA_BN254_MAX_PK_LEN, HALO2_IPA_BN254_MAX_PROOF_LEN, HALO2_IPA_BN254_MAX_VK_LEN,
    HALO2_IPA_BN254_PROOF_V1_MAGIC, HALO2_IPA_BN254_VK_V1_MAGIC, HALO2_IPA_BN254_VK_V2_MAGIC,
    encode_instances_v1, rustcrypto_halo2_ipa_bn254_instances_validate,
    rustcrypto_halo2_ipa_bn254_proof_validate, rustcrypto_halo2_ipa_bn254_verify,
    rustcrypto_halo2_ipa_bn254_vk_validate,
};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use rust_crypto_ffi::halo2_ipa::{
    HALO2_IPA_BN254_PK_V1_MAGIC, HALO2_IPA_BN254_PK_V2_MAGIC, encode_fr_be,
    rustcrypto_halo2_ipa_bn254_pk_validate, rustcrypto_halo2_ipa_bn254_prepare,
    rustcrypto_halo2_ipa_bn254_prove,
};
use rust_crypto_ffi::halo2_ipa_registry::{
    ApprovedCircuit, CircuitProfile, HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE,
    HALO2_IPA_EXTERNAL_MAX_WITNESS_LEN, decode_fr_be,
    validate_instances as registry_validate_instances, validate_proof as registry_validate_proof,
    validate_vk as registry_validate_vk, verify as registry_verify,
};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use rust_crypto_ffi::halo2_ipa_registry::{
    prepare as registry_prepare, prove as registry_prove, validate_pk as registry_validate_pk,
};
use rust_crypto_ffi::{
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT, RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
    RUSTCRYPTO_ERR_PANIC, RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use rust_crypto_ffi::{RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT};

use halo2_axiom::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::plonk::{Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Instance};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CUBIC_FIXTURE: &str = include_str!("../../tests/fixtures/halo2_ipa_bn254_v1.hex");
const POSEIDON2_FIXTURE: &str = include_str!("../../tests/fixtures/halo2_ipa_poseidon2_v1.hex");
const POSEIDON2_ARITY12_FIXTURE: &str =
    include_str!("../../tests/fixtures/halo2_ipa_poseidon2_arity12_v1.hex");

struct Artifacts {
    vk: Vec<u8>,
    proof: Vec<u8>,
    instances: Vec<u8>,
    #[cfg_attr(feature = "halo2-ipa-verify-only", allow(dead_code))]
    witness: Vec<u8>,
}

impl Artifacts {
    fn load(fixture: &str) -> Self {
        Self {
            vk: fixture_value(fixture, "VK"),
            proof: fixture_value(fixture, "PROOF"),
            instances: fixture_value(fixture, "INSTANCES"),
            witness: fixture_value(fixture, "WITNESS"),
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd-length fixture hex");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("valid fixture hex"))
        .collect()
}

fn fixture_value(fixture: &str, name: &str) -> Vec<u8> {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .map(unhex)
        .unwrap_or_else(|| panic!("missing fixture value {name}"))
}

// ---------------------------------------------------------------------------
// Documented status sets
// ---------------------------------------------------------------------------

/// `rustcrypto_halo2_ipa_bn254_vk_validate`.
const VK_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
];

/// `rustcrypto_halo2_ipa_bn254_proof_validate`.
const PROOF_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
];

/// `rustcrypto_halo2_ipa_bn254_instances_validate`.
const INSTANCES_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
];

/// `rustcrypto_halo2_ipa_bn254_verify`.
const VERIFY_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
];

/// `rustcrypto_halo2_ipa_bn254_pk_validate`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
const PK_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
];

/// `rustcrypto_halo2_ipa_bn254_prepare`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
const PREPARE_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_NULL_OUTPUT,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
];

/// `rustcrypto_halo2_ipa_bn254_prove`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
const PROVE_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_NULL_OUTPUT,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
];

const REGISTRY_VK_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    RUSTCRYPTO_ERR_INVALID_PARAMETER,
];

const REGISTRY_VERIFY_STATUSES: &[c_int] = &[
    RUSTCRYPTO_OK,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    RUSTCRYPTO_ERR_INVALID_PARAMETER,
];

fn check_status(context: &str, status: c_int, allowed: &[c_int]) {
    assert_ne!(
        status, RUSTCRYPTO_ERR_PANIC,
        "{context}: a panic escaped as RUSTCRYPTO_ERR_PANIC"
    );
    assert!(
        allowed.contains(&status),
        "{context}: undocumented status {status} (allowed {allowed:?})"
    );
}

// ---------------------------------------------------------------------------
// C ABI wrappers
// ---------------------------------------------------------------------------

fn validate_vk(bytes: &[u8]) -> c_int {
    rustcrypto_halo2_ipa_bn254_vk_validate(bytes.as_ptr(), bytes.len())
}

fn validate_proof(bytes: &[u8]) -> c_int {
    rustcrypto_halo2_ipa_bn254_proof_validate(bytes.as_ptr(), bytes.len())
}

fn validate_instances(bytes: &[u8]) -> c_int {
    rustcrypto_halo2_ipa_bn254_instances_validate(bytes.as_ptr(), bytes.len())
}

fn verify(vk: &[u8], proof: &[u8], instances: &[u8]) -> c_int {
    rustcrypto_halo2_ipa_bn254_verify(
        vk.as_ptr(),
        vk.len(),
        proof.as_ptr(),
        proof.len(),
        instances.as_ptr(),
        instances.len(),
    )
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn validate_pk(bytes: &[u8]) -> c_int {
    rustcrypto_halo2_ipa_bn254_pk_validate(bytes.as_ptr(), bytes.len())
}

/// Two-call prepare through the public C ABI, returning caller-owned blobs.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prepare_keys(circuit_id: u32, k: u32) -> (Vec<u8>, Vec<u8>) {
    let mut vk_len = 0usize;
    let mut pk_len = 0usize;
    let sizing = rustcrypto_halo2_ipa_bn254_prepare(
        circuit_id,
        k,
        core::ptr::null_mut(),
        0,
        &mut vk_len,
        core::ptr::null_mut(),
        0,
        &mut pk_len,
    );
    check_status("prepare sizing", sizing, PREPARE_STATUSES);

    let mut vk = vec![0u8; vk_len];
    let mut pk = vec![0u8; pk_len];
    let mut written_vk = 0usize;
    let mut written_pk = 0usize;
    let status = rustcrypto_halo2_ipa_bn254_prepare(
        circuit_id,
        k,
        vk.as_mut_ptr(),
        vk.len(),
        &mut written_vk,
        pk.as_mut_ptr(),
        pk.len(),
        &mut written_pk,
    );
    check_status("prepare body", status, PREPARE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_OK);
    vk.truncate(written_vk);
    pk.truncate(written_pk);
    (vk, pk)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_raw(
    pk: &[u8],
    witness: &[u8],
    instances: &[u8],
    proof_out: *mut u8,
    proof_cap: usize,
) -> (c_int, usize) {
    let mut proof_len = 0usize;
    let status = rustcrypto_halo2_ipa_bn254_prove(
        pk.as_ptr(),
        pk.len(),
        witness.as_ptr(),
        witness.len(),
        instances.as_ptr(),
        instances.len(),
        proof_out,
        proof_cap,
        &mut proof_len,
    );
    (status, proof_len)
}

// ---------------------------------------------------------------------------
// Header / blob helpers
// ---------------------------------------------------------------------------

fn push_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("u32 header"))
}

fn key_header(magic: &[u8; 8], circuit_id: u32, k: u32, payload_len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(magic);
    push_u32_be(&mut out, circuit_id);
    push_u32_be(&mut out, k);
    push_u32_be(&mut out, payload_len);
    out
}

fn proof_header(payload_len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(HALO2_IPA_BN254_PROOF_V1_MAGIC);
    push_u32_be(&mut out, payload_len);
    out
}

fn instances_header(column_count: u32, value_counts: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(HALO2_IPA_BN254_INSTANCES_V1_MAGIC);
    push_u32_be(&mut out, column_count);
    for &count in value_counts {
        push_u32_be(&mut out, count);
        out.extend(core::iter::repeat_n(0u8, count as usize * 32));
    }
    out
}

/// BN254 `Fr` modulus (big-endian). A field element equal to this or larger is
/// non-canonical.
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

// ---------------------------------------------------------------------------
// 1. Baseline: committed fixtures are accepted
// ---------------------------------------------------------------------------

#[test]
fn committed_fixtures_are_accepted() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);
    assert_eq!(validate_vk(&cubic.vk), RUSTCRYPTO_OK);
    assert_eq!(validate_proof(&cubic.proof), RUSTCRYPTO_OK);
    assert_eq!(validate_instances(&cubic.instances), RUSTCRYPTO_OK);
    assert_eq!(
        verify(&cubic.vk, &cubic.proof, &cubic.instances),
        RUSTCRYPTO_OK
    );
    assert_eq!(cubic.vk.len(), 20 + read_u32_be(&cubic.vk, 16) as usize);
    assert_eq!(
        cubic.proof.len(),
        12 + read_u32_be(&cubic.proof, 8) as usize
    );

    let poseidon2 = Artifacts::load(POSEIDON2_FIXTURE);
    assert_eq!(&poseidon2.vk[..8], HALO2_IPA_BN254_VK_V2_MAGIC);
    assert_eq!(
        read_u32_be(&poseidon2.vk, 8),
        HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1
    );
    assert_eq!(validate_vk(&poseidon2.vk), RUSTCRYPTO_OK);
    assert_eq!(validate_proof(&poseidon2.proof), RUSTCRYPTO_OK);
    assert_eq!(validate_instances(&poseidon2.instances), RUSTCRYPTO_OK);
    assert_eq!(
        verify(&poseidon2.vk, &poseidon2.proof, &poseidon2.instances),
        RUSTCRYPTO_OK
    );

    let arity12 = Artifacts::load(POSEIDON2_ARITY12_FIXTURE);
    assert_eq!(
        read_u32_be(&arity12.vk, 8),
        HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE + 12
    );
    assert_eq!(validate_vk(&arity12.vk), RUSTCRYPTO_OK);
    assert_eq!(
        verify(&arity12.vk, &arity12.proof, &arity12.instances),
        RUSTCRYPTO_OK
    );
}

// ---------------------------------------------------------------------------
// 2. Truncation at every boundary
// ---------------------------------------------------------------------------

#[test]
fn every_truncation_is_total_and_documented() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);

    // Every prefix of the cubic envelopes. Header fields are rejected before
    // the payload is decoded, so this is cheap and covers every field boundary.
    for len in 0..=cubic.vk.len() {
        let status = validate_vk(&cubic.vk[..len]);
        check_status(&format!("cubic vk prefix {len}"), status, VK_STATUSES);
    }
    for len in 0..=cubic.proof.len() {
        let status = validate_proof(&cubic.proof[..len]);
        check_status(&format!("cubic proof prefix {len}"), status, PROOF_STATUSES);
    }
    for len in 0..=cubic.instances.len() {
        let status = validate_instances(&cubic.instances[..len]);
        check_status(
            &format!("cubic instances prefix {len}"),
            status,
            INSTANCES_STATUSES,
        );
    }

    // Representative field boundaries for the larger Poseidon2 V2 fixtures.
    let poseidon2 = Artifacts::load(POSEIDON2_FIXTURE);
    let vk_boundaries = [
        0usize,
        7,
        8,
        11,
        12,
        15,
        16,
        19,
        20,
        21,
        poseidon2.vk.len() / 2,
        poseidon2.vk.len() - 1,
    ];
    for &len in &vk_boundaries {
        let status = validate_vk(&poseidon2.vk[..len]);
        check_status(&format!("poseidon2 vk prefix {len}"), status, VK_STATUSES);
    }
    for &len in &[
        0usize,
        7,
        8,
        11,
        12,
        13,
        poseidon2.proof.len() / 2,
        poseidon2.proof.len() - 1,
    ] {
        let status = validate_proof(&poseidon2.proof[..len]);
        check_status(
            &format!("poseidon2 proof prefix {len}"),
            status,
            PROOF_STATUSES,
        );
    }
    for &len in &[0usize, 7, 8, 11, 12, 13, 16, poseidon2.instances.len() - 1] {
        let status = validate_instances(&poseidon2.instances[..len]);
        check_status(
            &format!("poseidon2 instances prefix {len}"),
            status,
            INSTANCES_STATUSES,
        );
    }

    // Truncation through `verify` must reject before proof verification. Only
    // one representative length per artifact is run here because every
    // `verify` call deterministically regenerates the IPA params.
    let len = cubic.vk.len() - 1;
    let status = verify(&cubic.vk[..len], &cubic.proof, &cubic.instances);
    check_status(
        &format!("verify cubic vk prefix {len}"),
        status,
        VERIFY_STATUSES,
    );
    assert_ne!(status, RUSTCRYPTO_OK);

    let len = cubic.proof.len() - 1;
    let status = verify(&cubic.vk, &cubic.proof[..len], &cubic.instances);
    check_status(
        &format!("verify cubic proof prefix {len}"),
        status,
        VERIFY_STATUSES,
    );
    assert_ne!(status, RUSTCRYPTO_OK);

    let len = cubic.instances.len() - 1;
    let status = verify(&cubic.vk, &cubic.proof, &cubic.instances[..len]);
    check_status(
        &format!("verify cubic instances prefix {len}"),
        status,
        VERIFY_STATUSES,
    );
    assert_ne!(status, RUSTCRYPTO_OK);
}

// ---------------------------------------------------------------------------
// 3. Header corruption / trailing bytes / bad magic / wrong id / wrong k
// ---------------------------------------------------------------------------

#[test]
fn header_corruption_is_rejected_with_documented_status() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);

    // Trailing bytes are rejected by every envelope parser.
    let mut trailing = cubic.vk.clone();
    trailing.push(0);
    assert_eq!(validate_vk(&trailing), RUSTCRYPTO_ERR_INVALID_LENGTH);
    let mut trailing = cubic.proof.clone();
    trailing.push(0);
    assert_eq!(
        validate_proof(&trailing),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );
    let mut trailing = cubic.instances.clone();
    trailing.push(0);
    assert_eq!(validate_instances(&trailing), RUSTCRYPTO_ERR_INVALID_LENGTH);

    // Bad magic.
    let mut bad = cubic.vk.clone();
    bad[..8].copy_from_slice(b"RCH2V1\0\0");
    assert_eq!(validate_vk(&bad), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    let mut bad = cubic.proof.clone();
    bad[..8].copy_from_slice(b"RCH2P1\0\0");
    assert_eq!(validate_proof(&bad), RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    let mut bad = cubic.instances.clone();
    bad[0] ^= 0x01;
    assert_eq!(validate_instances(&bad), RUSTCRYPTO_ERR_INVALID_LENGTH);

    // Unknown circuit id.
    let mut unknown = cubic.vk.clone();
    write_u32_be(&mut unknown, 8, 3);
    assert_eq!(validate_vk(&unknown), RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);

    // Circuit id whose revision does not match the V1 magic.
    let mut poseidon_id = cubic.vk.clone();
    write_u32_be(
        &mut poseidon_id,
        8,
        HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1,
    );
    assert_eq!(
        validate_vk(&poseidon_id),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );

    // k outside [4, 16], and k that disagrees with the embedded key.
    for k in [0u32, 3, 17, u32::MAX] {
        let mut bad_k = cubic.vk.clone();
        write_u32_be(&mut bad_k, 12, k);
        assert_eq!(
            validate_vk(&bad_k),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
            "vk k={k}"
        );
    }

    // Length header lies: zero, too large, one more, one fewer.
    let actual_vk_len = read_u32_be(&cubic.vk, 16);
    for claimed in [0u32, actual_vk_len + 1, actual_vk_len - 1, u32::MAX] {
        let mut bad_len = cubic.vk.clone();
        write_u32_be(&mut bad_len, 16, claimed);
        let status = validate_vk(&bad_len);
        check_status("vk length header", status, VK_STATUSES);
        assert_ne!(status, RUSTCRYPTO_OK, "vk claimed length {claimed}");
    }

    let actual_proof_len = read_u32_be(&cubic.proof, 8);
    for claimed in [0u32, actual_proof_len + 1, actual_proof_len - 1, u32::MAX] {
        let mut bad_len = cubic.proof.clone();
        write_u32_be(&mut bad_len, 8, claimed);
        assert_eq!(
            validate_proof(&bad_len),
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
            "proof claimed length {claimed}"
        );
    }

    // Instances column/value count headers.
    for columns in [
        0u32,
        HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS as u32 + 1,
        u32::MAX,
    ] {
        let mut bad = cubic.instances.clone();
        write_u32_be(&mut bad, 8, columns);
        assert_eq!(
            validate_instances(&bad),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
            "instances column_count {columns}"
        );
    }
    for count in [0u32, 2, 14, u32::MAX] {
        let mut bad = cubic.instances.clone();
        write_u32_be(&mut bad, 12, count);
        let status = validate_instances(&bad);
        check_status(
            &format!("instances value_count {count}"),
            status,
            INSTANCES_STATUSES,
        );
        // 1 is the only cubic-shaped count accepted by the circuit-agnostic
        // validator; 2..=13 is a valid Poseidon2 arity shape.
        if count == 0 || count == 14 || count == u32::MAX {
            assert_ne!(status, RUSTCRYPTO_OK, "instances value_count {count}");
        }
    }

    // `verify` must reject the same header corruption without panicking.
    let checks = [
        ("vk magic", {
            let mut vk = cubic.vk.clone();
            vk[0] ^= 0x01;
            verify(&vk, &cubic.proof, &cubic.instances)
        }),
        ("vk circuit", {
            let mut vk = cubic.vk.clone();
            write_u32_be(&mut vk, 8, 3);
            verify(&vk, &cubic.proof, &cubic.instances)
        }),
        ("vk k", {
            let mut vk = cubic.vk.clone();
            write_u32_be(&mut vk, 12, 17);
            verify(&vk, &cubic.proof, &cubic.instances)
        }),
        ("proof magic", {
            let mut proof = cubic.proof.clone();
            proof[0] ^= 0x01;
            verify(&cubic.vk, &proof, &cubic.instances)
        }),
        ("proof length", {
            let mut proof = cubic.proof.clone();
            write_u32_be(&mut proof, 8, u32::MAX);
            verify(&cubic.vk, &proof, &cubic.instances)
        }),
        ("instances columns", {
            let mut instances = cubic.instances.clone();
            write_u32_be(&mut instances, 8, 9);
            verify(&cubic.vk, &cubic.proof, &instances)
        }),
        ("instances values", {
            let mut instances = cubic.instances.clone();
            write_u32_be(&mut instances, 12, 2);
            verify(&cubic.vk, &cubic.proof, &instances)
        }),
    ];
    for (name, status) in checks {
        check_status(name, status, VERIFY_STATUSES);
        assert_ne!(status, RUSTCRYPTO_OK, "{name} must be rejected");
    }
}

// ---------------------------------------------------------------------------
// 4. Non-canonical Fr, all-zero buffers, null / zero-length pointers
// ---------------------------------------------------------------------------

#[test]
fn noncanonical_and_zero_buffers_are_documented() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);
    let value_start = cubic.instances.len() - 32;

    // `Fr::MODULUS` itself is not a canonical field element.
    let mut at_modulus = cubic.instances.clone();
    at_modulus[value_start..].copy_from_slice(&FR_MODULUS_BE);
    assert_eq!(
        validate_instances(&at_modulus),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );
    assert_eq!(
        verify(&cubic.vk, &cubic.proof, &at_modulus),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );

    // `Fr::MODULUS - 1` is canonical and the envelope shape stays valid.
    let mut below_modulus = cubic.instances.clone();
    below_modulus[value_start..].copy_from_slice(&FR_MODULUS_BE);
    *below_modulus.last_mut().expect("last byte") -= 1;
    assert_eq!(validate_instances(&below_modulus), RUSTCRYPTO_OK);

    // 0xff..ff is far above the modulus.
    let mut all_ones = cubic.instances.clone();
    all_ones[value_start..].fill(0xff);
    assert_eq!(
        validate_instances(&all_ones),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );

    // All-zero buffers of representative lengths never panic.
    for len in [0usize, 8, 11, 12, 19, 20, 21, 48, 64] {
        let zeros = vec![0u8; len];
        check_status(&format!("zero vk {len}"), validate_vk(&zeros), VK_STATUSES);
        check_status(
            &format!("zero proof {len}"),
            validate_proof(&zeros),
            PROOF_STATUSES,
        );
        check_status(
            &format!("zero instances {len}"),
            validate_instances(&zeros),
            INSTANCES_STATUSES,
        );
        check_status(
            &format!("zero verify {len}"),
            verify(&zeros, &zeros, &zeros),
            VERIFY_STATUSES,
        );
    }
}

#[test]
fn null_and_zero_length_pointers_are_documented() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);

    // Null pointer with a non-zero length reaches the pointer check.
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_vk_validate(core::ptr::null(), cubic.vk.len()),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_proof_validate(core::ptr::null(), cubic.proof.len()),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_instances_validate(core::ptr::null(), cubic.instances.len()),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );

    // Null pointers with data through `verify`, one argument at a time.
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_verify(
            core::ptr::null(),
            cubic.vk.len(),
            cubic.proof.as_ptr(),
            cubic.proof.len(),
            cubic.instances.as_ptr(),
            cubic.instances.len(),
        ),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_verify(
            cubic.vk.as_ptr(),
            cubic.vk.len(),
            core::ptr::null(),
            cubic.proof.len(),
            cubic.instances.as_ptr(),
            cubic.instances.len(),
        ),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_verify(
            cubic.vk.as_ptr(),
            cubic.vk.len(),
            cubic.proof.as_ptr(),
            cubic.proof.len(),
            core::ptr::null(),
            cubic.instances.len(),
        ),
        RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );

    // Zero length is a length error even with a valid non-null pointer.
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_vk_validate(cubic.vk.as_ptr(), 0),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_proof_validate(cubic.proof.as_ptr(), 0),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_instances_validate(cubic.instances.as_ptr(), 0),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    assert_eq!(
        verify(&cubic.vk[..0], &cubic.proof, &cubic.instances),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    assert_eq!(
        verify(&cubic.vk, &cubic.proof[..0], &cubic.instances),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );
    assert_eq!(
        verify(&cubic.vk, &cubic.proof, &cubic.instances[..0]),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // Null pointers with zero length are still length errors (no read).
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_vk_validate(core::ptr::null(), 0),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_proof_validate(core::ptr::null(), 0),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_instances_validate(core::ptr::null(), 0),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
}

// ---------------------------------------------------------------------------
// 5. Bound checks that use length headers instead of huge allocations
// ---------------------------------------------------------------------------

#[test]
fn declared_bounds_are_enforced() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);

    // VK > 4 MiB: rejected from the length header alone.
    let oversized_vk = key_header(
        HALO2_IPA_BN254_VK_V1_MAGIC,
        HALO2_IPA_BN254_CIRCUIT_CUBIC_V1,
        8,
        HALO2_IPA_BN254_MAX_VK_LEN as u32 + 1,
    );
    assert_eq!(validate_vk(&oversized_vk), RUSTCRYPTO_ERR_INVALID_LENGTH);

    // Proof > 4 MiB.
    let oversized_proof = proof_header(HALO2_IPA_BN254_MAX_PROOF_LEN as u32 + 1);
    assert_eq!(
        validate_proof(&oversized_proof),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );

    // PK > 64 MiB: rejected without allocating the claimed payload.
    #[cfg(not(feature = "halo2-ipa-verify-only"))]
    {
        let oversized_pk = key_header(
            HALO2_IPA_BN254_PK_V1_MAGIC,
            HALO2_IPA_BN254_CIRCUIT_CUBIC_V1,
            8,
            HALO2_IPA_BN254_MAX_PK_LEN as u32 + 1,
        );
        assert_eq!(validate_pk(&oversized_pk), RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    // Instance column count > 8.
    let too_many_columns = instances_header(HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS as u32 + 1, &[1]);
    assert_eq!(
        validate_instances(&too_many_columns),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );

    // Total instance values > 4096. The outer blob bound also cap the total, so
    // the public C ABI reports INVALID_LENGTH; either way it must reject before
    // any unbounded allocation.
    let too_many_values = instances_header(2, &[2049, 2049]);
    let status = validate_instances(&too_many_values);
    check_status("total values > 4096", status, INSTANCES_STATUSES);
    assert_ne!(status, RUSTCRYPTO_OK);

    // A blob larger than the global instances bound is rejected by the outer
    // length check (MAX_INSTANCES_BLOB_LEN + 1).
    // Additionally claim a huge column count in a tiny buffer.
    let mut huge_count = Vec::new();
    huge_count.extend_from_slice(HALO2_IPA_BN254_INSTANCES_V1_MAGIC);
    push_u32_be(&mut huge_count, u32::MAX);
    assert_eq!(
        validate_instances(&huge_count),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );

    // A declared value count that claims more values than the buffer holds.
    let mut short_body = Vec::new();
    short_body.extend_from_slice(HALO2_IPA_BN254_INSTANCES_V1_MAGIC);
    push_u32_be(&mut short_body, 1);
    push_u32_be(&mut short_body, 2);
    short_body.extend_from_slice(&[0u8; 32]);
    assert_eq!(
        validate_instances(&short_body),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // The value-count total is capped even when the individual counts fit.
    let mut total_over = Vec::new();
    total_over.extend_from_slice(HALO2_IPA_BN254_INSTANCES_V1_MAGIC);
    push_u32_be(&mut total_over, 1);
    push_u32_be(
        &mut total_over,
        HALO2_IPA_BN254_MAX_INSTANCE_VALUES as u32 + 1,
    );
    assert_eq!(
        validate_instances(&total_over),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );

    // Sanity: the unmodified fixture remains accepted.
    assert_eq!(validate_instances(&cubic.instances), RUSTCRYPTO_OK);
}

// ---------------------------------------------------------------------------
// 6. Cross-revision checks (V1 cubic / V2 Poseidon2)
// ---------------------------------------------------------------------------

#[test]
fn cross_revision_artifacts_are_separated() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);
    let poseidon2 = Artifacts::load(POSEIDON2_FIXTURE);

    // V1 cubic is accepted.
    assert_eq!(&cubic.vk[..8], HALO2_IPA_BN254_VK_V1_MAGIC);
    assert_eq!(validate_vk(&cubic.vk), RUSTCRYPTO_OK);
    assert_eq!(
        verify(&cubic.vk, &cubic.proof, &cubic.instances),
        RUSTCRYPTO_OK
    );

    // V2 Poseidon2 is accepted.
    assert_eq!(&poseidon2.vk[..8], HALO2_IPA_BN254_VK_V2_MAGIC);
    assert_eq!(validate_vk(&poseidon2.vk), RUSTCRYPTO_OK);
    assert_eq!(
        verify(&poseidon2.vk, &poseidon2.proof, &poseidon2.instances),
        RUSTCRYPTO_OK
    );

    // V2 magic on the cubic circuit is rejected.
    let mut cubic_v2 = cubic.vk.clone();
    cubic_v2[..8].copy_from_slice(HALO2_IPA_BN254_VK_V2_MAGIC);
    assert_eq!(validate_vk(&cubic_v2), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    assert_eq!(
        verify(&cubic_v2, &cubic.proof, &cubic.instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );

    // V1 magic on the Poseidon2 payload is rejected.
    let mut poseidon_v1 = poseidon2.vk.clone();
    poseidon_v1[..8].copy_from_slice(HALO2_IPA_BN254_VK_V1_MAGIC);
    assert_eq!(
        validate_vk(&poseidon_v1),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );

    // Proofs/instances are revision-independent but cannot be moved between
    // circuits while keeping a valid statement.
    let cross = verify(&cubic.vk, &poseidon2.proof, &poseidon2.instances);
    check_status("cross-circuit proof", cross, VERIFY_STATUSES);
    assert_ne!(cross, RUSTCRYPTO_OK);
}

// ---------------------------------------------------------------------------
// 7. Deterministic mutation fuzz (fixed seed, no external crate)
// ---------------------------------------------------------------------------

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

    fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0);
        (self.next_u64() % bound as u64) as usize
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

fn mutate_byte(bytes: &mut [u8], rng: &mut XorShift64) {
    let index = rng.below(bytes.len());
    let delta = rng.byte() | 1;
    bytes[index] ^= delta;
}

fn fuzz_artifacts(name: &str, artifacts: &Artifacts, iterations: usize, seed: u64) {
    let mut rng = XorShift64::new(seed);
    for iteration in 0..iterations {
        let mut vk = artifacts.vk.clone();
        let mut proof = artifacts.proof.clone();
        let mut instances = artifacts.instances.clone();

        let mutations = 1 + rng.below(3);
        for _ in 0..mutations {
            match rng.below(3) {
                0 => mutate_byte(&mut vk, &mut rng),
                1 => mutate_byte(&mut proof, &mut rng),
                _ => mutate_byte(&mut instances, &mut rng),
            }
        }

        let context = format!("{name} iteration {iteration}");
        check_status(
            &format!("{context} vk_validate"),
            validate_vk(&vk),
            VK_STATUSES,
        );
        check_status(
            &format!("{context} proof_validate"),
            validate_proof(&proof),
            PROOF_STATUSES,
        );
        check_status(
            &format!("{context} instances_validate"),
            validate_instances(&instances),
            INSTANCES_STATUSES,
        );

        // Every `verify` call derives `ParamsIPA` from `k` again, so keep full
        // verification to a sparse, deterministic subset of iterations.
        if iteration % 256 == 0 {
            check_status(
                &format!("{context} verify"),
                verify(&vk, &proof, &instances),
                VERIFY_STATUSES,
            );
        }
    }
}

#[test]
fn deterministic_mutation_fuzz_never_panics() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);
    let poseidon2 = Artifacts::load(POSEIDON2_FIXTURE);

    assert_eq!(
        verify(&cubic.vk, &cubic.proof, &cubic.instances),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        verify(&poseidon2.vk, &poseidon2.proof, &poseidon2.instances),
        RUSTCRYPTO_OK
    );

    fuzz_artifacts("cubic", &cubic, 600, 0x9E37_79B9_7F4A_7C15);
    fuzz_artifacts("poseidon2", &poseidon2, 150, 0xD1B5_4A32_D192_ED03);
}

#[test]
fn representative_single_byte_mutations_are_documented() {
    let cubic = Artifacts::load(CUBIC_FIXTURE);

    // Header byte flips must always be rejected.
    for offset in 0..20 {
        let mut vk = cubic.vk.clone();
        vk[offset] ^= 0x01;
        let status = validate_vk(&vk);
        check_status(&format!("vk header byte {offset}"), status, VK_STATUSES);
        assert_ne!(status, RUSTCRYPTO_OK, "vk header byte {offset}");
        if [0usize, 8, 12, 16].contains(&offset) {
            let verify_status = verify(&vk, &cubic.proof, &cubic.instances);
            check_status(
                &format!("verify vk header byte {offset}"),
                verify_status,
                VERIFY_STATUSES,
            );
            assert_ne!(verify_status, RUSTCRYPTO_OK);
        }
    }
    for offset in 0..8 {
        let mut proof = cubic.proof.clone();
        proof[offset] ^= 0x01;
        assert_eq!(validate_proof(&proof), RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    for offset in 0..12 {
        let mut instances = cubic.instances.clone();
        instances[offset] ^= 0x01;
        let status = validate_instances(&instances);
        check_status(
            &format!("instances header byte {offset}"),
            status,
            INSTANCES_STATUSES,
        );
        assert_ne!(status, RUSTCRYPTO_OK, "instances header byte {offset}");
    }

    // Proof payload flips must not verify. This is deterministic for the
    // committed fixture; a false accept would be a security failure.
    for offset in [12usize, cubic.proof.len() / 2, cubic.proof.len() - 1] {
        let mut proof = cubic.proof.clone();
        proof[offset] ^= 0x01;
        let status = verify(&cubic.vk, &proof, &cubic.instances);
        check_status(
            &format!("proof payload byte {offset}"),
            status,
            VERIFY_STATUSES,
        );
        assert_ne!(status, RUSTCRYPTO_OK, "proof payload byte {offset}");
    }

    // VK payload flips may still decode as a (different) key, so only the
    // documented status set is required. `verify` must not panic.
    for offset in [20usize, 64, cubic.vk.len() / 2, cubic.vk.len() - 1] {
        let mut vk = cubic.vk.clone();
        vk[offset] ^= 0x01;
        check_status(
            &format!("vk payload byte {offset}"),
            validate_vk(&vk),
            VK_STATUSES,
        );
    }
    {
        let offset = 64usize;
        let mut vk = cubic.vk.clone();
        vk[offset] ^= 0x01;
        check_status(
            &format!("verify vk payload byte {offset}"),
            verify(&vk, &cubic.proof, &cubic.instances),
            VERIFY_STATUSES,
        );
    }

    // Instance value flips are valid envelopes but invalid statements.
    let value_offsets = [cubic.instances.len() - 32, cubic.instances.len() - 1];
    for offset in value_offsets {
        let mut instances = cubic.instances.clone();
        instances[offset] ^= 0x01;
        let status = validate_instances(&instances);
        check_status(
            &format!("instance value byte {offset}"),
            status,
            INSTANCES_STATUSES,
        );
        let verify_status = verify(&cubic.vk, &cubic.proof, &instances);
        check_status(
            &format!("verify instance value byte {offset}"),
            verify_status,
            VERIFY_STATUSES,
        );
        // Flipping a canonical value keeps it canonical here; verification must
        // fail against the committed proof.
        if status == RUSTCRYPTO_OK {
            assert_eq!(verify_status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);
        }
    }
}

// ---------------------------------------------------------------------------
// 8. Prover-side codec paths (gated for halo2-ipa-verify-only)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[test]
fn pk_codec_and_prove_bounds_are_documented() {
    let (vk, pk) = prepare_keys(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8);
    assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
    assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);
    assert_eq!(&pk[..8], HALO2_IPA_BN254_PK_V1_MAGIC);

    // Every prefix and representative boundaries of the PK envelope.
    for len in [0usize, 7, 8, 11, 12, 15, 16, 19, 20, 21, pk.len() - 1] {
        let status = validate_pk(&pk[..len]);
        check_status(&format!("pk prefix {len}"), status, PK_STATUSES);
        if len < pk.len() {
            assert_ne!(status, RUSTCRYPTO_OK, "pk prefix {len}");
        }
    }

    // Trailing byte, bad magic, wrong circuit id, wrong k, bad length fields.
    let mut trailing = pk.clone();
    trailing.push(0);
    assert_eq!(validate_pk(&trailing), RUSTCRYPTO_ERR_INVALID_LENGTH);

    let mut bad_magic = pk.clone();
    bad_magic[..8].copy_from_slice(HALO2_IPA_BN254_PK_V2_MAGIC);
    assert_eq!(validate_pk(&bad_magic), RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);

    let mut bad_circuit = pk.clone();
    write_u32_be(&mut bad_circuit, 8, 3);
    assert_eq!(
        validate_pk(&bad_circuit),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );

    for k in [0u32, 3, 17, u32::MAX] {
        let mut bad_k = pk.clone();
        write_u32_be(&mut bad_k, 12, k);
        assert_eq!(
            validate_pk(&bad_k),
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
            "pk k={k}"
        );
    }

    let actual_pk_len = read_u32_be(&pk, 16);
    for claimed in [0u32, actual_pk_len + 1, actual_pk_len - 1, u32::MAX] {
        let mut bad_len = pk.clone();
        write_u32_be(&mut bad_len, 16, claimed);
        assert_eq!(
            validate_pk(&bad_len),
            RUSTCRYPTO_ERR_INVALID_LENGTH,
            "pk claimed length {claimed}"
        );
    }

    // Header and payload mutations must stay within the documented status set.
    for offset in [0usize, 8, 12, 16, 20, pk.len() / 2, pk.len() - 1] {
        let mut mutated = pk.clone();
        mutated[offset] ^= 0x01;
        check_status(
            &format!("pk mutation byte {offset}"),
            validate_pk(&mutated),
            PK_STATUSES,
        );
    }

    // `prove` rejects malformed PK / witness / instances before proving.
    let witness = encode_fr_be(Fr::from(3u64));
    let instances = encode_instances_v1(&[vec![cubic_instance(3)]]).expect("instances");
    let mut out = vec![0u8; 4096];

    let (status, _) = prove_raw(&pk[..19], &witness, &instances, out.as_mut_ptr(), out.len());
    check_status("prove truncated pk", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);

    let mut v2_pk = pk.clone();
    v2_pk[..8].copy_from_slice(HALO2_IPA_BN254_PK_V2_MAGIC);
    let (status, _) = prove_raw(&v2_pk, &witness, &instances, out.as_mut_ptr(), out.len());
    check_status("prove relabelled pk", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);

    let mut wrong_id = pk.clone();
    write_u32_be(&mut wrong_id, 8, HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1);
    let (status, _) = prove_raw(&wrong_id, &witness, &instances, out.as_mut_ptr(), out.len());
    check_status("prove wrong id pk", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);

    let mut wrong_k = pk.clone();
    write_u32_be(&mut wrong_k, 12, 4);
    let (status, _) = prove_raw(&wrong_k, &witness, &instances, out.as_mut_ptr(), out.len());
    check_status("prove wrong k pk", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);

    // Witness length: too long (allocated), too short, non-canonical.
    for bad_witness in [vec![0u8; 64], vec![0u8; 16], vec![0xffu8; 32]] {
        let (status, _) = prove_raw(&pk, &bad_witness, &instances, out.as_mut_ptr(), out.len());
        check_status("prove bad witness", status, PROVE_STATUSES);
        assert_ne!(status, RUSTCRYPTO_OK);
    }

    // Instances shape / canonical checks happen before proving.
    let wrong_instance_count =
        encode_instances_v1(&[vec![cubic_instance(3), cubic_instance(4)]]).expect("instances");
    let (status, _) = prove_raw(
        &pk,
        &witness,
        &wrong_instance_count,
        out.as_mut_ptr(),
        out.len(),
    );
    check_status("prove wrong instance count", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);

    // A mismatched statement is rejected with INVALID_PARAMETER and does not
    // write a proof.
    let mismatched = encode_instances_v1(&[vec![cubic_instance(4)]]).expect("instances");
    let mut out_len = 0usize;
    let (status, _) = prove_raw(&pk, &witness, &mismatched, out.as_mut_ptr(), out.len());
    check_status("prove mismatched statement", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);

    // Null output sizing call still reports a required length.
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_prove(
            pk.as_ptr(),
            pk.len(),
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            core::ptr::null_mut(),
            0,
            &mut out_len,
        ),
        RUSTCRYPTO_ERR_NULL_OUTPUT
    );
    assert!(out_len > 0);

    // Null proof_len is rejected before doing any work.
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_prove(
            pk.as_ptr(),
            pk.len(),
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            out.as_mut_ptr(),
            out.len(),
            core::ptr::null_mut(),
        ),
        RUSTCRYPTO_ERR_NULL_OUTPUT
    );

    // prepare argument/pointer/parameter errors.
    let mut vk_len = 0usize;
    let mut pk_len = 0usize;
    for (id, k) in [(3u32, 8u32), (1, 3), (1, 17), (0x100 + 13, 9)] {
        let status = rustcrypto_halo2_ipa_bn254_prepare(
            id,
            k,
            core::ptr::null_mut(),
            0,
            &mut vk_len,
            core::ptr::null_mut(),
            0,
            &mut pk_len,
        );
        check_status("prepare invalid parameter", status, PREPARE_STATUSES);
        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER, "id={id} k={k}");
    }
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_prepare(
            1,
            8,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        ),
        RUSTCRYPTO_ERR_NULL_OUTPUT
    );

    // Too-short output buffer reports OUTPUT_TOO_SHORT and does not write.
    let mut short = [0u8; 1];
    let mut short_len = 0usize;
    let mut other_len = 0usize;
    assert_eq!(
        rustcrypto_halo2_ipa_bn254_prepare(
            1,
            8,
            short.as_mut_ptr(),
            short.len(),
            &mut short_len,
            short.as_mut_ptr(),
            short.len(),
            &mut other_len,
        ),
        RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT
    );
    assert_eq!(short, [0u8]);
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[test]
fn arity12_witness_length_overflow_is_rejected() {
    // k=9 is the minimum for arity 12. This is the only real keygen in the
    // bound-check path; it does not run inside any mutation loop.
    let (vk, pk) = prepare_keys(HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE + 12, 9);
    assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
    assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);

    let arity12 = Artifacts::load(POSEIDON2_ARITY12_FIXTURE);
    assert_eq!(arity12.witness.len(), 12 * 32);
    assert_eq!(validate_instances(&arity12.instances), RUSTCRYPTO_OK);

    let mut out = vec![0u8; 4096];

    // One extra field element: the declared witness length overflows the
    // 12 * 32 = 384 byte contract. The buffer is actually allocated so this is
    // not an out-of-bounds slice.
    let too_long = vec![0u8; 13 * 32];
    let (status, _) = prove_raw(
        &pk,
        &too_long,
        &arity12.instances,
        out.as_mut_ptr(),
        out.len(),
    );
    check_status("arity12 oversized witness", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);

    // One byte short.
    let mut too_short = arity12.witness.clone();
    too_short.pop();
    let (status, _) = prove_raw(
        &pk,
        &too_short,
        &arity12.instances,
        out.as_mut_ptr(),
        out.len(),
    );
    check_status("arity12 short witness", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);

    // Non-canonical field element in the witness is rejected before proving.
    let mut noncanonical = arity12.witness.clone();
    noncanonical[..32].fill(0xff);
    let (status, _) = prove_raw(
        &pk,
        &noncanonical,
        &arity12.instances,
        out.as_mut_ptr(),
        out.len(),
    );
    check_status("arity12 noncanonical witness", status, PROVE_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT);
}

/// Cubic public instance `y = x^3 + x + 5`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn cubic_instance(x: u64) -> Fr {
    let x = Fr::from(x);
    x * x * x + x + Fr::from(5u64)
}

// ---------------------------------------------------------------------------
// 9. Generic registry: profile validation
// ---------------------------------------------------------------------------

#[test]
fn registry_rejects_invalid_profiles() {
    let valid = CircuitProfile::new(HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE, 1, 4, 8, 32, &[1]);
    assert_eq!(valid.validate(), Ok(()));

    assert_eq!(
        CircuitProfile::new(0, 1, 4, 8, 32, &[1]).validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "external id base is reserved"
    );
    assert_eq!(
        CircuitProfile::new(HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE, 1, 3, 8, 32, &[1]).validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "min_k below global minimum"
    );
    assert_eq!(
        CircuitProfile::new(HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE, 1, 4, 17, 32, &[1]).validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "max_k above global maximum"
    );
    assert_eq!(
        CircuitProfile::new(HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE, 1, 8, 7, 32, &[1]).validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "min_k > max_k"
    );
    assert_eq!(
        CircuitProfile::new(
            HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE,
            1,
            4,
            8,
            HALO2_IPA_EXTERNAL_MAX_WITNESS_LEN + 1,
            &[1],
        )
        .validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "witness_len above external maximum"
    );
    assert_eq!(
        CircuitProfile::new(HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE, 1, 4, 8, 32, &[]).validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "empty instance columns"
    );
    assert_eq!(
        CircuitProfile::new(
            HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE,
            1,
            4,
            8,
            32,
            &[1; HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS + 1],
        )
        .validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "too many instance columns"
    );
    assert_eq!(
        CircuitProfile::new(HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE, 1, 4, 8, 32, &[0]).validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "zero-length instance column"
    );
    assert_eq!(
        CircuitProfile::new(
            HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE,
            1,
            4,
            8,
            32,
            &[HALO2_IPA_BN254_MAX_INSTANCE_VALUES, 1],
        )
        .validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "total instance values above the global cap"
    );
    assert_eq!(
        valid.with_bounds(0, 1, 1).validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "zero VK bound"
    );
    assert_eq!(
        valid
            .with_bounds(HALO2_IPA_BN254_MAX_VK_LEN + 1, 1, 1)
            .validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "VK bound above the global cap"
    );
    assert_eq!(
        valid
            .with_bounds(1, HALO2_IPA_BN254_MAX_PK_LEN + 1, 1)
            .validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "PK bound above the global cap"
    );
    assert_eq!(
        valid
            .with_bounds(1, 1, HALO2_IPA_BN254_MAX_PROOF_LEN + 1)
            .validate(),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        "proof bound above the global cap"
    );
}

// ---------------------------------------------------------------------------
// 10. Generic registry: malformed envelopes never panic
// ---------------------------------------------------------------------------

/// A tiny approved circuit used only by these tests.
///
/// `advice == public instance`, one 32-byte witness, one public value. The
/// layout is trivial so a k=4 keygen is cheap.
#[derive(Clone, Default)]
struct EqualityCircuit {
    value: Value<Fr>,
}

#[derive(Clone)]
struct EqualityConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
}

impl Circuit<Fr> for EqualityCircuit {
    type Config = EqualityConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> EqualityConfig {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(advice);
        meta.enable_equality(instance);
        EqualityConfig { advice, instance }
    }

    fn synthesize(
        &self,
        config: EqualityConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let cell = layouter.assign_region(
            || "equality witness",
            |mut region| {
                let cell = region.assign_advice(config.advice, 0, self.value.map(Assigned::from));
                Ok(cell)
            },
        )?;
        layouter.constrain_instance(cell.cell(), config.instance, 0);
        Ok(())
    }
}

impl ApprovedCircuit for EqualityCircuit {
    fn profile() -> CircuitProfile {
        CircuitProfile::new(HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE + 0x21, 1, 4, 8, 32, &[1])
    }

    fn from_witness(bytes: &[u8]) -> Result<Self, c_int> {
        if bytes.len() != 32 {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        Ok(Self {
            value: Value::known(decode_fr_be(bytes)?),
        })
    }
}

fn equality_id() -> u32 {
    HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE + 0x21
}

fn registry_vk_status(vk: &[u8]) -> c_int {
    registry_validate_vk::<EqualityCircuit>(vk)
}

fn registry_verify_status(vk: &[u8], proof: &[u8], instances: &[u8]) -> c_int {
    match registry_verify::<EqualityCircuit>(vk, proof, instances) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

fn equality_instances(value: u64) -> Vec<u8> {
    encode_instances_v1(&[vec![Fr::from(value)]]).expect("instances")
}

#[test]
fn registry_validate_rejects_malformed_envelopes() {
    let equality_id = equality_id();
    let valid_shape_instances = equality_instances(7);
    let cubic = Artifacts::load(CUBIC_FIXTURE);
    let poseidon2 = Artifacts::load(POSEIDON2_FIXTURE);

    // Empty / truncated.
    for len in [0usize, 1, 7, 8, 11, 12, 15, 16, 19, 20] {
        let zeros = vec![0u8; len];
        check_status(
            &format!("registry vk zero {len}"),
            registry_vk_status(&zeros),
            REGISTRY_VK_STATUSES,
        );
    }

    // Wrong magic, including V1 and a built-in circuit's V2 key.
    let v1_magic = key_header(HALO2_IPA_BN254_VK_V1_MAGIC, equality_id, 4, 10);
    assert_eq!(
        registry_vk_status(&v1_magic),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );
    check_status(
        "registry built-in cubic vk",
        registry_vk_status(&cubic.vk),
        REGISTRY_VK_STATUSES,
    );
    assert_eq!(
        registry_vk_status(&cubic.vk),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );
    check_status(
        "registry built-in poseidon2 vk",
        registry_vk_status(&poseidon2.vk),
        REGISTRY_VK_STATUSES,
    );
    assert_eq!(
        registry_vk_status(&poseidon2.vk),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );

    // Header length / circuit id / k mismatches.
    let zero_len = key_header(HALO2_IPA_BN254_VK_V2_MAGIC, equality_id, 4, 0);
    assert_eq!(registry_vk_status(&zero_len), RUSTCRYPTO_ERR_INVALID_LENGTH);
    let huge_len = key_header(
        HALO2_IPA_BN254_VK_V2_MAGIC,
        equality_id,
        4,
        HALO2_IPA_BN254_MAX_VK_LEN as u32 + 1,
    );
    assert_eq!(registry_vk_status(&huge_len), RUSTCRYPTO_ERR_INVALID_LENGTH);
    let mut wrong_id = key_header(HALO2_IPA_BN254_VK_V2_MAGIC, equality_id + 1, 4, 4);
    wrong_id.extend_from_slice(&[0u8; 4]);
    assert_eq!(
        registry_vk_status(&wrong_id),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );
    for k in [3u32, 9] {
        let mut wrong_k = key_header(HALO2_IPA_BN254_VK_V2_MAGIC, equality_id, k, 4);
        wrong_k.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            registry_vk_status(&wrong_k),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
            "registry vk k={k}"
        );
    }
    let mut short_payload = key_header(HALO2_IPA_BN254_VK_V2_MAGIC, equality_id, 4, 4);
    short_payload.extend_from_slice(&[0u8; 4]);
    check_status(
        "registry short payload",
        registry_vk_status(&short_payload),
        REGISTRY_VK_STATUSES,
    );

    // Instances: profile shape is exactly one column with one value.
    assert_eq!(
        registry_validate_instances::<EqualityCircuit>(&valid_shape_instances),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        registry_validate_instances::<EqualityCircuit>(&[]),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    let two_columns =
        encode_instances_v1(&[vec![Fr::from(1u64)], vec![Fr::from(2u64)]]).expect("instances");
    assert_eq!(
        registry_validate_instances::<EqualityCircuit>(&two_columns),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );
    let two_values =
        encode_instances_v1(&[vec![Fr::from(1u64), Fr::from(2u64)]]).expect("instances");
    assert_eq!(
        registry_validate_instances::<EqualityCircuit>(&two_values),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );
    let mut noncanonical = valid_shape_instances.clone();
    noncanonical[16..].copy_from_slice(&FR_MODULUS_BE);
    assert_eq!(
        registry_validate_instances::<EqualityCircuit>(&noncanonical),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );
    let mut trailing = valid_shape_instances.clone();
    trailing.push(0);
    assert_eq!(
        registry_validate_instances::<EqualityCircuit>(&trailing),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // Proof envelope: revision independent, same limits as the built-in ABI.
    assert_eq!(registry_validate_proof(&cubic.proof), RUSTCRYPTO_OK);
    assert_eq!(
        registry_validate_proof(&[]),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );
    assert_eq!(
        registry_validate_proof(&proof_header(0)),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );
    assert_eq!(
        registry_validate_proof(&proof_header(HALO2_IPA_BN254_MAX_PROOF_LEN as u32 + 1)),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );
    let mut trailing_proof = cubic.proof.clone();
    trailing_proof.push(0);
    assert_eq!(
        registry_validate_proof(&trailing_proof),
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
    );

    // `verify` with malformed envelopes: no keygen, only parsing.
    check_status(
        "registry verify empty",
        registry_verify_status(&[], &[], &[]),
        REGISTRY_VERIFY_STATUSES,
    );
    check_status(
        "registry verify cubic vk",
        registry_verify_status(&cubic.vk, &cubic.proof, &valid_shape_instances),
        REGISTRY_VERIFY_STATUSES,
    );
    assert_eq!(
        registry_verify_status(&cubic.vk, &cubic.proof, &valid_shape_instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );

    // Short payload after a valid V2 header is a decode error, not a panic.
    check_status(
        "registry verify short payload",
        registry_verify_status(&short_payload, &cubic.proof, &valid_shape_instances),
        REGISTRY_VERIFY_STATUSES,
    );
}

// ---------------------------------------------------------------------------
// 11. Generic registry: full small-circuit round-trip and mutations
// ---------------------------------------------------------------------------

#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[test]
fn registry_roundtrip_and_mutations() {
    let (vk, pk) = registry_prepare::<EqualityCircuit>(8).expect("equality keygen");
    assert_eq!(registry_validate_vk::<EqualityCircuit>(&vk), RUSTCRYPTO_OK);
    assert_eq!(registry_validate_pk::<EqualityCircuit>(&pk), RUSTCRYPTO_OK);
    assert_eq!(&vk[..8], HALO2_IPA_BN254_VK_V2_MAGIC);
    assert_eq!(&pk[..8], HALO2_IPA_BN254_PK_V2_MAGIC);
    assert_eq!(read_u32_be(&vk, 8), equality_id());

    let witness = encode_fr_be(Fr::from(7u64));
    let instances = equality_instances(7);
    let proof = registry_prove::<EqualityCircuit>(&pk, &witness, &instances).expect("prove");
    assert_eq!(registry_validate_proof(&proof), RUSTCRYPTO_OK);
    assert_eq!(
        registry_verify_status(&vk, &proof, &instances),
        RUSTCRYPTO_OK
    );

    // Relabelled / truncated envelopes are rejected before transcript reading.
    let mut v1_vk = vk.clone();
    v1_vk[..8].copy_from_slice(HALO2_IPA_BN254_VK_V1_MAGIC);
    assert_eq!(
        registry_verify_status(&v1_vk, &proof, &instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );

    let mut wrong_id = vk.clone();
    write_u32_be(&mut wrong_id, 8, equality_id() + 1);
    assert_eq!(
        registry_verify_status(&wrong_id, &proof, &instances),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );

    for k in [3u32, 9] {
        let mut wrong_k = vk.clone();
        write_u32_be(&mut wrong_k, 12, k);
        assert_eq!(
            registry_verify_status(&wrong_k, &proof, &instances),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
            "registry verify k={k}"
        );
    }

    for len in [0usize, 19, vk.len() - 1] {
        check_status(
            &format!("registry verify vk prefix {len}"),
            registry_verify_status(&vk[..len], &proof, &instances),
            REGISTRY_VERIFY_STATUSES,
        );
    }
    for len in [0usize, 11, proof.len() - 1] {
        let status = registry_verify_status(&vk, &proof[..len], &instances);
        check_status(
            &format!("registry verify proof prefix {len}"),
            status,
            REGISTRY_VERIFY_STATUSES,
        );
        assert_ne!(status, RUSTCRYPTO_OK);
    }
    for len in [0usize, 11, instances.len() - 1] {
        let status = registry_verify_status(&vk, &proof, &instances[..len]);
        check_status(
            &format!("registry verify instances prefix {len}"),
            status,
            REGISTRY_VERIFY_STATUSES,
        );
        assert_ne!(status, RUSTCRYPTO_OK);
    }

    // Header byte flips.
    for offset in 0..20 {
        let mut mutated = vk.clone();
        mutated[offset] ^= 0x01;
        let status = registry_verify_status(&mutated, &proof, &instances);
        check_status(
            &format!("registry verify vk header {offset}"),
            status,
            REGISTRY_VERIFY_STATUSES,
        );
        assert_ne!(status, RUSTCRYPTO_OK, "registry vk header {offset}");
    }
    for offset in 0..8 {
        let mut mutated = proof.clone();
        mutated[offset] ^= 0x01;
        assert_eq!(
            registry_validate_proof(&mutated),
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
        );
    }

    // Proof payload mutations must not verify (deterministic fixture).
    for offset in [12usize, proof.len() / 2, proof.len() - 2, proof.len() - 1] {
        let mut mutated = proof.clone();
        mutated[offset] ^= 0x01;
        let status = registry_verify_status(&vk, &mutated, &instances);
        check_status(
            &format!("registry proof payload {offset}"),
            status,
            REGISTRY_VERIFY_STATUSES,
        );
        assert_ne!(status, RUSTCRYPTO_OK, "registry proof payload {offset}");
    }

    // Wrong public value is a valid envelope but an invalid statement.
    let wrong_instances = equality_instances(8);
    let status = registry_verify_status(&vk, &proof, &wrong_instances);
    check_status("registry wrong instance", status, REGISTRY_VERIFY_STATUSES);
    assert_eq!(status, RUSTCRYPTO_ERR_VERIFICATION_FAILED);

    // `prove` rejects malformed PK / witness / instances before proving.
    fn registry_prove_status(pk: &[u8], witness: &[u8], instances: &[u8]) -> c_int {
        match registry_prove::<EqualityCircuit>(pk, witness, instances) {
            Ok(_) => RUSTCRYPTO_OK,
            Err(error) => error,
        }
    }

    let valid_prove_statuses: &[c_int] = &[
        RUSTCRYPTO_OK,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
    ];

    for len in [0usize, 19, pk.len() - 1] {
        let status = registry_prove_status(&pk[..len], &witness, &instances);
        check_status(
            &format!("registry prove pk prefix {len}"),
            status,
            valid_prove_statuses,
        );
        assert_ne!(status, RUSTCRYPTO_OK);
    }

    let mut v1_pk = pk.clone();
    v1_pk[..8].copy_from_slice(HALO2_IPA_BN254_PK_V1_MAGIC);
    assert_eq!(
        registry_prove_status(&v1_pk, &witness, &instances),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );

    let mut wrong_id_pk = pk.clone();
    write_u32_be(&mut wrong_id_pk, 8, equality_id() + 1);
    assert_eq!(
        registry_prove_status(&wrong_id_pk, &witness, &instances),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );

    for k in [3u32, 9] {
        let mut wrong_k_pk = pk.clone();
        write_u32_be(&mut wrong_k_pk, 12, k);
        assert_eq!(
            registry_prove_status(&wrong_k_pk, &witness, &instances),
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
            "registry prove k={k}"
        );
    }

    for bad_witness in [
        vec![0u8; 31],
        vec![0u8; 33],
        vec![0u8; 64],
        vec![0xffu8; 32],
    ] {
        let status = registry_prove_status(&pk, &bad_witness, &instances);
        check_status("registry prove bad witness", status, valid_prove_statuses);
        assert_ne!(status, RUSTCRYPTO_OK);
    }

    let two_values =
        encode_instances_v1(&[vec![Fr::from(7u64), Fr::from(7u64)]]).expect("instances");
    assert_eq!(
        registry_prove_status(&pk, &witness, &two_values),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );

    let mut noncanonical_instances = instances.clone();
    noncanonical_instances[16..].copy_from_slice(&FR_MODULUS_BE);
    assert_eq!(
        registry_prove_status(&pk, &witness, &noncanonical_instances),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );

    // `prepare` k bounds.
    assert_eq!(
        registry_prepare::<EqualityCircuit>(3),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    );
    assert_eq!(
        registry_prepare::<EqualityCircuit>(9),
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    );
}
