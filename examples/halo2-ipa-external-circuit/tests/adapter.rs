//! End-to-end tests for the compile-time external-circuit adapter.
//!
//! Everything here goes through the macro-generated C ABI functions (the same
//! code a static library consumer or wasm module would call).

use core::ffi::c_int;
use halo2_axiom::dev::MockProver;
use halo2_axiom::halo2curves::bn256::Fr;
use halo2_ipa_external_circuit::{
    CHAIN_CIRCUIT_ID, ChainCircuit, INSTANCE_VALUES, LINEAR_CIRCUIT_ID, LinearCircuit,
    WITNESS_VALUES, chain_adapter, chain_public_values, linear_adapter, linear_public_values,
    linear_verifier,
};
use rust_crypto_ffi::halo2_ipa::{encode_fr_be, encode_instances_v1};
use rust_crypto_ffi::halo2_ipa_registry::{params_digest, vk_digest};
use rust_crypto_ffi::{
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_PANIC,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
};
use std::sync::OnceLock;

type PrepareFn = extern "C" fn(
    u32,
    *mut u8,
    usize,
    *mut usize,
    *mut u8,
    usize,
    *mut usize,
) -> c_int;
type ProveFn = extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> c_int;
type VerifyFn = extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> c_int;
type ValidateFn = extern "C" fn(*const u8, usize) -> c_int;

const K: u32 = 8;

fn inputs() -> [Fr; WITNESS_VALUES] {
    core::array::from_fn(|index| Fr::from(index as u64 + 1))
}

fn witness_bytes(inputs: &[Fr; WITNESS_VALUES]) -> Vec<u8> {
    inputs
        .iter()
        .flat_map(|value| encode_fr_be(*value))
        .collect()
}

fn instances_bytes(public: &[Fr]) -> Vec<u8> {
    assert_eq!(public.len(), INSTANCE_VALUES);
    encode_instances_v1(&[public.to_vec()]).expect("instances")
}

fn prepare_with(prepare: PrepareFn) -> (Vec<u8>, Vec<u8>) {
    // Two-call sizing convention: a null-output call reports the lengths.
    let mut vk_len = 0usize;
    let mut pk_len = 0usize;
    assert_eq!(
        prepare(
            K,
            core::ptr::null_mut(),
            0,
            &mut vk_len,
            core::ptr::null_mut(),
            0,
            &mut pk_len,
        ),
        RUSTCRYPTO_ERR_NULL_OUTPUT
    );
    assert!(vk_len > 0 && pk_len > 0);

    let mut vk = vec![0u8; vk_len];
    let mut pk = vec![0u8; pk_len];
    let mut vk_len2 = 0usize;
    let mut pk_len2 = 0usize;
    assert_eq!(
        prepare(
            K,
            vk.as_mut_ptr(),
            vk.len(),
            &mut vk_len2,
            pk.as_mut_ptr(),
            pk.len(),
            &mut pk_len2,
        ),
        RUSTCRYPTO_OK
    );
    assert_eq!(vk_len2, vk_len);
    assert_eq!(pk_len2, pk_len);
    vk.truncate(vk_len2);
    pk.truncate(pk_len2);
    (vk, pk)
}

fn prove_with(prove: ProveFn, pk: &[u8], witness: &[u8], instances: &[u8]) -> Vec<u8> {
    let mut required = 0usize;
    assert_eq!(
        prove(
            pk.as_ptr(),
            pk.len(),
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            core::ptr::null_mut(),
            0,
            &mut required,
        ),
        RUSTCRYPTO_ERR_NULL_OUTPUT
    );
    assert!(required > 0);

    let mut proof = vec![0u8; required];
    let mut written = 0usize;
    assert_eq!(
        prove(
            pk.as_ptr(),
            pk.len(),
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            proof.as_mut_ptr(),
            proof.len(),
            &mut written,
        ),
        RUSTCRYPTO_OK
    );
    assert_eq!(written, required);
    proof.truncate(written);
    proof
}

fn verify_with(verify: VerifyFn, vk: &[u8], proof: &[u8], instances: &[u8]) -> c_int {
    verify(
        vk.as_ptr(),
        vk.len(),
        proof.as_ptr(),
        proof.len(),
        instances.as_ptr(),
        instances.len(),
    )
}

fn chain_keys() -> &'static (Vec<u8>, Vec<u8>) {
    static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEYS.get_or_init(|| prepare_with(chain_adapter::prepare))
}

fn linear_keys() -> &'static (Vec<u8>, Vec<u8>) {
    static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEYS.get_or_init(|| prepare_with(linear_adapter::prepare))
}

fn chain_statement() -> (Vec<u8>, Vec<u8>) {
    let inputs = inputs();
    (
        witness_bytes(&inputs),
        instances_bytes(&chain_public_values(&inputs)),
    )
}

/// `k` used by the mock-prover soundness tests (the profile minimum).
const MOCK_K: u32 = 6;

/// Builds the public column from an explicit accumulator chain. This lets the
/// malicious-witness tests publish the chain the prover actually assigned,
/// isolating the `acc_0 == input_0` binding as the only violated constraint.
fn public_from_accumulators(
    inputs: &[Fr; WITNESS_VALUES],
    accumulators: &[Fr; WITNESS_VALUES],
) -> Vec<Fr> {
    let mut public = Vec::with_capacity(INSTANCE_VALUES);
    public.extend_from_slice(&accumulators[1..WITNESS_VALUES]);
    public.push(inputs[0]);
    public.push(inputs[WITNESS_VALUES - 1]);
    public
}

fn chain_malicious_accumulators(inputs: &[Fr; WITNESS_VALUES]) -> [Fr; WITNESS_VALUES] {
    let mut accumulators = [Fr::from(0u64); WITNESS_VALUES];
    // The old exploit: public input_0 = 1 but start the accumulator at 7.
    accumulators[0] = Fr::from(7u64);
    for index in 1..WITNESS_VALUES {
        accumulators[index] =
            accumulators[index - 1] * accumulators[index - 1] + inputs[index];
    }
    accumulators
}

fn linear_malicious_accumulators(inputs: &[Fr; WITNESS_VALUES]) -> [Fr; WITNESS_VALUES] {
    let mut accumulators = [Fr::from(0u64); WITNESS_VALUES];
    // The old exploit: public input_0 = 1 but start the accumulator at 7.
    accumulators[0] = Fr::from(7u64);
    for index in 1..WITNESS_VALUES {
        accumulators[index] = accumulators[index - 1] + inputs[index];
    }
    accumulators
}

#[test]
fn honest_witnesses_satisfy_the_constraints() {
    let inputs = inputs();

    let chain = ChainCircuit::new(&inputs);
    let chain_prover =
        MockProver::run(MOCK_K, &chain, vec![chain_public_values(&inputs)]).expect("mock prover");
    chain_prover.assert_satisfied();

    let linear = LinearCircuit::new(&inputs);
    let linear_prover = MockProver::run(MOCK_K, &linear, vec![linear_public_values(&inputs)])
        .expect("mock prover");
    linear_prover.assert_satisfied();
}

#[test]
fn old_malicious_initial_accumulator_is_rejected() {
    let inputs = inputs();

    let chain_accumulators = chain_malicious_accumulators(&inputs);
    assert_eq!(inputs[0], Fr::from(1u64));
    assert_eq!(chain_accumulators[0], Fr::from(7u64));
    let chain = ChainCircuit::from_witness_parts(&inputs, &chain_accumulators);
    let chain_instance = public_from_accumulators(&inputs, &chain_accumulators);
    let chain_prover =
        MockProver::run(MOCK_K, &chain, vec![chain_instance]).expect("mock prover");
    assert!(
        chain_prover.verify().is_err(),
        "ChainCircuit accepted acc_0 = 7 while publishing input_0 = 1"
    );

    let linear_accumulators = linear_malicious_accumulators(&inputs);
    let linear = LinearCircuit::from_witness_parts(&inputs, &linear_accumulators);
    let linear_instance = public_from_accumulators(&inputs, &linear_accumulators);
    let linear_prover =
        MockProver::run(MOCK_K, &linear, vec![linear_instance]).expect("mock prover");
    assert!(
        linear_prover.verify().is_err(),
        "LinearCircuit accepted acc_0 = 7 while publishing input_0 = 1"
    );
}

#[test]
fn changing_only_the_public_input_zero_is_rejected() {
    let inputs = inputs();

    let mut chain_instance = chain_public_values(&inputs);
    chain_instance[WITNESS_VALUES - 1] += Fr::from(1u64);
    let chain_prover = MockProver::run(MOCK_K, &ChainCircuit::new(&inputs), vec![chain_instance])
        .expect("mock prover");
    assert!(
        chain_prover.verify().is_err(),
        "ChainCircuit accepted a changed public input_0"
    );

    let mut linear_instance = linear_public_values(&inputs);
    linear_instance[WITNESS_VALUES - 1] += Fr::from(1u64);
    let linear_prover = MockProver::run(MOCK_K, &LinearCircuit::new(&inputs), vec![linear_instance])
        .expect("mock prover");
    assert!(
        linear_prover.verify().is_err(),
        "LinearCircuit accepted a changed public input_0"
    );
}

#[test]
fn prepare_prove_verify_roundtrip_with_seventeen_public_values() {
    let (vk, pk) = chain_keys();
    assert_eq!(&vk[..8], b"RCH2IPV2");
    assert_eq!(&pk[..8], b"RCH2IPP2");
    assert_eq!(chain_adapter::vk_validate(vk.as_ptr(), vk.len()), RUSTCRYPTO_OK);
    assert_eq!(chain_adapter::pk_validate(pk.as_ptr(), pk.len()), RUSTCRYPTO_OK);

    let (witness, instances) = chain_statement();
    // 12-byte header + 4-byte value count + 17 * 32-byte Fr.
    assert_eq!(instances.len(), 12 + 4 + INSTANCE_VALUES * 32);

    let proof = prove_with(chain_adapter::prove, pk, &witness, &instances);
    assert_eq!(
        chain_adapter::proof_validate(proof.as_ptr(), proof.len()),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        chain_adapter::instances_validate(instances.as_ptr(), instances.len()),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        verify_with(chain_adapter::verify, vk, &proof, &instances),
        RUSTCRYPTO_OK
    );
    // Side-effect free.
    assert_eq!(
        verify_with(chain_adapter::verify, vk, &proof, &instances),
        RUSTCRYPTO_OK
    );
}

#[test]
fn wrong_expected_public_instances_are_rejected() {
    let (vk, pk) = chain_keys();
    let (witness, instances) = chain_statement();
    let proof = prove_with(chain_adapter::prove, pk, &witness, &instances);

    // The last value is w_15; flipping one bit keeps it canonical Fr.
    let mut wrong = instances.clone();
    let last = wrong.len() - 1;
    wrong[last] ^= 1;
    assert_eq!(
        chain_adapter::instances_validate(wrong.as_ptr(), wrong.len()),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        verify_with(chain_adapter::verify, vk, &proof, &wrong),
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    );
}

#[test]
fn tampered_proof_and_v1_relabelled_key_are_rejected() {
    let (vk, pk) = chain_keys();
    let (witness, instances) = chain_statement();
    let proof = prove_with(chain_adapter::prove, pk, &witness, &instances);

    let mut tampered = proof.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let status = verify_with(chain_adapter::verify, vk, &tampered, &instances);
    assert_ne!(status, RUSTCRYPTO_OK);
    assert_ne!(status, RUSTCRYPTO_ERR_PANIC);

    // Old V1-magic keys are not accepted as the sound V2 circuit.
    let mut v1_vk = vk.clone();
    v1_vk[..8].copy_from_slice(b"RCH2IPV1");
    assert_eq!(
        chain_adapter::vk_validate(v1_vk.as_ptr(), v1_vk.len()),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );
    assert_eq!(
        verify_with(chain_adapter::verify, &v1_vk, &proof, &instances),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );

    let mut v1_pk = pk.clone();
    v1_pk[..8].copy_from_slice(b"RCH2IPP1");
    assert_eq!(
        chain_adapter::pk_validate(v1_pk.as_ptr(), v1_pk.len()),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );
}

#[test]
fn wrong_circuit_id_and_wrong_circuit_key_are_rejected() {
    let (vk, pk) = chain_keys();
    let (witness, instances) = chain_statement();
    let proof = prove_with(chain_adapter::prove, pk, &witness, &instances);

    let mut wrong_id = vk.clone();
    wrong_id[8..12].copy_from_slice(&(CHAIN_CIRCUIT_ID + 1).to_be_bytes());
    assert_eq!(
        chain_adapter::vk_validate(wrong_id.as_ptr(), wrong_id.len()),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );
    assert_eq!(
        verify_with(chain_adapter::verify, &wrong_id, &proof, &instances),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );

    // A VK for a different registered circuit is rejected by id at the
    // profile check, and cannot verify this proof even through its own adapter.
    let (linear_vk, _) = linear_keys();
    assert_eq!(
        verify_with(chain_adapter::verify, linear_vk, &proof, &instances),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );
    assert_eq!(
        verify_with(linear_verifier::verify, linear_vk, &proof, &instances),
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    );

    // Also build linear-shaped instances to show the transcript itself does
    // not verify under the other circuit's VK.
    let linear_inputs = inputs();
    let linear_instances = instances_bytes(&linear_public_values(&linear_inputs));
    assert_eq!(
        verify_with(
            linear_verifier::verify,
            linear_vk,
            &proof,
            &linear_instances
        ),
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    );
}

#[test]
fn invalid_witness_and_instance_encodings_are_rejected() {
    let (vk, pk) = chain_keys();
    let (witness, instances) = chain_statement();

    // Non-canonical witness field element.
    let mut noncanonical_witness = witness.clone();
    noncanonical_witness[..32].fill(0xff);
    let mut out = vec![0u8; 4096];
    let mut out_len = 0usize;
    assert_eq!(
        chain_adapter::prove(
            pk.as_ptr(),
            pk.len(),
            noncanonical_witness.as_ptr(),
            noncanonical_witness.len(),
            instances.as_ptr(),
            instances.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        ),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );

    // Trailing witness byte.
    let mut trailing_witness = witness.clone();
    trailing_witness.push(0);
    assert_eq!(
        chain_adapter::prove(
            pk.as_ptr(),
            pk.len(),
            trailing_witness.as_ptr(),
            trailing_witness.len(),
            instances.as_ptr(),
            instances.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // Oversized witness length is rejected by the bounded reader.
    assert_eq!(
        chain_adapter::prove(
            pk.as_ptr(),
            pk.len(),
            witness.as_ptr(),
            witness.len() * 2,
            instances.as_ptr(),
            instances.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // Non-canonical public instance.
    let mut noncanonical_instances = instances.clone();
    let last_value = noncanonical_instances.len() - 32;
    noncanonical_instances[last_value..].fill(0xff);
    assert_eq!(
        chain_adapter::instances_validate(
            noncanonical_instances.as_ptr(),
            noncanonical_instances.len()
        ),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );
    assert_eq!(
        chain_adapter::verify(
            vk.as_ptr(),
            vk.len(),
            instances.as_ptr(),
            instances.len(),
            noncanonical_instances.as_ptr(),
            noncanonical_instances.len(),
        ),
        RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
    );

    // Trailing instance byte.
    let mut trailing_instances = instances.clone();
    trailing_instances.push(0);
    assert_eq!(
        chain_adapter::instances_validate(
            trailing_instances.as_ptr(),
            trailing_instances.len()
        ),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // Wrong value count (16 instead of 17).
    let short_instances =
        encode_instances_v1(&[vec![Fr::from(1u64); INSTANCE_VALUES - 1]]).expect("instances");
    assert_eq!(
        chain_adapter::instances_validate(short_instances.as_ptr(), short_instances.len()),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );

    // Wrong column count (two columns instead of one).
    let extra_column = encode_instances_v1(&[
        vec![Fr::from(1u64); INSTANCE_VALUES],
        vec![Fr::from(2u64)],
    ])
    .expect("instances");
    assert_eq!(
        chain_adapter::instances_validate(extra_column.as_ptr(), extra_column.len()),
        RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
    );
}

#[test]
fn vk_digest_pinning_is_stable_and_deterministic() {
    let (vk, _) = chain_keys();
    let digest = vk_digest(vk);
    assert_eq!(digest, vk_digest(vk));
    assert_eq!(digest, key_digest_alias(vk));

    // A fresh prepare is deterministic for the same circuit and k.
    let (vk_again, _) = prepare_with(chain_adapter::prepare);
    assert_eq!(vk, &vk_again);
    assert_eq!(digest, vk_digest(&vk_again));

    // Pinning detects a modified VK.
    let mut tampered = vk.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_ne!(digest, vk_digest(&tampered));

    // Params are derived from k alone; the digest binds k.
    assert_eq!(params_digest(K), params_digest(K));
    assert_ne!(params_digest(K), params_digest(K + 1));
}

fn key_digest_alias(bytes: &[u8]) -> [u8; 32] {
    rust_crypto_ffi::halo2_ipa_registry::key_digest(bytes)
}

#[test]
fn verifier_only_adapter_accepts_a_matching_proof() {
    let (linear_vk, linear_pk) = linear_keys();
    let inputs = inputs();
    let witness = witness_bytes(&inputs);
    let instances = instances_bytes(&linear_public_values(&inputs));
    let proof = prove_with(linear_adapter::prove, linear_pk, &witness, &instances);

    assert_eq!(LINEAR_CIRCUIT_ID, linear_vk[8..12]
        .try_into()
        .map(u32::from_be_bytes)
        .unwrap());
    assert_eq!(
        linear_verifier::vk_validate(linear_vk.as_ptr(), linear_vk.len()),
        RUSTCRYPTO_OK
    );
    assert_eq!(
        verify_with(linear_verifier::verify, linear_vk, &proof, &instances),
        RUSTCRYPTO_OK
    );

    // A proof generated for the square-add circuit must not verify here.
    let (chain_vk, chain_pk) = chain_keys();
    let (chain_witness, chain_instances) = chain_statement();
    let chain_proof = prove_with(chain_adapter::prove, chain_pk, &chain_witness, &chain_instances);
    assert_eq!(
        verify_with(linear_verifier::verify, linear_vk, &chain_proof, &instances),
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    );
    assert_eq!(
        verify_with(chain_adapter::verify, chain_vk, &chain_proof, &chain_instances),
        RUSTCRYPTO_OK
    );
}

#[test]
fn prepare_and_prove_reject_bad_load_parameters() {
    // k below the profile minimum.
    let mut vk_len = 0usize;
    let mut pk_len = 0usize;
    assert_eq!(
        chain_adapter::prepare(
            4,
            core::ptr::null_mut(),
            0,
            &mut vk_len,
            core::ptr::null_mut(),
            0,
            &mut pk_len,
        ),
        rust_crypto_ffi::RUSTCRYPTO_ERR_INVALID_PARAMETER
    );

    let (_, pk) = chain_keys();
    let (witness, instances) = chain_statement();

    // Null length pointer.
    assert_eq!(
        chain_adapter::prove(
            pk.as_ptr(),
            pk.len(),
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        ),
        RUSTCRYPTO_ERR_NULL_OUTPUT
    );

    // Null making/verifying key pointer with a non-zero length.
    assert_eq!(
        chain_adapter::prove(
            core::ptr::null(),
            10,
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            core::ptr::null_mut(),
            0,
            &mut 0usize,
        ),
        rust_crypto_ffi::RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
    );

    // Wrong (V1) PK magic is rejected.
    let mut v1_pk = pk.clone();
    v1_pk[..8].copy_from_slice(b"RCH2IPP1");
    assert_eq!(
        chain_adapter::prove(
            v1_pk.as_ptr(),
            v1_pk.len(),
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            core::ptr::null_mut(),
            0,
            &mut 0usize,
        ),
        RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
    );
}

#[test]
fn validate_symbols_reject_truncated_and_trailing_keys() {
    let (vk, pk) = chain_keys();
    let vk_validate: ValidateFn = chain_adapter::vk_validate;
    let pk_validate: ValidateFn = chain_adapter::pk_validate;

    let mut truncated_vk = vk.clone();
    truncated_vk.pop();
    assert_eq!(
        vk_validate(truncated_vk.as_ptr(), truncated_vk.len()),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    let mut trailing_vk = vk.clone();
    trailing_vk.push(0);
    assert_eq!(
        vk_validate(trailing_vk.as_ptr(), trailing_vk.len()),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    let mut truncated_pk = pk.clone();
    truncated_pk.pop();
    assert_eq!(
        pk_validate(truncated_pk.as_ptr(), truncated_pk.len()),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );
    let mut trailing_pk = pk.clone();
    trailing_pk.push(0);
    assert_eq!(
        pk_validate(trailing_pk.as_ptr(), trailing_pk.len()),
        RUSTCRYPTO_ERR_INVALID_LENGTH
    );

    // Unknown magic and unknown external circuit id.
    let mut kzg_vk = vk.clone();
    kzg_vk[..8].copy_from_slice(b"RCH2V1\0\0");
    assert_eq!(
        vk_validate(kzg_vk.as_ptr(), kzg_vk.len()),
        RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
    );
}
