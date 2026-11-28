//! Halo2 IPA / BN254 demo for the Poseidon2 custom gate.
//!
//! The circuit hashes three BN254 `Fr` values with the Poseidon2
//! Noir/Barretenberg sponge (one permutation, because 3 is a non-zero multiple
//! of the rate) and exposes `[digest, input0, input1, input2]` as public
//! instances.
//!
//! ```text
//! cargo run --locked --release --example poseidon2_halo2_ipa
//! ```
//!
//! Output is a JSON object with the measured layout, artifact sizes, timings
//! and negative checks. The RNG seed is fixed **for this fixture only**; the
//! C ABI and production proving use `OsRng`.
//!
//! Native-only: this example is not part of the wasm execution surface for the
//! Poseidon2 gate.

use halo2_axiom::SerdeFormat;
use halo2_axiom::halo2curves::bn256::{Fr, G1Affine};
use halo2_axiom::halo2curves::ff::PrimeField;
use halo2_axiom::plonk::{
    Circuit, ConstraintSystem, ProvingKey, VerifyingKey, create_proof, keygen_pk, keygen_vk,
    verify_proof,
};
use halo2_axiom::poly::VerificationStrategy;
use halo2_axiom::poly::commitment::ParamsProver;
use halo2_axiom::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_axiom::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
use halo2_axiom::poly::ipa::strategy::SingleStrategy;
use halo2_axiom::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rust_crypto_ffi::poseidon2_halo2::{
    Poseidon2HashCircuit, hash_circuit_rows, hash_output, hash_public_inputs,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

const K: u32 = 10;
const INPUT_COUNT: usize = 3;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn fr_hex_be(value: Fr) -> String {
    let mut le = value.to_repr().as_ref().to_vec();
    le.reverse();
    hex(&le)
}

fn verify_bytes(
    params: &ParamsIPA<G1Affine>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    instance: &[Fr],
) -> bool {
    let inner = || {
        let verifier_params = params.verifier_params();
        let columns: [&[Fr]; 1] = [instance];
        let instances: [&[&[Fr]]; 1] = [&columns];
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(proof);
        verify_proof::<IPACommitmentScheme<G1Affine>, VerifierIPA<_>, _, _, SingleStrategy<_>>(
            verifier_params,
            vk,
            SingleStrategy::new(verifier_params),
            &instances,
            &mut transcript,
        )
        .is_ok()
    };
    matches!(catch_unwind(AssertUnwindSafe(inner)), Ok(true))
}

fn main() {
    let inputs: Vec<Fr> = (1..=INPUT_COUNT as u64).map(Fr::from).collect();
    assert_eq!(inputs.len(), INPUT_COUNT, "one full sponge block");
    let circuit = Poseidon2HashCircuit::new(&inputs);
    let instance = hash_public_inputs(&inputs);
    let digest = hash_output(&inputs);
    assert_eq!(instance[0], digest, "public digest drift");
    let rows = hash_circuit_rows(inputs.len());
    let instance_rows = instance.len();
    let mut cs = ConstraintSystem::<Fr>::default();
    let _ = Poseidon2HashCircuit::configure(&mut cs);

    // ---- keygen ---------------------------------------------------------
    let keygen_start = Instant::now();
    let params = ParamsIPA::<G1Affine>::new(K);
    let keygen_circuit = circuit.without_witnesses();
    let vk = keygen_vk(&params, &keygen_circuit).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &keygen_circuit).expect("keygen_pk");
    let keygen_ms = keygen_start.elapsed().as_secs_f64() * 1000.0;

    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::Processed)
        .expect("serialize vk");
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::Processed)
        .expect("serialize pk");

    // ---- prove (deterministic test-only RNG) ----------------------------
    let mut rng = StdRng::from_seed([42u8; 32]);
    let instance_columns: [&[Fr]; 1] = [&instance];
    let instances: [&[&[Fr]]; 1] = [&instance_columns];
    let prove_start = Instant::now();
    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<IPACommitmentScheme<G1Affine>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit.clone()],
        &instances,
        &mut rng,
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    // ---- verify ---------------------------------------------------------
    let verify_start = Instant::now();
    let proof_verified = verify_bytes(&params, &vk, &proof, &instance);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    let mut wrong_instance = instance.clone();
    wrong_instance[0] += Fr::from(1u64);
    let wrong_digest_rejected = !verify_bytes(&params, &vk, &proof, &wrong_instance);

    let mut tampered_proof = proof.clone();
    let last = tampered_proof.len() - 1;
    tampered_proof[last] ^= 0x01;
    let tampered_proof_rejected = !verify_bytes(&params, &vk, &tampered_proof, &instance);

    // `PK` is only used to demonstrate that the artifact round-trips through
    // the same serialization the C ABI uses.
    let mut pk_cursor = pk_bytes.as_slice();
    let _pk_roundtrip = ProvingKey::<G1Affine>::read::<_, Poseidon2HashCircuit>(
        &mut pk_cursor,
        SerdeFormat::Processed,
        (),
    )
    .expect("pk round-trip");
    assert!(pk_cursor.is_empty(), "pk trailing bytes");

    println!("{{");
    println!("  \"k\": {K},");
    println!("  \"rows\": {rows},");
    println!("  \"instance_rows\": {instance_rows},");
    println!("  \"advice_columns\": {},", cs.num_advice_columns());
    println!("  \"selectors\": {},", cs.num_selectors());
    println!("  \"gate_degree\": {},", cs.degree());
    println!("  \"vk_bytes\": {},", vk_bytes.len());
    println!("  \"pk_bytes\": {},", pk_bytes.len());
    println!("  \"proof_bytes\": {},", proof.len());
    println!("  \"keygen_ms\": {keygen_ms:.3},");
    println!("  \"prove_ms\": {prove_ms:.3},");
    println!("  \"verify_ms\": {verify_ms:.3},");
    println!("  \"digest\": \"{}\",", fr_hex_be(digest));
    println!("  \"proof_verified\": {proof_verified},");
    println!("  \"wrong_digest_rejected\": {wrong_digest_rejected},");
    println!("  \"tampered_proof_rejected\": {tampered_proof_rejected}");
    println!("}}");
}
