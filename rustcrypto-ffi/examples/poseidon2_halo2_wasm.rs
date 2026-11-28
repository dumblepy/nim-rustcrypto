//! Poseidon2 Halo2 custom gate / IPA prove-verify smoke for native and
//! wasm32-wasip1.
//!
//! The circuit hashes three BN254 `Fr` values with the Noir/Barretenberg
//! Poseidon2 sponge (one permutation, because 3 is a non-zero multiple of the
//! rate) and exposes `[digest, input0, input1, input2]` as public instances.
//! Every Poseidon2 round is constrained by the custom gate.
//!
//! ```text
//! cargo run --locked --release --example poseidon2_halo2_wasm
//! cargo build --locked --release --example poseidon2_halo2_wasm --target wasm32-wasip1
//! node ci/poseidon2_halo2_wasm_smoke.mjs <wasm>
//! ```
//!
//! The example prints one compact JSON object with the measured sizes, timings
//! and negative checks. The RNG seed is fixed **for this fixture only**; the
//! C ABI and production proving use `OsRng`.
//!
//! `k = 10` is intentional: proving this gate inside wasm is slow, and the
//! larger domain keeps the measurement meaningful. It is not a performance
//! optimisation.
//!
//! The process exits with status 1 when any check fails. The failure is
//! returned from `main` instead of calling `std::process::exit`, so the same
//! code path works for a wasm32-wasip1 command module.

use halo2_axiom::SerdeFormat;
use halo2_axiom::halo2curves::bn256::{Fr, G1Affine};
use halo2_axiom::halo2curves::ff::PrimeField;
use halo2_axiom::plonk::{
    Circuit, ConstraintSystem, VerifyingKey, create_proof, keygen_pk, keygen_vk, verify_proof,
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
const EXPECTED_DIGEST: &str = "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8";

/// Failure marker returned from `main`. `Debug` is printed by the standard
/// library before it exits with status 1.
struct SmokeFailure;

impl core::fmt::Debug for SmokeFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("poseidon2 halo2 wasm smoke failed")
    }
}

fn target_name() -> &'static str {
    if cfg!(target_arch = "wasm32") {
        "wasm"
    } else {
        "native"
    }
}

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
    // `panic = "abort"` turns this into a direct call in wasm; the tampered
    // proof used below is a well-formed transcript that verifies to `false`.
    matches!(catch_unwind(AssertUnwindSafe(inner)), Ok(true))
}

fn run() -> bool {
    let inputs: Vec<Fr> = (1..=INPUT_COUNT as u64).map(Fr::from).collect();
    let circuit = Poseidon2HashCircuit::new(&inputs);
    let instance = hash_public_inputs(&inputs);
    let digest = hash_output(&inputs);
    let rows = hash_circuit_rows(inputs.len());
    let digest_ok = fr_hex_be(digest) == EXPECTED_DIGEST && instance[0] == digest;

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
    let mut rng = StdRng::from_seed([0x85u8; 32]);
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
    let verified = verify_bytes(&params, &vk, &proof, &instance);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    let mut wrong_instance = instance.clone();
    wrong_instance[0] += Fr::from(1u64);
    let wrong_rejected = !verify_bytes(&params, &vk, &proof, &wrong_instance);

    let mut tampered_proof = proof.clone();
    if let Some(last) = tampered_proof.last_mut() {
        *last ^= 0x01;
    }
    let tampered_rejected = !verify_bytes(&params, &vk, &tampered_proof, &instance);

    println!(
        "{{\"target\":\"{}\",\"k\":{K},\"rows\":{rows},\"instance_rows\":{},\
         \"advice_columns\":{},\"selectors\":{},\"gate_degree\":{},\
         \"vk_bytes\":{},\"pk_bytes\":{},\"proof_bytes\":{},\
         \"keygen_ms\":{keygen_ms:.3},\"prove_ms\":{prove_ms:.3},\
         \"verify_ms\":{verify_ms:.3},\"digest\":\"{}\",\
         \"digest_ok\":{digest_ok},\"verified\":{verified},\
         \"wrong_rejected\":{wrong_rejected},\"tampered_rejected\":{tampered_rejected}}}",
        target_name(),
        instance.len(),
        cs.num_advice_columns(),
        cs.num_selectors(),
        cs.degree(),
        vk_bytes.len(),
        pk_bytes.len(),
        proof.len(),
        fr_hex_be(digest),
    );

    digest_ok && verified && wrong_rejected && tampered_rejected
}

fn main() -> Result<(), SmokeFailure> {
    if run() { Ok(()) } else { Err(SmokeFailure) }
}
