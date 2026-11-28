//! Halo2 IPA / BN254 comparison of the Poseidon1 and Poseidon2 custom gates.
//!
//! Both circuits hash the same three BN254 `Fr` values. Poseidon1 uses the
//! Circom-compatible `light-poseidon` width-4 permutation (`state =
//! [0, x0, x1, x2]`); Poseidon2 uses the Noir/Barretenberg sponge. The two
//! circuits are keyed and proved against the **same** `ParamsIPA` instance so
//! rows, artifacts, and timings are apples-to-apples for this k.
//!
//! ```text
//! cargo run --locked --release --example poseidon1_halo2_ipa
//! ```
//!
//! JSON goes to stdout and a human-readable table goes to stderr.
//!
//! Native-only: this example is not part of any wasm execution surface.
//! The RNG seed is fixed **for this fixture only**; production proving uses
//! `OsRng`. This is an unaudited comparison demo, not a production circuit.

use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
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
use light_poseidon::{Poseidon, PoseidonHasher};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rust_crypto_ffi::poseidon1_halo2::{
    Poseidon1HashCircuit, hash_circuit_rows as poseidon1_rows, hash_output as poseidon1_hash,
    hash_public_inputs as poseidon1_public_inputs,
};
use rust_crypto_ffi::poseidon2_halo2::{
    Poseidon2HashCircuit, hash_circuit_rows as poseidon2_rows, hash_output as poseidon2_hash,
    hash_public_inputs as poseidon2_public_inputs,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

const K: u32 = 10;
const INPUT_COUNT: usize = 3;

struct Measurements {
    rows: usize,
    instance_rows: usize,
    advice_columns: usize,
    selectors: usize,
    gate_degree: usize,
    vk_bytes: usize,
    pk_bytes: usize,
    proof_bytes: usize,
    keygen_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    verified: bool,
    wrong_digest_rejected: bool,
    tampered_proof_rejected: bool,
    digest: String,
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

fn halo_fr(value: ark_bn254::Fr) -> Fr {
    let bytes = value.into_bigint().to_bytes_le();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[..32]);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("BN254 scalar field")
}

fn light_poseidon_kat(inputs: &[ark_bn254::Fr; INPUT_COUNT]) -> Fr {
    let mut poseidon =
        Poseidon::<ark_bn254::Fr>::new_circom(INPUT_COUNT).expect("Poseidon1 parameters");
    halo_fr(poseidon.hash(inputs).expect("Poseidon1 hash"))
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

fn measure<C: Circuit<Fr, Params = ()>>(
    params: &ParamsIPA<G1Affine>,
    circuit: C,
    instance: Vec<Fr>,
    digest: Fr,
    rows: usize,
) -> Measurements {
    let mut cs = ConstraintSystem::<Fr>::default();
    let _ = C::configure(&mut cs);

    // ---- keygen ---------------------------------------------------------
    let keygen_start = Instant::now();
    let keygen_circuit = circuit.without_witnesses();
    let vk = keygen_vk(params, &keygen_circuit).expect("keygen_vk");
    let pk = keygen_pk(params, vk.clone(), &keygen_circuit).expect("keygen_pk");
    let keygen_ms = keygen_start.elapsed().as_secs_f64() * 1000.0;

    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::Processed)
        .expect("serialize vk");
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::Processed)
        .expect("serialize pk");

    // ---- prove (deterministic test-only RNG) ----------------------------
    let mut rng = StdRng::from_seed([85u8; 32]);
    let instance_columns: [&[Fr]; 1] = [&instance];
    let instances: [&[&[Fr]]; 1] = [&instance_columns];
    let prove_start = Instant::now();
    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<IPACommitmentScheme<G1Affine>, ProverIPA<_>, _, _, _, _>(
        params,
        &pk,
        &[circuit],
        &instances,
        &mut rng,
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    // ---- verify ---------------------------------------------------------
    let verify_start = Instant::now();
    let verified = verify_bytes(params, &vk, &proof, &instance);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    let mut wrong_instance = instance.clone();
    wrong_instance[0] += Fr::from(1u64);
    let wrong_digest_rejected = !verify_bytes(params, &vk, &proof, &wrong_instance);

    let mut tampered_proof = proof.clone();
    let last = tampered_proof.len() - 1;
    tampered_proof[last] ^= 0x01;
    let tampered_proof_rejected = !verify_bytes(params, &vk, &tampered_proof, &instance);

    // PK round-trip through the same serialization the C ABI uses.
    let mut pk_cursor = pk_bytes.as_slice();
    let _pk_roundtrip =
        ProvingKey::<G1Affine>::read::<_, C>(&mut pk_cursor, SerdeFormat::Processed, ())
            .expect("pk round-trip");
    assert!(pk_cursor.is_empty(), "pk trailing bytes");

    Measurements {
        rows,
        instance_rows: instance.len(),
        advice_columns: cs.num_advice_columns(),
        selectors: cs.num_selectors(),
        gate_degree: cs.degree(),
        vk_bytes: vk_bytes.len(),
        pk_bytes: pk_bytes.len(),
        proof_bytes: proof.len(),
        keygen_ms,
        prove_ms,
        verify_ms,
        verified,
        wrong_digest_rejected,
        tampered_proof_rejected,
        digest: fr_hex_be(digest),
    }
}

fn print_measurements(name: &str, measurements: &Measurements, last: bool) {
    println!("  \"{name}\": {{");
    println!("    \"rows\": {},", measurements.rows);
    println!("    \"instance_rows\": {},", measurements.instance_rows);
    println!("    \"advice_columns\": {},", measurements.advice_columns);
    println!("    \"selectors\": {},", measurements.selectors);
    println!("    \"gate_degree\": {},", measurements.gate_degree);
    println!("    \"vk_bytes\": {},", measurements.vk_bytes);
    println!("    \"pk_bytes\": {},", measurements.pk_bytes);
    println!("    \"proof_bytes\": {},", measurements.proof_bytes);
    println!("    \"keygen_ms\": {:.3},", measurements.keygen_ms);
    println!("    \"prove_ms\": {:.3},", measurements.prove_ms);
    println!("    \"verify_ms\": {:.3},", measurements.verify_ms);
    println!("    \"verified\": {},", measurements.verified);
    println!(
        "    \"wrong_digest_rejected\": {},",
        measurements.wrong_digest_rejected
    );
    println!(
        "    \"tampered_proof_rejected\": {},",
        measurements.tampered_proof_rejected
    );
    println!("    \"digest\": \"{}\"", measurements.digest);
    if last {
        println!("  }}");
    } else {
        println!("  }},");
    }
}

fn main() {
    let inputs: [Fr; INPUT_COUNT] = core::array::from_fn(|index| Fr::from((index + 1) as u64));

    let poseidon1_digest = poseidon1_hash(&inputs);
    let poseidon2_digest = poseidon2_hash(&inputs);
    let poseidon1_instance = poseidon1_public_inputs(&inputs);
    let poseidon2_instance = poseidon2_public_inputs(&inputs);
    assert_eq!(poseidon1_instance[0], poseidon1_digest);
    assert_eq!(poseidon2_instance[0], poseidon2_digest);

    let ark_inputs: [ark_bn254::Fr; INPUT_COUNT] =
        inputs.map(|value| ark_bn254::Fr::from_le_bytes_mod_order(value.to_repr().as_ref()));
    let light_poseidon_digest = light_poseidon_kat(&ark_inputs);

    // ---- shared params --------------------------------------------------
    let params_start = Instant::now();
    let params = ParamsIPA::<G1Affine>::new(K);
    let params_ms = params_start.elapsed().as_secs_f64() * 1000.0;

    let poseidon1 = measure(
        &params,
        Poseidon1HashCircuit::new(&inputs),
        poseidon1_instance,
        poseidon1_digest,
        poseidon1_rows(),
    );
    let poseidon2 = measure(
        &params,
        Poseidon2HashCircuit::new(&inputs),
        poseidon2_instance,
        poseidon2_digest,
        poseidon2_rows(inputs.len()),
    );

    println!("{{");
    println!("  \"k\": {K},");
    println!("  \"input_count\": {INPUT_COUNT},");
    println!("  \"shared_params\": true,");
    println!("  \"params_ms\": {params_ms:.3},");
    println!("  \"proof_rng\": \"StdRng([85; 32]) fixture only\",");
    println!("  \"verification_strategy\": \"SingleStrategy\",");
    print_measurements("poseidon1", &poseidon1, false);
    print_measurements("poseidon2", &poseidon2, false);
    println!(
        "  \"light_poseidon_kat\": \"{}\",",
        fr_hex_be(light_poseidon_digest)
    );
    println!(
        "  \"light_poseidon_matches\": {}",
        light_poseidon_digest == poseidon1_digest
    );
    println!("}}");

    // ---- human table ----------------------------------------------------
    eprintln!("Poseidon1 vs Poseidon2 Halo2 IPA / BN254 (inputs [1,2,3], k={K})");
    eprintln!(
        "{:<10} {:>5} {:>5} {:>5} {:>7} {:>10} {:>10} {:>8} {:>10} {:>9} {:>9}",
        "circuit",
        "rows",
        "inst",
        "adv",
        "sel",
        "vk_bytes",
        "pk_bytes",
        "proof",
        "keygen_ms",
        "prove_ms",
        "verify_ms"
    );
    for (name, measurements) in [("Poseidon1", &poseidon1), ("Poseidon2", &poseidon2)] {
        eprintln!(
            "{:<10} {:>5} {:>5} {:>5} {:>7} {:>10} {:>10} {:>8} {:>10.3} {:>9.3} {:>9.3}",
            name,
            measurements.rows,
            measurements.instance_rows,
            measurements.advice_columns,
            measurements.selectors,
            measurements.vk_bytes,
            measurements.pk_bytes,
            measurements.proof_bytes,
            measurements.keygen_ms,
            measurements.prove_ms,
            measurements.verify_ms
        );
    }
    eprintln!(
        "verified p1={} p2={}; wrong digest rejected p1={} p2={}; tampered proof rejected p1={} p2={}",
        poseidon1.verified,
        poseidon2.verified,
        poseidon1.wrong_digest_rejected,
        poseidon2.wrong_digest_rejected,
        poseidon1.tampered_proof_rejected,
        poseidon2.tampered_proof_rejected
    );
    eprintln!(
        "Poseidon1 digest = {} (light-poseidon match = {})",
        poseidon1.digest,
        light_poseidon_digest == poseidon1_digest
    );
    eprintln!("Poseidon2 digest = {}", poseidon2.digest);
}
