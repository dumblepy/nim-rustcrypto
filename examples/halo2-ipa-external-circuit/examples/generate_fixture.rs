//! Deterministic fixture generator for the external `ChainCircuit` (id 0x10001).
//!
//! Usage:
//! ```text
//! cargo run --release --example generate_fixture --manifest-path \
//!   examples/halo2-ipa-external-circuit/Cargo.toml [output.hex] [k]
//! ```
//!
//! Without arguments the fixture is written to
//! `tests/fixtures/halo2_ipa_external_chain_v1.hex` and the profile minimum
//! `k = 6` is used. The witness is the canonical BE `Fr` encoding of the
//! private inputs `1..=16`; the public instance column is the 17 values
//! `[acc_1, .., acc_15, input_0, input_15]` computed by
//! `chain_public_values`.
//!
//! The RNG seed is fixed for this fixture only (never use a fixed seed in a
//! production prover). Note that the vendored `halo2-axiom` fork samples part
//! of the vanishing argument from `rand::thread_rng()` internally, so the
//! `PROOF` line is not byte-identical across runs even with a seeded
//! `prove_with_rng`; `VK`, `PK`, `INSTANCES`, and `WITNESS` are reproducible
//! for a fixed `k`. Every generated file is self-checked with `verify` before
//! it is written.

use halo2_axiom::halo2curves::bn256::Fr;
use halo2_ipa_external_circuit::{
    CHAIN_CIRCUIT_ID, CHAIN_CIRCUIT_VERSION, ChainCircuit, INSTANCE_VALUES, WITNESS_VALUES,
    chain_public_values,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rust_crypto_ffi::halo2_ipa::{encode_fr_be, encode_instances_v1};
use rust_crypto_ffi::halo2_ipa_registry::{
    ApprovedCircuit, params_digest, prepare, prove_with_rng, verify, vk_digest,
};

/// Fixed, test-only seed. Never use a fixed seed outside fixtures/tests.
const FIXTURE_SEED: [u8; 32] = [0x87u8; 32];
const DEFAULT_K: u32 = 6;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn inputs() -> [Fr; WITNESS_VALUES] {
    core::array::from_fn(|index| Fr::from(index as u64 + 1))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let output_arg = args.next();
    let k_arg = args.next();
    if args.next().is_some() {
        eprintln!(
            "usage: generate_fixture [output.hex] [k >= {}]",
            ChainCircuit::profile().min_k
        );
        std::process::exit(2);
    }

    let profile = ChainCircuit::profile();
    assert_eq!(profile.circuit_id, CHAIN_CIRCUIT_ID);
    assert_eq!(profile.circuit_version, CHAIN_CIRCUIT_VERSION);
    assert_eq!(profile.total_instance_values(), INSTANCE_VALUES);
    assert_eq!(profile.witness_len, WITNESS_VALUES * 32);

    let k: u32 = match k_arg {
        Some(value) => value.parse().expect("k must be an integer"),
        None => DEFAULT_K,
    };
    assert!(
        (profile.min_k..=profile.max_k).contains(&k),
        "k must be within {}..={}",
        profile.min_k,
        profile.max_k
    );

    let output_path = output_arg.unwrap_or_else(|| {
        format!(
            "{}/../../tests/fixtures/halo2_ipa_external_chain_v1.hex",
            env!("CARGO_MANIFEST_DIR")
        )
    });

    let inputs = inputs();
    let public = chain_public_values(&inputs);
    assert_eq!(public.len(), INSTANCE_VALUES);

    let witness: Vec<u8> = inputs
        .iter()
        .flat_map(|value| encode_fr_be(*value))
        .collect();
    let instances = encode_instances_v1(&[public.clone()]).expect("instances encoding");

    // Deterministic transparent keygen through the public registry API.
    let (vk, pk) = prepare::<ChainCircuit>(k).expect("prepare should succeed");

    // Fixed, test-only seed. `prove_with_rng` is called explicitly so the
    // fixture never relies on an ambient RNG.
    let mut rng = StdRng::from_seed(FIXTURE_SEED);
    let proof = prove_with_rng::<ChainCircuit, _>(&pk, &witness, &instances, &mut rng)
        .expect("proof generation should succeed");

    // Self-check through the same generic verifier consumers use.
    verify::<ChainCircuit>(&vk, &proof, &instances).expect("generated fixture must verify");

    let contents = format!(
        "VK={}\nPK={}\nPROOF={}\nINSTANCES={}\nWITNESS={}\n",
        hex(&vk),
        hex(&pk),
        hex(&proof),
        hex(&instances),
        hex(&witness),
    );

    if let Some(parent) = std::path::Path::new(&output_path).parent() {
        std::fs::create_dir_all(parent).expect("create fixture directory");
    }
    std::fs::write(&output_path, contents).expect("write fixture");

    println!("wrote {output_path}");
    println!(
        "circuit={CHAIN_CIRCUIT_ID:#x} version={CHAIN_CIRCUIT_VERSION} k={k} \
         instance_values={INSTANCE_VALUES} witness_values={WITNESS_VALUES}"
    );
    println!("vk: encoded={} digest={}", vk.len(), hex(&vk_digest(&vk)));
    println!(
        "pk: encoded={} digest={}",
        pk.len(),
        hex(&rust_crypto_ffi::halo2_ipa_registry::pk_digest(&pk))
    );
    println!(
        "proof: encoded={} transcript={}",
        proof.len(),
        proof.len() - 12
    );
    println!("instances: encoded={}", instances.len());
    println!("witness: encoded={}", witness.len());
    println!("params: digest={}", hex(&params_digest(k)));
}
