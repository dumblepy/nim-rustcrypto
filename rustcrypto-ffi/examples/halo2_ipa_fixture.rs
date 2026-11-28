//! Deterministic Halo2 IPA / BN254 v1 fixture generator.
//!
//! Usage:
//! ```text
//! `cargo run --example halo2_ipa_fixture [output.hex]`
//! ```
//!
//! The default output is `../tests/fixtures/halo2_ipa_bn254_v1.hex` relative to
//! this crate.
//!
//! The RNG seed is fixed for the fixture's test-only blinds. Note that this
//! vendored `halo2-axiom` fork samples the vanishing argument's random
//! polynomial from `rand::thread_rng()` internally, so the `PROOF` line is not
//! byte-identical when the generator is re-run; `VK`, `PK`, `INSTANCES`, and
//! `WITNESS` are reproducible. The C ABI always uses `OsRng`.

use halo2_axiom::halo2curves::bn256::Fr;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rust_crypto_ffi::halo2_ipa::{
    HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, encode_fr_be, encode_instances_v1, generate_key_material_v1,
    prove_with_rng_v1, rustcrypto_halo2_ipa_bn254_verify,
};

const K: u32 = 8;
/// Witness x. Public instance is x^3 + x + 5 = 35.
const X: u64 = 3;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn main() {
    let output_path = std::env::args().skip(1).next().unwrap_or_else(|| {
        format!(
            "{}/../tests/fixtures/halo2_ipa_bn254_v1.hex",
            env!("CARGO_MANIFEST_DIR")
        )
    });

    let (vk, pk) = generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, K)
        .expect("deterministic IPA keygen should succeed");

    let x = Fr::from(X);
    let y = x * x * x + x + Fr::from(5u64);
    assert_eq!(y, Fr::from(35u64), "fixture witness/instance drift");

    // Fixed, test-only seed. Never use a fixed seed outside fixtures/tests.
    let mut rng = StdRng::from_seed([7u8; 32]);
    let proof = prove_with_rng_v1(&pk, x, y, &mut rng).expect("proof generation should succeed");

    let instances = encode_instances_v1(&[vec![y]]).expect("instances encoding should succeed");
    let witness = encode_fr_be(x);

    let status = rustcrypto_halo2_ipa_bn254_verify(
        vk.as_ptr(),
        vk.len(),
        proof.as_ptr(),
        proof.len(),
        instances.as_ptr(),
        instances.len(),
    );
    assert_eq!(status, 0, "generated fixture must verify through the C ABI");

    let contents = format!(
        "VK={}\nPROOF={}\nINSTANCES={}\nWITNESS={}\n",
        hex(&vk),
        hex(&proof),
        hex(&instances),
        hex(&witness),
    );

    if let Some(parent) = std::path::Path::new(&output_path).parent() {
        std::fs::create_dir_all(parent).expect("create fixture directory");
    }
    std::fs::write(&output_path, contents).expect("write fixture");

    println!("wrote {output_path}");
    println!("k={K} circuit=1 x={X} y=35");
    println!("vk: encoded={} payload={}", vk.len(), vk.len() - 20);
    println!("pk: encoded={} payload={}", pk.len(), pk.len() - 20);
    println!(
        "proof: encoded={} transcript={}",
        proof.len(),
        proof.len() - 12
    );
    println!("instances: encoded={}", instances.len());
    println!("witness: encoded={}", witness.len());
}
