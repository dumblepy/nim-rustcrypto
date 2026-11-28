//! Deterministic Halo2 IPA / BN254 v1 fixture for the 3-input Poseidon2 hash
//! circuit (circuit id `2`).
//!
//! Usage:
//! ```text
//! cargo run --locked --release --example halo2_ipa_poseidon2_fixture [output.hex]
//! ```
//!
//! The default output is `../tests/fixtures/halo2_ipa_poseidon2_v1.hex`
//! relative to this crate. The witness is three canonical 32-byte BE `Fr`
//! inputs `1, 2, 3` (96 bytes) and the public instance column is
//! `[digest, 1, 2, 3]`.
//!
//! The RNG seed is fixed for the fixture's test-only blinds. Note that this
//! vendored `halo2-axiom` fork samples the vanishing argument's random
//! polynomial from `rand::thread_rng()` internally, so the `PROOF` line is not
//! byte-identical when the generator is re-run; `VK`, `INSTANCES`, and
//! `WITNESS` are reproducible. The C ABI always uses `OsRng`.

use halo2_axiom::halo2curves::bn256::Fr;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rust_crypto_ffi::halo2_ipa::{
    HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1, encode_fr_be, encode_instances_v1,
    generate_poseidon2_key_material_v1, prove_poseidon2_with_rng_v1,
    rustcrypto_halo2_ipa_bn254_verify,
};

const K: u32 = 8;
/// Noir/Barretenberg Poseidon2 sponge digest of `[1, 2, 3]`.
const EXPECTED_DIGEST_HEX: &str =
    "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8";

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
            "{}/../tests/fixtures/halo2_ipa_poseidon2_v1.hex",
            env!("CARGO_MANIFEST_DIR")
        )
    });

    let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let digest = rust_crypto_ffi::poseidon2_halo2::hash_output(&inputs);
    assert_eq!(
        hex(&encode_fr_be(digest)),
        EXPECTED_DIGEST_HEX,
        "Poseidon2 [1,2,3] KAT drift"
    );

    let (vk, pk) = generate_poseidon2_key_material_v1(K)
        .expect("deterministic Poseidon2 IPA keygen should succeed");

    // Fixed, test-only seed. Never use a fixed seed outside fixtures/tests.
    let mut rng = StdRng::from_seed([0x85u8; 32]);
    let proof = prove_poseidon2_with_rng_v1(&pk, inputs, digest, &mut rng)
        .expect("proof generation should succeed");

    let instances = encode_instances_v1(&[vec![digest, inputs[0], inputs[1], inputs[2]]])
        .expect("instances encoding should succeed");
    let mut witness = Vec::with_capacity(3 * 32);
    for input in inputs {
        witness.extend_from_slice(&encode_fr_be(input));
    }

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
    println!("k={K} circuit={HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1} inputs=[1,2,3]");
    println!("digest: {}", hex(&encode_fr_be(digest)));
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
