//! Deterministic Halo2 IPA / BN254 v1 fixture for the Poseidon2 hash circuits.
//!
//! Usage:
//! ```text
//! cargo run --locked --release --example halo2_ipa_poseidon2_fixture [output.hex] [arity]
//! ```
//!
//! - Without `arity`, the legacy 3-input circuit id `2` is used and the default
//!   output is `../tests/fixtures/halo2_ipa_poseidon2_v1.hex` relative to this
//!   crate.
//! - With `arity` in `0..=12`, the arbitrary-arity circuit id
//!   `0x100 + arity` is used at its minimum `k`. For example:
//!   `cargo run --locked --release --example halo2_ipa_poseidon2_fixture \
//!      ../tests/fixtures/halo2_ipa_poseidon2_arity12_v1.hex 12`
//!
//! The default witness is three canonical 32-byte BE `Fr` inputs `1, 2, 3`
//! (96 bytes) and the public instance column is `[digest, 1, 2, 3]`. The
//! arbitrary-arity witness is `arity` inputs `1..=arity` (`32 * arity` bytes,
//! empty for arity 0) and the instance column is `[digest, 1, .., arity]`.
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
    generate_poseidon2_arity_key_material_v1, generate_poseidon2_key_material_v1,
    poseidon2_arity_min_k, prove_poseidon2_arity_with_rng_v1, prove_poseidon2_with_rng_v1,
    rustcrypto_halo2_ipa_bn254_verify,
};
use rust_crypto_ffi::poseidon2_halo2::{hash_output, hash_public_inputs};

const LEGACY_K: u32 = 8;
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
    let mut args = std::env::args().skip(1);
    let output_arg = args.next();
    let arity_arg = args.next();
    if args.next().is_some() {
        eprintln!("usage: halo2_ipa_poseidon2_fixture [output.hex] [arity 0..=12]");
        std::process::exit(2);
    }

    // Without an explicit arity the legacy 3-input circuit id 2 is used so the
    // committed `halo2_ipa_poseidon2_v1.hex` fixture stays reproducible.
    let legacy = arity_arg.is_none();
    let arity: usize = match arity_arg {
        Some(value) => value.parse().expect("arity must be an integer"),
        None => 3,
    };
    let output_path = output_arg.unwrap_or_else(|| {
        let name = if legacy {
            "halo2_ipa_poseidon2_v1.hex"
        } else {
            "halo2_ipa_poseidon2_arity_v1.hex"
        };
        format!("{}/../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
    });

    let inputs: Vec<Fr> = (1..=arity as u64).map(Fr::from).collect();
    let digest = hash_output(&inputs);
    if legacy {
        assert_eq!(
            hex(&encode_fr_be(digest)),
            EXPECTED_DIGEST_HEX,
            "Poseidon2 [1,2,3] KAT drift"
        );
    }

    let (circuit_id, k, vk, pk) = if legacy {
        let (vk, pk) = generate_poseidon2_key_material_v1(LEGACY_K)
            .expect("deterministic Poseidon2 IPA keygen should succeed");
        (HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1, LEGACY_K, vk, pk)
    } else {
        let k = poseidon2_arity_min_k(arity).expect("arity must be in 0..=12");
        let (vk, pk) = generate_poseidon2_arity_key_material_v1(arity, k)
            .expect("deterministic Poseidon2 arity keygen should succeed");
        (
            0x100u32 + u32::try_from(arity).expect("arity fits in u32"),
            k,
            vk,
            pk,
        )
    };

    // Fixed, test-only seed. Never use a fixed seed outside fixtures/tests.
    let mut rng = StdRng::from_seed([0x85u8; 32]);
    let proof = if legacy {
        prove_poseidon2_with_rng_v1(&pk, [inputs[0], inputs[1], inputs[2]], digest, &mut rng)
            .expect("proof generation should succeed")
    } else {
        prove_poseidon2_arity_with_rng_v1(&pk, &inputs, digest, &mut rng)
            .expect("proof generation should succeed")
    };

    let instances = encode_instances_v1(&[hash_public_inputs(&inputs)])
        .expect("instances encoding should succeed");
    let mut witness = Vec::with_capacity(arity * 32);
    for input in &inputs {
        witness.extend_from_slice(&encode_fr_be(*input));
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
    println!("k={k} circuit={circuit_id} arity={arity}");
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
