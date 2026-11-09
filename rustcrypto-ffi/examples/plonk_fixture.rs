//! Deterministic PLONK/BN254 fixture generator (genshi-core profile).
//!
//! Usage: `cargo run --example plonk_fixture`
//!
//! The fixture is generated with genshi-core's **insecure test SRS**. It must never be
//! used for production proofs. The output uses the v1 wire format consumed by
//! `rustcrypto_plonk_bn254_verify`.

use ark_bn254::Fr;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use genshi_core::proving::{api, srs::SRS};
use genshi_core::{Circuit, ProvableCircuit};
use rust_crypto_ffi::fixture::{
    encode_plonk_proof, encode_plonk_public_inputs, encode_plonk_vk,
};

struct AddCircuit;
struct AddWitness {
    a: Fr,
    b: Fr,
}

impl Circuit for AddCircuit {
    type PublicInputs = [Fr; 1];
    const ID: &'static str = "rustcrypto-ffi.fixture.add";

    fn num_public_inputs() -> usize {
        1
    }
}

impl ProvableCircuit for AddCircuit {
    type Witness = AddWitness;

    fn synthesize(builder: &mut UltraCircuitBuilder, w: &Self::Witness) -> Self::PublicInputs {
        let a = builder.add_variable(w.a);
        let b = builder.add_variable(w.b);
        let c = builder.add(a, b);
        builder.set_public(c);
        [w.a + w.b]
    }

    fn dummy_witness() -> Self::Witness {
        AddWitness {
            a: Fr::from(0u64),
            b: Fr::from(0u64),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn main() {
    let srs = SRS::insecure_for_testing(128);
    let (_proof, vk, public_inputs) = api::prove::<AddCircuit>(
        &AddWitness {
            a: Fr::from(3u64),
            b: Fr::from(5u64),
        },
        &srs,
    );
    let public_inputs: Vec<genshi_math::Fr> = public_inputs
        .iter()
        .map(|value| genshi_math::Fr::from_ark(*value))
        .collect();

    println!("VK={}", hex(&encode_plonk_vk(&vk, &srs)));
    println!("PROOF={}", hex(&encode_plonk_proof(&_proof)));
    println!("INPUTS={}", hex(&encode_plonk_public_inputs(&public_inputs)));
}
