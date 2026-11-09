//! Deterministic Groth16/BN254 fixture generator used by the Nim integration tests.
//!
//! Usage: `cargo run --example groth16_fixture`
//!
//! The circuit is a single multiplication gate `a * a = b` over BN254 `Fr`.
//! Output is the v1 wire format consumed by `rustcrypto_groth16_bn254_verify`.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rust_crypto_ffi::fixture::{
    encode_proof, encode_public_inputs, encode_vk,
};

#[derive(Clone)]
struct MulCircuit {
    a: Option<u64>,
    b: Option<u64>,
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| Ok(Fr::from(self.a.unwrap())))?;
        let b = cs.new_input_variable(|| Ok(Fr::from(self.b.unwrap())))?;
        cs.enforce_constraint(lc!() + a, lc!() + a, lc!() + b)?;
        Ok(())
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
    let circuit = MulCircuit {
        a: Some(3),
        b: Some(9),
    };
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng).unwrap();
    let proof: Proof<Bn254> = Groth16::<Bn254>::prove(&params, circuit, &mut rng).unwrap();
    let vk: VerifyingKey<Bn254> = params.vk.clone();
    let inputs = [Fr::from(9u64)];

    println!("VK={}", hex(&encode_vk(&vk)));
    println!("PROOF={}", hex(&encode_proof(&proof)));
    println!("INPUTS={}", hex(&encode_public_inputs(&inputs)));
}
