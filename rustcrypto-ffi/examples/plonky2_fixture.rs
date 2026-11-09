//! Deterministic Plonky2/Goldilocks fixture generator.
//!
//! Usage: `cargo run --example plonky2_fixture`
//!
//! Produces two different circuits so the integration tests can also verify that a
//! proof is rejected with mismatched verifier/common circuit data.

use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::util::serialization::DefaultGateSerializer;
use plonky2::PoseidonGoldilocksConfig;

const D: usize = 2;
type F = plonky2::field::goldilocks_field::GoldilocksField;
type C = PoseidonGoldilocksConfig;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn main() {
    // Circuit 1: c = a * b
    {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.mul(a, b);
        builder.register_public_input(c);
        let data = builder.build::<C>();
        let proof = data
            .prove({
                let mut witness = PartialWitness::new();
                witness.set_target(a, F::from_canonical_u64(3)).unwrap();
                witness.set_target(b, F::from_canonical_u64(5)).unwrap();
                witness
            })
            .unwrap();
        data.verify(proof.clone()).unwrap();
        println!("MUL_PROOF={}", hex(&proof.to_bytes()));
        println!("MUL_VERIFIER={}", hex(&data.verifier_only.to_bytes().unwrap()));
        println!(
            "MUL_COMMON={}",
            hex(&data.common.to_bytes(&DefaultGateSerializer).unwrap())
        );
    }

    // Circuit 2: c = a + b
    {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.add(a, b);
        builder.register_public_input(c);
        builder.register_public_input(a);
        let data = builder.build::<C>();
        let proof = data
            .prove({
                let mut witness = PartialWitness::new();
                witness.set_target(a, F::from_canonical_u64(3)).unwrap();
                witness.set_target(b, F::from_canonical_u64(5)).unwrap();
                witness
            })
            .unwrap();
        data.verify(proof.clone()).unwrap();
        println!("ADD_PROOF={}", hex(&proof.to_bytes()));
        println!("ADD_VERIFIER={}", hex(&data.verifier_only.to_bytes().unwrap()));
        println!(
            "ADD_COMMON={}",
            hex(&data.common.to_bytes(&DefaultGateSerializer).unwrap())
        );
    }
}
