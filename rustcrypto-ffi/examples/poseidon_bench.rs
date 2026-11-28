//! Poseidon1 vs Poseidon2 / BN254 R1CS and native-hash benchmark.
//!
//! Usage (release only for meaningful numbers):
//!
//! ```text
//! cargo run --locked --release --example poseidon_bench
//! ```
//!
//! The human-readable table is written to stderr and the machine-readable JSON
//! document to stdout, so a CI script can redirect stdout without losing the
//! table:
//!
//! ```text
//! cargo run --locked --release --example poseidon_bench > poseidon-bench.json
//! ```
//!
//! # What is measured
//!
//! * R1CS shape from `ark-relations` 0.5.1 / `ark-r1cs-std` 0.5:
//!   constraints, witness variables, instance variables and A/B/C non-zero
//!   coefficients. The matrices are built with the default
//!   `SynthesisMode::Prove { construct_matrices: true }` and `cs.finalize()` is
//!   called before `cs.to_matrices()`.
//! * Native hash timing: `light-poseidon` Poseidon1 (`new_circom`) and the
//!   Poseidon2 C ABI (`rustcrypto_poseidon2_bn254_hash`). The Poseidon2 timing
//!   therefore includes the small C ABI marshalling overhead; input bytes are
//!   encoded once outside the loop.
//!
//! # What is not measured
//!
//! `ark-relations` / Groth16 R1CS has no Halo2-style padded row domain, so
//! "rows"/"padding" are reported as `null` with an explicit note. Halo2 rows for
//! a Poseidon1 gate are not available because this branch does not implement a
//! Poseidon1 Halo2 custom gate.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode};
use light_poseidon::{Poseidon, PoseidonHasher};
use rust_crypto_ffi::groth16_prover::poseidon_gadget;
use rust_crypto_ffi::poseidon2::{
    POSEIDON2_BN254_RATE, POSEIDON2_BN254_WIDTH, rustcrypto_poseidon2_bn254_hash,
};
use rust_crypto_ffi::poseidon2_gadget;
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Arity 0 is only supported by Poseidon2 in this benchmark.
const ARITIES: &[usize] = &[0, 1, 2, 3, 8, 9];

#[derive(Clone, Copy)]
struct R1csStats {
    constraints: usize,
    witness_variables: usize,
    instance_variables: usize,
    a_nnz: usize,
    b_nnz: usize,
    c_nnz: usize,
}

impl R1csStats {
    fn total_nnz(self) -> usize {
        self.a_nnz + self.b_nnz + self.c_nnz
    }
}

/// Finalizes `cs`, checks that the generated assignment satisfies every
/// constraint, and extracts the R1CS matrix statistics.
fn stats_from_cs(cs: &ConstraintSystemRef<Fr>) -> Result<R1csStats, SynthesisError> {
    cs.finalize();
    match cs.is_satisfied() {
        Ok(true) => {}
        Ok(false) => return Err(SynthesisError::Unsatisfiable),
        Err(error) => return Err(error),
    }
    let matrices = cs.to_matrices().ok_or(SynthesisError::Unsatisfiable)?;
    Ok(R1csStats {
        constraints: matrices.num_constraints,
        witness_variables: matrices.num_witness_variables,
        instance_variables: matrices.num_instance_variables,
        a_nnz: matrices.a_num_non_zero,
        b_nnz: matrices.b_num_non_zero,
        c_nnz: matrices.c_num_non_zero,
    })
}

fn poseidon1_stats(arity: usize) -> Result<R1csStats, SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });
    let inputs = (0..arity)
        .map(|index| FpVar::new_witness(cs.clone(), || Ok(Fr::from(index as u64))))
        .collect::<Result<Vec<_>, _>>()?;
    let output = poseidon_gadget(&inputs)?;
    // Keep the output alive: ark-r1cs generates constraints eagerly, so this
    // is only to make the intent explicit.
    let _ = black_box(output);
    stats_from_cs(&cs)
}

fn poseidon2_stats(arity: usize) -> Result<R1csStats, SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });
    let inputs = (0..arity)
        .map(|index| FpVar::new_witness(cs.clone(), || Ok(Fr::from(index as u64))))
        .collect::<Result<Vec<_>, _>>()?;
    let output = poseidon2_gadget::hash(&inputs)?;
    let _ = black_box(output);
    stats_from_cs(&cs)
}

fn iterations_for(arity: usize) -> usize {
    match arity {
        0..=3 => 2_000,
        _ => 500,
    }
}

fn bench_ns<F: FnMut()>(mut op: F, iterations: usize) -> f64 {
    let warmup = std::cmp::max(16, iterations / 20);
    for _ in 0..warmup {
        op();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        op();
    }
    start.elapsed().as_nanos() as f64 / iterations as f64
}

fn poseidon1_native_ns(arity: usize) -> Option<f64> {
    if arity == 0 {
        return None;
    }
    let mut hasher = Poseidon::<Fr>::new_circom(arity).expect("supported Poseidon1 width");
    let inputs: Vec<Fr> = (0..arity).map(|index| Fr::from(index as u64)).collect();
    let iterations = iterations_for(arity);
    Some(bench_ns(
        || {
            let digest = hasher.hash(&inputs).expect("Poseidon1 hash");
            black_box(digest);
        },
        iterations,
    ))
}

fn poseidon2_native_ns(arity: usize) -> f64 {
    let inputs: Vec<Fr> = (0..arity).map(|index| Fr::from(index as u64)).collect();
    let mut input_bytes = Vec::with_capacity(arity * 32);
    for value in &inputs {
        input_bytes.extend_from_slice(&value.into_bigint().to_bytes_be());
    }
    let input_ptr = if input_bytes.is_empty() {
        core::ptr::null()
    } else {
        input_bytes.as_ptr()
    };
    let mut output = [0u8; 32];
    let iterations = iterations_for(arity);
    bench_ns(
        || {
            let status = rustcrypto_poseidon2_bn254_hash(
                input_ptr,
                input_bytes.len(),
                arity,
                output.as_mut_ptr(),
                output.len(),
            );
            assert_eq!(status, 0, "Poseidon2 C ABI hash failed");
            let _ = black_box(output);
        },
        iterations,
    )
}

fn command_stdout(program: &str, args: &[&str]) -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|| "unavailable".to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (program, args);
        "unavailable".to_string()
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn main() {
    let rustc = command_stdout("rustc", &["--version"]);
    let uname = command_stdout("uname", &["-srm"]);
    let generated_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    eprintln!("Poseidon1 vs Poseidon2 / BN254 Fr (release build)");
    eprintln!("rustc: {rustc}");
    eprintln!("uname: {uname}");
    eprintln!(
        "Poseidon2 profile: t={POSEIDON2_BN254_WIDTH}, rate={POSEIDON2_BN254_RATE}, capacity=1, sbox=x^5, RF=8, RP=56, sponge=Noir/Barretenberg"
    );
    eprintln!(
        "{:<10} {:>5} {:>11} {:>9} {:>6} {:>7} {:>7} {:>7} {:>8} {:>12}",
        "hash", "arity", "constraints", "witness", "inst", "A", "B", "C", "nnz", "ns/op"
    );

    let mut rows: Vec<String> = Vec::new();
    for &arity in ARITIES {
        let usage = if arity == 2 {
            "merkle_node"
        } else {
            "field_hash"
        };

        // Poseidon1: arity 0 is unsupported (light-poseidon requires >= 1 input).
        if arity == 0 {
            eprintln!("{:<10} {:>5} {:>11}", "poseidon1", arity, "unsupported");
            rows.push(format!(
                "{{\"hash\":\"poseidon1\",\"arity\":0,\"use\":\"{usage}\",\"supported\":false,\"reason\":\"light-poseidon requires at least one input\",\"constraints\":null,\"witness_variables\":null,\"instance_variables\":null,\"a_nnz\":null,\"b_nnz\":null,\"c_nnz\":null,\"total_nnz\":null,\"native_iterations\":0,\"native_ns_per_op\":null,\"padding\":null,\"padding_note\":\"R1CS/Groth16 has no Halo2-style padded row domain in this measurement\"}}"
            ));
        } else {
            let stats = poseidon1_stats(arity).expect("Poseidon1 R1CS synthesis");
            let iterations = iterations_for(arity);
            let ns = poseidon1_native_ns(arity).expect("Poseidon1 native hash");
            eprintln!(
                "{:<10} {:>5} {:>11} {:>9} {:>6} {:>7} {:>7} {:>7} {:>8} {:>12.1}",
                "poseidon1",
                arity,
                stats.constraints,
                stats.witness_variables,
                stats.instance_variables,
                stats.a_nnz,
                stats.b_nnz,
                stats.c_nnz,
                stats.total_nnz(),
                ns
            );
            rows.push(format!(
                "{{\"hash\":\"poseidon1\",\"arity\":{arity},\"use\":\"{usage}\",\"supported\":true,\"constraints\":{},\"witness_variables\":{},\"instance_variables\":{},\"a_nnz\":{},\"b_nnz\":{},\"c_nnz\":{},\"total_nnz\":{},\"native_iterations\":{iterations},\"native_ns_per_op\":{ns:.1},\"padding\":null,\"padding_note\":\"R1CS/Groth16 has no Halo2-style padded row domain in this measurement\"}}",
                stats.constraints,
                stats.witness_variables,
                stats.instance_variables,
                stats.a_nnz,
                stats.b_nnz,
                stats.c_nnz,
                stats.total_nnz(),
            ));
        }

        // Poseidon2: arity 0 is allowed.
        let stats = poseidon2_stats(arity).expect("Poseidon2 R1CS synthesis");
        let iterations = iterations_for(arity);
        let ns = poseidon2_native_ns(arity);
        eprintln!(
            "{:<10} {:>5} {:>11} {:>9} {:>6} {:>7} {:>7} {:>7} {:>8} {:>12.1}",
            "poseidon2",
            arity,
            stats.constraints,
            stats.witness_variables,
            stats.instance_variables,
            stats.a_nnz,
            stats.b_nnz,
            stats.c_nnz,
            stats.total_nnz(),
            ns
        );
        rows.push(format!(
            "{{\"hash\":\"poseidon2\",\"arity\":{arity},\"use\":\"{usage}\",\"supported\":true,\"constraints\":{},\"witness_variables\":{},\"instance_variables\":{},\"a_nnz\":{},\"b_nnz\":{},\"c_nnz\":{},\"total_nnz\":{},\"native_iterations\":{iterations},\"native_ns_per_op\":{ns:.1},\"padding\":null,\"padding_note\":\"R1CS/Groth16 has no Halo2-style padded row domain in this measurement\"}}",
            stats.constraints,
            stats.witness_variables,
            stats.instance_variables,
            stats.a_nnz,
            stats.b_nnz,
            stats.c_nnz,
            stats.total_nnz(),
        ));
    }

    println!("{{");
    println!("  \"schema\": \"benchmarks-branch85/poseidon-v1\",");
    println!("  \"generated_unix\": {generated_unix},");
    println!("  \"environment\": {{");
    println!("    \"rustc\": \"{}\",", json_escape(&rustc));
    println!("    \"uname\": \"{}\",", json_escape(&uname));
    println!("    \"profile\": \"release\"");
    println!("  }},");
    println!("  \"poseidon2_profile\": {{");
    println!("    \"field\": \"BN254 Fr\",");
    println!("    \"t\": {POSEIDON2_BN254_WIDTH},");
    println!("    \"rate\": {POSEIDON2_BN254_RATE},");
    println!("    \"capacity\": 1,");
    println!("    \"sbox\": \"x^5\",");
    println!("    \"RF\": 8,");
    println!("    \"RP\": 56,");
    println!("    \"sponge\": \"Noir/Barretenberg\"");
    println!("  }},");
    println!("  \"timing\": {{");
    println!("    \"clock\": \"std::time::Instant (wall clock, single process)\",");
    println!(
        "    \"poseidon1\": \"light-poseidon 0.4.1 Poseidon::<Fr>::new_circom(n), native fields, warmup then timed loop\","
    );
    println!(
        "    \"poseidon2\": \"rustcrypto_poseidon2_bn254_hash C ABI, native fields, input bytes encoded outside the loop, marshalling included\","
    );
    println!("    \"warmup_iterations\": \"max(16, iterations/20)\"");
    println!("  }},");
    println!("  \"limitations\": [");
    println!(
        "    \"R1CS/Groth16 shapes do not have Halo2 rows, k, or padded row domains; those fields are null.\","
    );
    println!(
        "    \"No Poseidon1 Halo2 custom gate exists in this branch, so Halo2 rows/proof size are not comparable.\","
    );
    println!("    \"WASM instruction/cycle counts are not measured by this native example.\"");
    println!("  ],");
    println!("  \"results\": [");
    for (index, row) in rows.iter().enumerate() {
        let comma = if index + 1 == rows.len() { "" } else { "," };
        println!("    {row}{comma}");
    }
    println!("  ]");
    println!("}}");
}
