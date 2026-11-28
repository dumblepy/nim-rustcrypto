//! Generic Halo2 IPA / BN254 shape benchmark (no C ABI / circuit registry).
//!
//! The circuit is synthetic by design:
//!
//! ```text
//! advice[0] = first
//! advice[r+1] = advice[r] * advice[r] + 1   (one enabled gate row per step)
//! ```
//!
//! The first and the final advice values are copied into an instance column
//! with `Layouter::constrain_instance`, so the proof binds two public values.
//!
//! This is a **shape benchmark**, not an application-equivalent Merkle path,
//! range proof, or asset statement. It measures keygen / prove / verify cost
//! for a given number of gate rows and a given `k`.
//!
//! Usage:
//!
//! ```text
//! cargo run --locked --release --example halo2_ipa_bench
//! cargo run --locked --release --example halo2_ipa_bench -- --steps 4096 --k 13
//! ```
//!
//! The human-readable table is written to stderr; JSON goes to stdout.

use halo2_axiom::SerdeFormat;
use halo2_axiom::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_axiom::dev::MockProver;
use halo2_axiom::halo2curves::bn256::{Fr, G1Affine};
use halo2_axiom::plonk::{
    Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
    create_proof, keygen_pk, keygen_vk, verify_proof,
};
use halo2_axiom::poly::Rotation;
use halo2_axiom::poly::VerificationStrategy;
use halo2_axiom::poly::commitment::{Params, ParamsProver};
use halo2_axiom::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_axiom::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
use halo2_axiom::poly::ipa::strategy::SingleStrategy;
use halo2_axiom::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::hint::black_box;
use std::io::Cursor;
use std::time::Instant;

/// `next = cur * cur + ADDEND`.
const ADDEND: u64 = 1;
const FIRST: u64 = 3;

/// Two benchmark sizes: ~1k gate rows (k = 11) and ~20k gate rows (k = 15).
const DEFAULT_SIZES: &[(usize, u32)] = &[(1_024, 11), (20_000, 15)];

#[derive(Clone)]
struct ChainCircuit {
    steps: usize,
    first: Value<Fr>,
}

#[derive(Clone, Debug)]
struct ChainConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

fn step(value: Fr) -> Fr {
    value * value + Fr::from(ADDEND)
}

fn chain_end(first: Fr, steps: usize) -> Fr {
    let mut value = first;
    for _ in 0..steps {
        value = step(value);
    }
    value
}

impl Circuit<Fr> for ChainCircuit {
    type Config = ChainConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            steps: self.steps,
            first: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> ChainConfig {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();
        meta.enable_equality(advice);
        meta.enable_equality(instance);
        meta.create_gate("next = cur^2 + 1", |meta| {
            let cur = meta.query_advice(advice, Rotation::cur());
            let next = meta.query_advice(advice, Rotation::next());
            let enabled = meta.query_selector(selector);
            vec![enabled * (cur.clone() * cur + Expression::Constant(Fr::from(ADDEND)) - next)]
        });
        ChainConfig {
            advice,
            instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: ChainConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (first_cell, final_cell) = layouter.assign_region(
            || "chain",
            |mut region| {
                let mut value = self.first;
                let first = region
                    .assign_advice(config.advice, 0, value.map(Assigned::from))
                    .cell();
                let mut final_cell = first;
                for row in 1..=self.steps {
                    config.selector.enable(&mut region, row - 1)?;
                    value = value.map(step);
                    final_cell = region
                        .assign_advice(config.advice, row, value.map(Assigned::from))
                        .cell();
                }
                Ok((first, final_cell))
            },
        )?;
        layouter.constrain_instance(first_cell, config.instance, 0);
        layouter.constrain_instance(final_cell, config.instance, 1);
        Ok(())
    }
}

fn ceil_log2(value: usize) -> u32 {
    let mut k = 0u32;
    let mut n = 1usize;
    while n < value {
        n <<= 1;
        k += 1;
    }
    k
}

#[derive(Clone, Copy)]
struct SizeArg {
    steps: usize,
    k: u32,
}

fn parse_args() -> Vec<SizeArg> {
    let mut steps: Option<usize> = None;
    let mut k: Option<u32> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--steps" => {
                steps = Some(
                    args.next()
                        .expect("--steps requires a value")
                        .parse()
                        .expect("--steps must be a positive integer"),
                );
            }
            "--k" => {
                k = Some(
                    args.next()
                        .expect("--k requires a value")
                        .parse()
                        .expect("--k must be a positive integer"),
                );
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: halo2_ipa_bench [--steps N] [--k K]\n\
                     default: steps=1024 k=11, steps=20000 k=15"
                );
                std::process::exit(0);
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    match steps {
        Some(steps) => {
            assert!(steps > 0, "--steps must be positive");
            // Assigned rows: steps + 1 advice rows. Blinding rows for this
            // circuit are 5, so reserve steps + 7 usable rows and one extra
            // power-of-two margin.
            let k = k.unwrap_or_else(|| ceil_log2(steps + 8).max(4));
            vec![SizeArg { steps, k }]
        }
        None => {
            let mut sizes: Vec<SizeArg> = DEFAULT_SIZES
                .iter()
                .map(|&(steps, k)| SizeArg { steps, k })
                .collect();
            if let Some(k) = k {
                sizes = sizes
                    .into_iter()
                    .map(|size| SizeArg {
                        steps: size.steps,
                        k,
                    })
                    .collect();
            }
            sizes
        }
    }
}

struct BenchResult {
    steps: usize,
    k: u32,
    n: u64,
    blinding_factors: usize,
    usable_rows: usize,
    gate_rows: usize,
    advice_rows: usize,
    constraints: usize,
    mock_prover_verified: bool,
    vk_bytes: usize,
    pk_bytes: usize,
    proof_bytes: usize,
    params_ms: f64,
    keygen_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    verified: bool,
    wrong_instance_rejected: bool,
}

fn run_one(size: SizeArg) -> BenchResult {
    let SizeArg { steps, k } = size;
    let first = Fr::from(FIRST);
    let final_value = chain_end(first, steps);
    let instance_values = [first, final_value];
    let instance_columns: [&[Fr]; 1] = [&instance_values];
    let instances: [&[&[Fr]]; 1] = [&instance_columns];

    eprintln!("[k={k}, steps={steps}] ParamsIPA::new(k) ...");
    let start = Instant::now();
    let params = ParamsIPA::<G1Affine>::new(k);
    let params_ms = start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(params.k(), k, "ParamsIPA k mismatch");
    assert_eq!(params.n(), 1u64 << k);

    let empty_circuit = ChainCircuit {
        steps,
        first: Value::unknown(),
    };

    let witness_circuit = ChainCircuit {
        steps,
        first: Value::known(first),
    };

    // MockProver is used to prove that the assigned region fits inside the
    // usable rows and satisfies the gate. It does not expose a row counter, so
    // the row counts below are the rows this circuit deterministically assigns.
    let mock = MockProver::run(k, &witness_circuit, vec![instance_values.to_vec()])
        .expect("MockProver::run should accept the circuit shape");
    let mock_prover_verified = mock.verify().is_ok();

    eprintln!("[k={k}, steps={steps}] keygen_vk / keygen_pk ...");
    let start = Instant::now();
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should succeed");
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).expect("keygen_pk should succeed");
    let keygen_ms = start.elapsed().as_secs_f64() * 1000.0;

    let blinding_factors = vk.cs().blinding_factors();
    let usable_rows = params.n() as usize - (blinding_factors + 1);
    let gate_rows = steps;
    let advice_rows = steps + 1;
    assert!(
        advice_rows <= usable_rows,
        "assigned rows exceed usable rows: {advice_rows} > {usable_rows}"
    );

    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::Processed)
        .expect("serialize vk");
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::Processed)
        .expect("serialize pk");

    let circuit = ChainCircuit {
        steps,
        first: Value::known(first),
    };

    eprintln!("[k={k}, steps={steps}] create_proof ...");
    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    let mut rng = StdRng::from_seed([0x85u8; 32]);
    let start = Instant::now();
    create_proof::<IPACommitmentScheme<G1Affine>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &instances,
        &mut rng,
        &mut transcript,
    )
    .expect("create_proof should succeed");
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let proof = transcript.finalize();

    let verifier_params = params.verifier_params();

    // Correct instance.
    let mut reader =
        Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(Cursor::new(proof.as_slice()));
    let start = Instant::now();
    let verified =
        verify_proof::<IPACommitmentScheme<G1Affine>, VerifierIPA<_>, _, _, SingleStrategy<_>>(
            verifier_params,
            &vk,
            SingleStrategy::new(verifier_params),
            &instances,
            &mut reader,
        )
        .is_ok();
    let verify_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Wrong final instance must be rejected.
    let wrong_values = [first, final_value + Fr::from(1u64)];
    let wrong_columns: [&[Fr]; 1] = [&wrong_values];
    let wrong_instances: [&[&[Fr]]; 1] = [&wrong_columns];
    let mut wrong_reader =
        Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(Cursor::new(proof.as_slice()));
    let wrong_instance_rejected =
        verify_proof::<IPACommitmentScheme<G1Affine>, VerifierIPA<_>, _, _, SingleStrategy<_>>(
            verifier_params,
            &vk,
            SingleStrategy::new(verifier_params),
            &wrong_instances,
            &mut wrong_reader,
        )
        .is_err();

    black_box(&proof);

    BenchResult {
        steps,
        k,
        n: params.n(),
        blinding_factors,
        usable_rows,
        gate_rows,
        advice_rows,
        constraints: gate_rows,
        mock_prover_verified,
        vk_bytes: vk_bytes.len(),
        pk_bytes: pk_bytes.len(),
        proof_bytes: proof.len(),
        params_ms,
        keygen_ms,
        prove_ms,
        verify_ms,
        verified,
        wrong_instance_rejected,
    }
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
    let sizes = parse_args();
    let rustc = command_stdout("rustc", &["--version"]);
    let uname = command_stdout("uname", &["-srm"]);
    let generated_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    eprintln!("Generic Halo2 IPA / BN254 shape benchmark (release build)");
    eprintln!("rustc: {rustc}");
    eprintln!("uname: {uname}");
    eprintln!(
        "{:>6} {:>7} {:>8} {:>9} {:>8} {:>7} {:>9} {:>9} {:>9} {:>8} {:>8} {:>8} {:>9}",
        "steps",
        "k",
        "n",
        "usable",
        "advice",
        "gates",
        "vk_bytes",
        "pk_bytes",
        "proof_B",
        "keygen",
        "prove",
        "verify",
        "ok"
    );

    let mut results = Vec::with_capacity(sizes.len());
    for size in sizes {
        let result = run_one(size);
        eprintln!(
            "{:>6} {:>7} {:>8} {:>9} {:>8} {:>7} {:>9} {:>9} {:>9} {:>8.1} {:>8.1} {:>8.1} {:>9}",
            result.steps,
            result.k,
            result.n,
            result.usable_rows,
            result.advice_rows,
            result.gate_rows,
            result.vk_bytes,
            result.pk_bytes,
            result.proof_bytes,
            result.keygen_ms,
            result.prove_ms,
            result.verify_ms,
            result.verified && result.wrong_instance_rejected
        );
        results.push(result);
    }

    println!("{{");
    println!("  \"schema\": \"benchmarks-branch85/halo2-ipa-v1\",");
    println!("  \"generated_unix\": {generated_unix},");
    println!("  \"environment\": {{");
    println!("    \"rustc\": \"{}\",", json_escape(&rustc));
    println!("    \"uname\": \"{}\",", json_escape(&uname));
    println!("    \"profile\": \"release\"");
    println!("  }},");
    println!("  \"profile\": {{");
    println!("    \"implementation\": \"halo2-axiom 0.5.3 (vendored)\",");
    println!("    \"curve\": \"BN254 G1\",");
    println!("    \"scalar_field\": \"BN254 Fr\",");
    println!("    \"pcs\": \"IPA (BGH19)\",");
    println!("    \"transcript\": \"Blake2b\",");
    println!("    \"verification_strategy\": \"SingleStrategy\"");
    println!("  }},");
    println!("  \"circuit\": {{");
    println!("    \"name\": \"ChainCircuit (synthetic shape benchmark)\",");
    println!("    \"gate\": \"next = cur^2 + 1\",");
    println!("    \"advice_columns\": 1,");
    println!("    \"instance_columns\": 1,");
    println!("    \"instance_values\": 2,");
    println!(
        "    \"description\": \"one enabled gate row per step; first and final advice cells are bound to instance rows 0 and 1\""
    );
    println!("  }},");
    println!("  \"limitations\": [");
    println!(
        "    \"This is a synthetic shape benchmark, not an application-equivalent Merkle/range statement.\","
    );
    println!(
        "    \"Rows/constraints are gate rows; the advice chain has steps + 1 assigned rows.\","
    );
    println!("    \"Proof bytes are the raw IPA transcript bytes, not the v1 C ABI envelope.\",");
    println!(
        "    \"Peak RSS is measured by ci/benchmarks_branch85.sh with /usr/bin/time, not by this process.\","
    );
    println!(
        "    \"This vendored fork may draw the vanishing-argument random polynomial from thread_rng internally, so proof bytes are not reproducible across runs.\""
    );
    println!("  ],");
    println!("  \"results\": [");
    for (index, result) in results.iter().enumerate() {
        let comma = if index + 1 == results.len() { "" } else { "," };
        println!("    {{");
        println!("      \"steps\": {},", result.steps);
        println!("      \"k\": {},", result.k);
        println!("      \"n\": {},", result.n);
        println!("      \"blinding_factors\": {},", result.blinding_factors);
        println!("      \"usable_rows\": {},", result.usable_rows);
        println!("      \"gate_rows\": {},", result.gate_rows);
        println!("      \"advice_rows\": {},", result.advice_rows);
        println!("      \"constraints\": {},", result.constraints);
        println!(
            "      \"rows_used_fraction\": {:.6},",
            result.advice_rows as f64 / result.usable_rows as f64
        );
        println!(
            "      \"mock_prover_verified\": {},",
            result.mock_prover_verified
        );
        println!("      \"vk_bytes\": {},", result.vk_bytes);
        println!("      \"pk_bytes\": {},", result.pk_bytes);
        println!("      \"proof_bytes\": {},", result.proof_bytes);
        println!("      \"params_ms\": {:.3},", result.params_ms);
        println!("      \"keygen_ms\": {:.3},", result.keygen_ms);
        println!("      \"prove_ms\": {:.3},", result.prove_ms);
        println!("      \"verify_ms\": {:.3},", result.verify_ms);
        println!("      \"verified\": {},", result.verified);
        println!(
            "      \"wrong_instance_rejected\": {}",
            result.wrong_instance_rejected
        );
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}
