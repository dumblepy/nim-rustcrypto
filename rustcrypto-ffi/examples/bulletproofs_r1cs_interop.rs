mod support {
    pub mod bulletproofs_fixture;
}
use rust_crypto_ffi::bulletproofs_r1cs::*;
use std::{env, fs, path::Path, time::Instant};
use support::bulletproofs_fixture::*;

const CONTEXT: &[u8] = b"nim-rustcrypto/interop/v1";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("fixture") if args.len() == 3 => {
            let dir = Path::new(&args[2]);
            fs::create_dir_all(dir)?;
            let fixture = multiplication();
            let circuit = CircuitDefinition::from_bytes(&fixture.circuit).unwrap();
            let proof = circuit
                .prove(
                    PublicInputs(&fixture.public),
                    Witness(&fixture.witness),
                    CONTEXT,
                )
                .unwrap();
            fs::write(dir.join("circuit.bin"), fixture.circuit)?;
            fs::write(dir.join("public.bin"), fixture.public)?;
            fs::write(dir.join("witness.bin"), fixture.witness)?;
            fs::write(dir.join("context.bin"), CONTEXT)?;
            fs::write(dir.join("native.bin"), proof)?;
        }
        Some("verify") if args.len() == 4 => {
            let dir = Path::new(&args[2]);
            let circuit =
                CircuitDefinition::from_bytes(&fs::read(dir.join("circuit.bin"))?).unwrap();
            let public = fs::read(dir.join("public.bin"))?;
            let context = fs::read(dir.join("context.bin"))?;
            let proof = fs::read(dir.join(&args[3]))?;
            let started = Instant::now();
            assert!(
                circuit
                    .verify(PublicInputs(&public), &context, Proof(&proof))
                    .unwrap()
            );
            println!("verifier_ms={:.3}", started.elapsed().as_secs_f64() * 1000.);
        }
        Some("bench") if args.len() == 2 => {
            const ITERATIONS: u32 = 10;
            println!(
                "case,rows,gates,proof_body_bytes,commitment_bytes,public_input_bytes,payload_bytes,generator_bytes,prover_ms,verifier_ms"
            );
            for (name, rows, fixture) in [
                ("range32", 33, ranged(32)),
                ("range64", 65, ranged(64)),
                ("range128", 129, ranged(128)),
                ("sum32", 100, bounded_sum(32)),
                ("sum64", 196, bounded_sum(64)),
                ("multiplication", 2, multiplication()),
            ] {
                let circuit = CircuitDefinition::from_bytes(&fixture.circuit).unwrap();
                let mut prover = 0.;
                let mut verifier = 0.;
                for iteration in 0..=ITERATIONS {
                    let started = Instant::now();
                    let proof = circuit
                        .prove(
                            PublicInputs(&fixture.public),
                            Witness(&fixture.witness),
                            CONTEXT,
                        )
                        .unwrap();
                    let prove_ms = started.elapsed().as_secs_f64() * 1000.;
                    let started = Instant::now();
                    assert!(
                        circuit
                            .verify(PublicInputs(&fixture.public), CONTEXT, Proof(&proof))
                            .unwrap()
                    );
                    if iteration != 0 {
                        prover += prove_ms;
                        verifier += started.elapsed().as_secs_f64() * 1000.;
                    }
                }
                println!(
                    "{name},{rows},{},{},{},{},{},{},{:.3},{:.3}",
                    circuit.multiplication_gates(),
                    circuit.proof_body_len(),
                    circuit.proof_len() - 42 - circuit.proof_body_len(),
                    fixture.public.len(),
                    fixture.public.len() + circuit.proof_len(),
                    circuit.encoded_generator_bytes(),
                    prover / f64::from(ITERATIONS),
                    verifier / f64::from(ITERATIONS)
                );
            }
        }
        _ => return Err("usage: fixture DIR | verify DIR FILE | bench".into()),
    }
    Ok(())
}
