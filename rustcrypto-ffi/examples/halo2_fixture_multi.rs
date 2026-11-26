//! Deterministic multi-instance-column Halo2 (PSE/Axiom KZG/BN254, SHPLONK,
//! Blake2b) fixture generator.
//!
//! This complements `halo2_fixture.rs`: it exercises the same v1 wire profile
//! with a medium-size circuit (K = 10), two advice columns and two instance
//! columns holding two public values each (`num_instance = [2, 2]`).
//!
//! Usage:
//!   `cargo run --example halo2_fixture_multi`
//!   `cargo run --example halo2_fixture_multi -- path/to/fixture.hex`
//!
//! Without an output path the `PARAMS=`/`VK=`/`PROOF=`/`INSTANCES=` lines are
//! printed to stdout. The proof is checked with halo2-axiom's native verifier
//! before anything is emitted.
//!
//! Uses `ParamsKZG::setup(10, seeded_rng)`. The SRS is **insecure and
//! test-only**; never use it in production.

use rand::SeedableRng;
use snark_verifier::halo2_base::halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use snark_verifier::halo2_base::halo2_proofs::halo2curves::CurveAffineExt;
use snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fq2, Fr, G1Affine};
use snark_verifier::halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use snark_verifier::halo2_base::halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, create_proof, keygen_pk,
    keygen_vk, verify_proof,
};
use snark_verifier::halo2_base::halo2_proofs::poly::Rotation;
use snark_verifier::halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use snark_verifier::halo2_base::halo2_proofs::poly::kzg::commitment::{
    KZGCommitmentScheme, ParamsKZG,
};
use snark_verifier::halo2_base::halo2_proofs::poly::kzg::multiopen::{
    ProverSHPLONK, VerifierSHPLONK,
};
use snark_verifier::halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use snark_verifier::halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use snark_verifier::system::halo2::{Config, compile};

const K: u32 = 10;
/// Number of constrained rows (well below the K = 10 domain size of 1024).
const ROWS: usize = 256;
/// Two public values per instance column.
const VALUES_PER_INSTANCE: usize = 2;

/// Advice column 0 holds `1, 2, 3, ...`; advice column 1 holds `2, 4, 6, ...`.
/// A custom gate enforces `advice1 = 2 * advice0` on every row, and the first
/// two cells of each column are constrained to that column's public instances.
#[derive(Clone)]
struct MultiInstanceCircuit {
    advice0: Vec<Value<Fr>>,
    advice1: Vec<Value<Fr>>,
}

impl MultiInstanceCircuit {
    fn new() -> Self {
        let advice0 = (0..ROWS)
            .map(|row| Value::known(Fr::from(row as u64 + 1)))
            .collect();
        let advice1 = (0..ROWS)
            .map(|row| Value::known(Fr::from(2 * (row as u64 + 1))))
            .collect();
        Self { advice0, advice1 }
    }

    /// Public instances matching the first `VALUES_PER_INSTANCE` rows of both
    /// advice columns.
    fn instances() -> Vec<Vec<Fr>> {
        let public0 = (0..VALUES_PER_INSTANCE)
            .map(|row| Fr::from(row as u64 + 1))
            .collect();
        let public1 = (0..VALUES_PER_INSTANCE)
            .map(|row| Fr::from(2 * (row as u64 + 1)))
            .collect();
        vec![public0, public1]
    }
}

impl Circuit<Fr> for MultiInstanceCircuit {
    type Config = (
        Column<Advice>,
        Column<Advice>,
        Column<Instance>,
        Column<Instance>,
        Selector,
    );
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            advice0: (0..ROWS).map(|_| Value::unknown()).collect(),
            advice1: (0..ROWS).map(|_| Value::unknown()).collect(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice0 = meta.advice_column();
        let advice1 = meta.advice_column();
        let instance0 = meta.instance_column();
        let instance1 = meta.instance_column();
        let gate = meta.selector();

        for column in [advice0, advice1] {
            meta.enable_equality(column);
        }
        for column in [instance0, instance1] {
            meta.enable_equality(column);
        }

        meta.create_gate("advice1 is twice advice0", |meta| {
            let q = meta.query_selector(gate);
            let a = meta.query_advice(advice0, Rotation::cur());
            let b = meta.query_advice(advice1, Rotation::cur());
            vec![q * (b - a.clone() - a)]
        });

        (advice0, advice1, instance0, instance1, gate)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (advice0, advice1, instance0, instance1, gate) = config;
        let mut first = None;
        let mut second = None;

        layouter.assign_region(
            || "witness",
            |mut region| {
                for row in 0..ROWS {
                    let cell0 = region.assign_advice(advice0, row, self.advice0[row]);
                    let cell1 = region.assign_advice(advice1, row, self.advice1[row]);
                    match row {
                        0 => first = Some((cell0.cell(), cell1.cell())),
                        1 => second = Some((cell0.cell(), cell1.cell())),
                        _ => {}
                    }
                    gate.enable(&mut region, row)?;
                }
                Ok(())
            },
        )?;

        let (a0, b0) = first.expect("row 0 assigned");
        let (a1, b1) = second.expect("row 1 assigned");
        layouter.constrain_instance(a0, instance0, 0);
        layouter.constrain_instance(a1, instance0, 1);
        layouter.constrain_instance(b0, instance1, 0);
        layouter.constrain_instance(b1, instance1, 1);
        Ok(())
    }
}

fn fq_be(value: &Fq) -> [u8; 32] {
    let mut bytes = value.to_repr();
    bytes.reverse();
    bytes
}

fn fq2_be(value: &Fq2) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_be(&value.c0));
    out[32..].copy_from_slice(&fq_be(&value.c1));
    out
}

fn fr_be(value: &Fr) -> [u8; 32] {
    let mut bytes = value.to_repr();
    bytes.reverse();
    bytes
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn main() {
    assert_eq!(VALUES_PER_INSTANCE, 2);

    let mut setup_rng = rand::rngs::StdRng::seed_from_u64(17);
    let params = ParamsKZG::<Bn256>::setup(K, &mut setup_rng);
    assert_eq!(params.k(), K);

    let circuit = MultiInstanceCircuit::new();
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk");
    let protocol = compile(
        &params,
        &vk,
        Config::kzg().with_num_instance(vec![VALUES_PER_INSTANCE, VALUES_PER_INSTANCE]),
    );
    assert_eq!(
        protocol.num_instance,
        vec![VALUES_PER_INSTANCE, VALUES_PER_INSTANCE]
    );

    let instance_values = MultiInstanceCircuit::instances();
    assert_eq!(instance_values.len(), 2);
    let instance_refs: Vec<&[Fr]> = instance_values
        .iter()
        .map(|column| column.as_slice())
        .collect();
    let proof_instances: Vec<&[&[Fr]]> = vec![instance_refs.as_slice()];

    let proof_rng = rand::rngs::StdRng::seed_from_u64(19);
    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<_>,
        Challenge255<G1Affine>,
        _,
        _,
        MultiInstanceCircuit,
    >(
        &params,
        &pk,
        &[circuit],
        &proof_instances,
        proof_rng,
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();

    // Verify with halo2-axiom's native verifier before emitting the fixture.
    let mut verifier_transcript =
        Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(proof.as_slice());
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<Bn256>,
        _,
        _,
        SingleStrategy<Bn256>,
    >(
        &params,
        &vk,
        SingleStrategy::new(&params),
        &proof_instances,
        &mut verifier_transcript,
    )
    .expect("native halo2 verification of the generated multi-instance proof failed");

    let g1_affine = params.get_g()[0];
    let (g1_x, g1_y) = g1_affine.into_coordinates();
    let (g2_x, g2_y) = params.g2().into_coordinates();
    let (s_g2_x, s_g2_y) = params.s_g2().into_coordinates();

    let mut params_bytes = Vec::new();
    params_bytes.extend_from_slice(b"RCH2P1\0\0");
    params_bytes.extend_from_slice(&fq_be(&g1_x));
    params_bytes.extend_from_slice(&fq_be(&g1_y));
    params_bytes.extend_from_slice(&fq2_be(&g2_x));
    params_bytes.extend_from_slice(&fq2_be(&g2_y));
    params_bytes.extend_from_slice(&fq2_be(&s_g2_x));
    params_bytes.extend_from_slice(&fq2_be(&s_g2_y));

    let protocol_bytes = bincode::serialize(&protocol).expect("serialize protocol");
    let mut vk_bytes = Vec::new();
    vk_bytes.extend_from_slice(b"RCH2V1\0\0");
    vk_bytes.extend_from_slice(&(protocol_bytes.len() as u32).to_be_bytes());
    vk_bytes.extend_from_slice(&protocol_bytes);

    let mut instance_bytes = Vec::new();
    instance_bytes.extend_from_slice(b"RCH2I1\0\0");
    instance_bytes.extend_from_slice(&(instance_values.len() as u32).to_be_bytes());
    for column in &instance_values {
        instance_bytes.extend_from_slice(&(column.len() as u32).to_be_bytes());
        for value in column {
            instance_bytes.extend_from_slice(&fr_be(value));
        }
    }

    let output = format!(
        "PARAMS={}\nVK={}\nPROOF={}\nINSTANCES={}\n",
        hex(&params_bytes),
        hex(&vk_bytes),
        hex(&proof),
        hex(&instance_bytes),
    );

    match std::env::args().nth(1) {
        Some(path) => {
            std::fs::write(&path, output.as_bytes())
                .unwrap_or_else(|error| panic!("failed to write fixture {path}: {error}"));
            eprintln!(
                "wrote {path}: params={} vk={} proof={} instances={} bytes",
                params_bytes.len(),
                vk_bytes.len(),
                proof.len(),
                instance_bytes.len(),
            );
        }
        None => print!("{output}"),
    }
}
