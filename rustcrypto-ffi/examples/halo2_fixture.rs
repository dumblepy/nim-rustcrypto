//! Deterministic Halo2 (PSE/Axiom KZG/BN254, SHPLONK, Blake2b) fixture generator.
//!
//! Usage: `cargo run --example halo2_fixture`
//!
//! Uses `ParamsKZG::setup(8, seeded_rng)`. The SRS is **insecure and test-only**.

use snark_verifier::halo2_base::halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fq2, Fr, G1Affine};
use snark_verifier::halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use snark_verifier::halo2_base::halo2_proofs::halo2curves::CurveAffineExt;
use snark_verifier::halo2_base::halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Instance, create_proof, keygen_pk, keygen_vk,
};
use snark_verifier::halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use snark_verifier::halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use snark_verifier::halo2_base::halo2_proofs::poly::kzg::multiopen::ProverSHPLONK;
use snark_verifier::halo2_base::halo2_proofs::transcript::{
    Blake2bWrite, Challenge255, TranscriptWriterBuffer,
};
use snark_verifier::system::halo2::{compile, Config};
use rand::SeedableRng;

const K: u32 = 8;

#[derive(Clone)]
struct TestCircuit {
    value: Value<Fr>,
    public: Fr,
}

impl Circuit<Fr> for TestCircuit {
    type Config = (Column<Advice>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            public: self.public,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(advice);
        meta.enable_equality(instance);
        (advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let cell = layouter.assign_region(
            || "value",
            |mut region| Ok(region.assign_advice(config.0, 0, self.value)),
        )?;
        layouter.constrain_instance(cell.cell(), config.1, 0);
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
    let mut setup_rng = rand::rngs::StdRng::seed_from_u64(7);
    let params = ParamsKZG::<Bn256>::setup(K, &mut setup_rng);

    let circuit = TestCircuit {
        value: Value::known(Fr::from(42u64)),
        public: Fr::from(42u64),
    };
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
    let protocol = compile(
        &params,
        &vk,
        Config::kzg().with_num_instance(vec![1]),
    );

    let public = Fr::from(42u64);
    let instance_values = vec![vec![public]];
    let instance_refs: Vec<&[Fr]> = instance_values.iter().map(|column| column.as_slice()).collect();
    let proof_instances: Vec<&[&[Fr]]> = vec![instance_refs.as_slice()];

    let proof_rng = rand::rngs::StdRng::seed_from_u64(11);
    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, Challenge255<G1Affine>, _, _, TestCircuit>(
        &params,
        &pk,
        &[circuit],
        &proof_instances,
        proof_rng,
        &mut transcript,
    )
    .unwrap();
    let proof = transcript.finalize();

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

    let protocol_bytes = bincode::serialize(&protocol).unwrap();
    let mut vk_bytes = Vec::new();
    vk_bytes.extend_from_slice(b"RCH2V1\0\0");
    vk_bytes.extend_from_slice(&(protocol_bytes.len() as u32).to_be_bytes());
    vk_bytes.extend_from_slice(&protocol_bytes);

    let mut instance_bytes = Vec::new();
    instance_bytes.extend_from_slice(b"RCH2I1\0\0");
    instance_bytes.extend_from_slice(&1u32.to_be_bytes());
    instance_bytes.extend_from_slice(&1u32.to_be_bytes());
    instance_bytes.extend_from_slice(&fr_be(&public));

    println!("PARAMS={}", hex(&params_bytes));
    println!("VK={}", hex(&vk_bytes));
    println!("PROOF={}", hex(&proof));
    println!("INSTANCES={}", hex(&instance_bytes));
}
