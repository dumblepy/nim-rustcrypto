//! Measures the fixed square demo with an externally generated development PK.
use rand_core::RngCore;
use rust_crypto_ffi::groth16_prover::{Circuit, ProverRng, prove, verify_v1};
fn main() {
    let dir = std::env::args().nth(1).expect("artifact directory");
    let read = |name: &str| std::fs::read(std::path::Path::new(&dir).join(name)).unwrap();
    let circuit = Circuit::from_bytes(&read("circuit.bin")).unwrap();
    let pk = read("proving-key.bin");
    let vk = read("verifying-key.bin");
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    rand_core::OsRng.try_fill_bytes(seed.as_mut()).unwrap();
    let mut rng = ProverRng::from_entropy(&seed);
    let mut inputs = [0u8; 32];
    inputs[31] = 9;
    let mut witness = zeroize::Zeroizing::new([0u8; 32]);
    witness[31] = 3;
    let start = std::time::Instant::now();
    let proof = prove(&circuit, &pk, &inputs, witness.as_ref(), &mut rng).unwrap();
    let ms = start.elapsed().as_secs_f64() * 1000.;
    assert_eq!(verify_v1(&vk, &proof, &inputs), 0);
    assert!(ms < 30000.);
    println!(
        "{{\"nativeProveMs\":{ms},\"keyBytes\":{},\"proofBytes\":{}}}",
        pk.len(),
        proof.len()
    );
}
