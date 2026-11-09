//! WASI/ICP-facing verifier example: stdin is VK hex, proof hex, public inputs hex.
//! This only validates the proof for that VK; a canister must pin an approved VK.
use std::io::{self, Read};
fn decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn main() {
    let mut text = String::new();
    io::stdin().take(600_000).read_to_string(&mut text).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    let vk = decode(lines[0]);
    let proof = decode(lines[1]);
    let inputs = decode(lines[2]);
    assert!(inputs.len().is_multiple_of(32));
    // Link and execute the production verifier, without a parallel implementation.
    let status = rust_crypto_ffi::groth16_prover::verify_v1(&vk, &proof, &inputs);
    if status != 0 {
        eprintln!("verification failed: {status}");
        std::process::exit(1);
    }
    println!("verified");
}
