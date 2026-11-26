//! Halo2 KZG/BN254 v1 fixture smoke test for native and wasm32-wasip1.
//!
//! Usage: `cargo run --example halo2_verify`
//!
//! Calls the same C ABI that the Nim wrapper uses, so a successful run under a
//! wasm runtime exercises the archive's Halo2 code path (not just compilation).

mod support {
    pub mod halo2_fixture;
}

fn main() {
    let failures = support::halo2_fixture::smoke();
    assert_eq!(
        failures, 0,
        "halo2 fixture smoke failed: bits {failures:#b}"
    );
    println!("halo2 kzg bn254 fixture smoke: ok");
}
