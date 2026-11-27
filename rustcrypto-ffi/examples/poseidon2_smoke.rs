//! Poseidon2/BN254 smoke test for native and `wasm32-wasip1` runtimes.
//!
//! Calls the same C ABI entry points that the Nim wrapper links against, so a
//! successful run exercises the archived implementation instead of only
//! compiling it.
//!
//! Usage: `cargo run --locked --release --example poseidon2_smoke`

use rust_crypto_ffi::poseidon2::{
    rustcrypto_poseidon2_bn254_hash, rustcrypto_poseidon2_bn254_permute,
};

/// Permutation KAT for the all-zero width-4 state.
const PERMUTATION_ZERO_KAT: [&str; 4] = [
    "18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e",
    "095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839",
    "0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59",
    "18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d",
];

/// Noir/Barretenberg sponge KAT for `[Fr(1), Fr(2), Fr(3)]`.
const HASH_N3_KAT: &str = "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8";

fn decode_hex32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex digit in {hex}"))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex digit in {hex}"))?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn check() -> Result<(), String> {
    let state = [0u8; 128];
    let mut permuted = [0u8; 128];
    let status = rustcrypto_poseidon2_bn254_permute(
        state.as_ptr(),
        state.len(),
        permuted.as_mut_ptr(),
        permuted.len(),
    );
    if status != 0 {
        return Err(format!("permute returned status {status}"));
    }
    for (index, expected) in PERMUTATION_ZERO_KAT.iter().enumerate() {
        let expected = decode_hex32(expected)?;
        let actual = &permuted[index * 32..(index + 1) * 32];
        if actual != expected {
            return Err(format!(
                "permutation KAT mismatch at index {index}: got {}",
                actual
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ));
        }
    }

    // Fr(1), Fr(2), Fr(3) as canonical 32-byte big-endian values.
    let mut inputs = [0u8; 96];
    inputs[31] = 1;
    inputs[63] = 2;
    inputs[95] = 3;
    let mut digest = [0u8; 32];
    let status = rustcrypto_poseidon2_bn254_hash(
        inputs.as_ptr(),
        inputs.len(),
        3,
        digest.as_mut_ptr(),
        digest.len(),
    );
    if status != 0 {
        return Err(format!("hash returned status {status}"));
    }
    if digest != decode_hex32(HASH_N3_KAT)? {
        return Err(format!(
            "hash n=3 KAT mismatch: got {}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
    }

    Ok(())
}

fn main() {
    match check() {
        Ok(()) => println!("poseidon2 smoke: ok"),
        Err(message) => {
            eprintln!("poseidon2 smoke: {message}");
            std::process::exit(1);
        }
    }
}
