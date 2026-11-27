//! `wasm32-unknown-unknown` cdylib smoke test for the Poseidon2/BN254 C ABI.
//!
//! Built as a cdylib and called from `ci/poseidon2_wasm_smoke.mjs`. It declares
//! the two exported C ABI functions and is linked against the same
//! `librust_crypto_ffi.a` archive that the Nim wrapper links, so the compiled
//! module contains only the Poseidon2 code path and imports no host functions.
//!
//! Returns 0 on success, or a bit mask describing the failed check.
//!
//! `Cargo.toml` is owned by another task and has no `[[example]]` entry that
//! marks this file as a cdylib, so `cargo test` would otherwise try to build it
//! as a binary. A no-op `main` is provided for non-wasm host builds; the wasm32
//! build is compiled as a cdylib by `ci/test_poseidon2_wasm.sh`.

#[cfg(target_arch = "wasm32")]
unsafe extern "C" {
    fn rustcrypto_poseidon2_bn254_permute(
        state: *const u8,
        state_len: usize,
        output: *mut u8,
        output_len: usize,
    ) -> i32;
    fn rustcrypto_poseidon2_bn254_hash(
        inputs: *const u8,
        inputs_len: usize,
        input_count: usize,
        output: *mut u8,
        output_len: usize,
    ) -> i32;
}

#[cfg(target_arch = "wasm32")]
/// Permutation KAT for the all-zero width-4 state.
const PERMUTATION_ZERO_KAT: [&str; 4] = [
    "18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e",
    "095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839",
    "0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59",
    "18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d",
];

#[cfg(target_arch = "wasm32")]
/// Noir/Barretenberg sponge KAT for `[Fr(1), Fr(2), Fr(3)]`.
const HASH_N3_KAT: &str = "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8";

#[cfg(target_arch = "wasm32")]
/// Decodes 64 hex characters into 32 bytes. Returns `None` on malformed input.
const fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_digit(bytes[2 * i]);
        let lo = hex_digit(bytes[2 * i + 1]);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out[i] = (hi << 4) | lo,
            _ => return None,
        }
        i += 1;
    }
    Some(out)
}

#[cfg(target_arch = "wasm32")]
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn check() -> i32 {
    let mut failures = 0;

    let state = [0u8; 128];
    let mut permuted = [0u8; 128];
    // SAFETY: both buffers are 128 bytes and owned by this stack frame.
    let status = unsafe {
        rustcrypto_poseidon2_bn254_permute(
            state.as_ptr(),
            state.len(),
            permuted.as_mut_ptr(),
            permuted.len(),
        )
    };
    if status != 0 {
        failures |= 1;
    } else {
        for (index, expected) in PERMUTATION_ZERO_KAT.iter().enumerate() {
            let Some(expected) = decode_hex32(expected) else {
                failures |= 2;
                continue;
            };
            if permuted[index * 32..(index + 1) * 32] != expected {
                failures |= 2;
            }
        }
    }

    // Fr(1), Fr(2), Fr(3) as canonical 32-byte big-endian values.
    let mut inputs = [0u8; 96];
    inputs[31] = 1;
    inputs[63] = 2;
    inputs[95] = 3;
    let mut digest = [0u8; 32];
    // SAFETY: `inputs` is 96 bytes (3 * 32) and `digest` is 32 bytes.
    let status = unsafe {
        rustcrypto_poseidon2_bn254_hash(
            inputs.as_ptr(),
            inputs.len(),
            3,
            digest.as_mut_ptr(),
            digest.len(),
        )
    };
    if status != 0 {
        failures |= 4;
    } else if decode_hex32(HASH_N3_KAT) != Some(digest) {
        failures |= 8;
    }

    failures
}

#[cfg(target_arch = "wasm32")]
/// Returns 0 when the permutation and hash KATs match, a non-zero bit mask
/// otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn poseidon2_smoke() -> i32 {
    check()
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {}
