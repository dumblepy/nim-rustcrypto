//! Minimal raw-byte IC update adapter for the Halo2 IPA/BN254 v1 verifier.
//!
//! The approving verifying key is pinned **at build time** through
//! `HALO2_IPA_APPROVED_VK`; the module exposes no arbitrary VK, witness,
//! params, or prover entry point.
//!
//! Request: `v1 proof bytes || v1 instances bytes`.
//! Reply: `i32 status LE || u64 verifier instructions LE || u32 memory pages LE`.
//!
//! Lengths are bounded before any allocation: the whole argument is at most
//! 4 MiB (proof transcript) + 1 MiB (instances) and the split point is derived
//! from the proof envelope header after it has been validated.

#[path = "../../../rustcrypto-ffi/src/status.rs"]
mod status;
pub use status::*;
#[path = "../../../rustcrypto-ffi/src/aead_common.rs"]
#[allow(dead_code)]
mod aead_common;
#[path = "../../../rustcrypto-ffi/src/bn254.rs"]
#[allow(dead_code)]
mod bn254;
// The circuit registry decodes circuit id 2 with `Poseidon2HashCircuit`, so
// the verifier compiles the Poseidon2 hash module and its constants. No C ABI
// entry point of those modules is reachable from the canister update.
#[path = "../../../rustcrypto-ffi/src/poseidon2.rs"]
#[allow(dead_code)]
mod poseidon2;
#[path = "../../../rustcrypto-ffi/src/poseidon2_halo2.rs"]
#[allow(dead_code)]
mod poseidon2_halo2;
#[path = "../../../rustcrypto-ffi/src/halo2_ipa.rs"]
#[allow(dead_code)]
mod halo2_ipa;

const APPROVED_VK: &[u8] = include_bytes!(env!("HALO2_IPA_APPROVED_VK"));

/// The verifier must not consume entropy. `halo2-axiom` compiles an unused
/// `AccumulatorStrategy` that names `OsRng`, so `getrandom` must link on
/// wasm32-unknown-unknown. Registering a fail-closed stub keeps the module
/// free of `wasm-bindgen` / Web Crypto imports instead of silently providing
/// entropy to a code path the verifier never uses.
#[cfg(target_arch = "wasm32")]
fn no_entropy(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(no_entropy);

/// Upper bound for the v1 proof transcript (matches `halo2_ipa.rs`).
const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
/// Upper bound for the v1 instances blob (well above the module's 128 KiB).
const MAX_INSTANCES_BYTES: usize = 1024 * 1024;
/// `"RCH2IPF1"` magic + `proof_len u32 BE`.
const PROOF_HEADER_LEN: usize = 12;

#[link(wasm_import_module = "ic0")]
unsafe extern "C" {
    fn msg_arg_data_size() -> i32;
    fn msg_arg_data_copy(dst: i32, offset: i32, size: i32);
    fn msg_reply_data_append(src: i32, size: i32);
    fn msg_reply();
    fn performance_counter(counter: i32) -> i64;
}

#[unsafe(export_name = "canister_update verify")]
pub extern "C" fn verify() {
    let total = unsafe { msg_arg_data_size() };
    let mut status = RUSTCRYPTO_ERR_INVALID_LENGTH;
    let mut instructions = 0u64;

    if total > 0 && (total as usize) <= MAX_PROOF_BYTES + MAX_INSTANCES_BYTES {
        let total = total as usize;
        if total >= PROOF_HEADER_LEN {
            let mut header = [0u8; PROOF_HEADER_LEN];
            unsafe {
                msg_arg_data_copy(header.as_mut_ptr() as i32, 0, PROOF_HEADER_LEN as i32);
            }
            let proof_len =
                u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
            let proof_total = PROOF_HEADER_LEN + proof_len;
            if proof_len > 0 && proof_len <= MAX_PROOF_BYTES && proof_total < total {
                let instances_len = total - proof_total;
                if instances_len <= MAX_INSTANCES_BYTES {
                    let mut input = vec![0u8; total];
                    unsafe {
                        msg_arg_data_copy(input.as_mut_ptr() as i32, 0, total as i32);
                    }
                    let start = unsafe { performance_counter(0) };
                    status = halo2_ipa::rustcrypto_halo2_ipa_bn254_verify(
                        APPROVED_VK.as_ptr(),
                        APPROVED_VK.len(),
                        input.as_ptr(),
                        proof_total,
                        input[proof_total..].as_ptr(),
                        instances_len,
                    );
                    instructions = (unsafe { performance_counter(0) } - start) as u64;
                }
            }
        }
    }

    let mut reply = [0u8; 16];
    reply[..4].copy_from_slice(&status.to_le_bytes());
    reply[4..12].copy_from_slice(&instructions.to_le_bytes());
    reply[12..].copy_from_slice(&(core::arch::wasm32::memory_size(0) as u32).to_le_bytes());
    unsafe {
        msg_reply_data_append(reply.as_ptr() as i32, reply.len() as i32);
        msg_reply();
    }
}
