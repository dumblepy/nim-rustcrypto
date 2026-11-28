//! Minimal raw-byte IC update adapter for the Poseidon2/BN254 hash.
//!
//! Request: `count * 32` bytes, where `count` is `0..=12` canonical
//! big-endian BN254 `Fr` values (no implicit modulo reduction).
//! Reply: `i32 status LE || u64 instructions LE || u32 memory pages LE || digest (32)`.
//!
//! The argument length is bounded before any allocation. No RNG, filesystem,
//! clock, or thread is used.

#[path = "../../../rustcrypto-ffi/src/status.rs"]
mod status;
pub use status::*;
#[path = "../../../rustcrypto-ffi/src/aead_common.rs"]
#[allow(dead_code)]
mod aead_common;
#[path = "../../../rustcrypto-ffi/src/bn254.rs"]
#[allow(dead_code)]
mod bn254;
#[path = "../../../rustcrypto-ffi/src/poseidon2.rs"]
#[allow(dead_code)]
mod poseidon2;

/// Maximum accepted input count, matching `poseidon2.rs`.
const MAX_INPUTS: usize = 12;
const FR_BYTES: usize = 32;
const MAX_INPUT_BYTES: usize = MAX_INPUTS * FR_BYTES;
const REPLY_LEN: usize = 4 + 8 + 4 + FR_BYTES;

#[link(wasm_import_module = "ic0")]
unsafe extern "C" {
    fn msg_arg_data_size() -> i32;
    fn msg_arg_data_copy(dst: i32, offset: i32, size: i32);
    fn msg_reply_data_append(src: i32, size: i32);
    fn msg_reply();
    fn performance_counter(counter: i32) -> i64;
}

#[unsafe(export_name = "canister_update hash")]
pub extern "C" fn hash() {
    let length = unsafe { msg_arg_data_size() };
    let mut status = RUSTCRYPTO_ERR_INVALID_LENGTH;
    let mut instructions = 0u64;
    let mut digest = [0u8; FR_BYTES];

    if length >= 0 {
        let length = length as usize;
        if length <= MAX_INPUT_BYTES && length % FR_BYTES == 0 {
            let mut input = vec![0u8; length];
            if length > 0 {
                unsafe {
                    msg_arg_data_copy(input.as_mut_ptr() as i32, 0, length as i32);
                }
            }
            let input_ptr = if input.is_empty() {
                core::ptr::null()
            } else {
                input.as_ptr()
            };
            let start = unsafe { performance_counter(0) };
            status = poseidon2::rustcrypto_poseidon2_bn254_hash(
                input_ptr,
                input.len(),
                input.len() / FR_BYTES,
                digest.as_mut_ptr(),
                digest.len(),
            );
            instructions = (unsafe { performance_counter(0) } - start) as u64;
        }
    }

    let mut reply = [0u8; REPLY_LEN];
    reply[..4].copy_from_slice(&status.to_le_bytes());
    reply[4..12].copy_from_slice(&instructions.to_le_bytes());
    reply[12..16].copy_from_slice(&(core::arch::wasm32::memory_size(0) as u32).to_le_bytes());
    reply[16..].copy_from_slice(&digest);
    unsafe {
        msg_reply_data_append(reply.as_ptr() as i32, reply.len() as i32);
        msg_reply();
    }
}
