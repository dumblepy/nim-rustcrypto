//! Minimal raw-byte IC update adapter. VK approval occurs at build time.
//! Request: 256-byte proof || ordered canonical BE Fr public inputs.
//! Reply: i32 status LE || u64 verifier instruction count LE || u32 memory pages LE.
//! No arbitrary user-supplied VK, witness, setup, or prover endpoint is exposed.
#[path = "../../../rustcrypto-ffi/src/status.rs"]
mod status;
pub use status::*;
#[path = "../../../rustcrypto-ffi/src/aead_common.rs"]
mod aead_common;
#[allow(dead_code)]
#[path = "../../../rustcrypto-ffi/src/bn254.rs"]
mod bn254;
#[allow(dead_code)]
#[path = "../../../rustcrypto-ffi/src/groth16.rs"]
mod groth16;
const APPROVED_VK: &[u8] = include_bytes!(env!("GROTH16_APPROVED_VK"));
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
    let length = unsafe { msg_arg_data_size() };
    let mut reply = [0u8; 16];
    let mut status = 9i32;
    let mut instructions = 0u64;
    if length >= 256 && length <= 256 + 256 * 32 && (length - 256) % 32 == 0 {
        let mut input = vec![0u8; length as usize];
        unsafe {
            msg_arg_data_copy(input.as_mut_ptr() as i32, 0, length);
        }
        let start = unsafe { performance_counter(0) };
        status = groth16::rustcrypto_groth16_bn254_verify(
            APPROVED_VK.as_ptr(),
            APPROVED_VK.len(),
            input.as_ptr(),
            256,
            input[256..].as_ptr(),
            input.len() - 256,
            (input.len() - 256) / 32,
        );
        instructions = (unsafe { performance_counter(0) } - start) as u64;
    }
    reply[..4].copy_from_slice(&status.to_le_bytes());
    reply[4..12].copy_from_slice(&instructions.to_le_bytes());
    reply[12..].copy_from_slice(&(core::arch::wasm32::memory_size(0) as u32).to_le_bytes());
    unsafe {
        msg_reply_data_append(reply.as_ptr() as i32, reply.len() as i32);
        msg_reply();
    }
}
