//! Native C ABI for the circuit-bound proving core.
use crate::groth16_prover::{
    Circuit, MAX_CIRCUIT_BYTES, MAX_INPUTS, MAX_KEY_BYTES, ProverRng, Result, prove, setup,
};
const INVALID: i32 = crate::RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA;
/// Host randomness callback: fill the entire requested buffer, return 0 on success.
/// Must use OS getrandom / Web Crypto; deterministic callbacks are only for tests.
pub type RandomCallback = unsafe extern "C" fn(*mut u8, usize) -> i32;
fn host_rng(callback: Option<RandomCallback>) -> Result<ProverRng> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    let callback = callback.ok_or(crate::RUSTCRYPTO_ERR_RANDOM_FAILED)?;
    if unsafe { callback(seed.as_mut_ptr(), 32) } != 0 {
        return Err(crate::RUSTCRYPTO_ERR_RANDOM_FAILED);
    }
    Ok(ProverRng::from_entropy(&seed))
}
fn ffi_result(f: impl FnOnce() -> Result<()>) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .map_or(crate::RUSTCRYPTO_ERR_PANIC, |r| r.err().unwrap_or(0))
}
/// All input and output buffers must be valid and non-overlapping. No ownership transfer.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_groth16_bn254_prove(
    circuit: *const u8,
    circuit_len: usize,
    key: *const u8,
    key_len: usize,
    public: *const u8,
    public_len: usize,
    private: *const u8,
    private_len: usize,
    random: Option<RandomCallback>,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    ffi_result(|| {
        if circuit_len > MAX_CIRCUIT_BYTES
            || key_len > MAX_KEY_BYTES
            || public_len > MAX_INPUTS * 32
            || private_len > MAX_INPUTS * 32
        {
            return Err(INVALID);
        }
        let definition =
            Circuit::from_bytes(crate::aead_common::optional_input(circuit, circuit_len)?)?;
        let key = crate::aead_common::optional_input(key, key_len)?;
        let public = crate::aead_common::optional_input(public, public_len)?;
        let private = crate::aead_common::optional_input(private, private_len)?;
        let output = crate::aead_common::output_buffer(output, output_len, 256)?;
        let proof = prove(&definition, key, public, private, &mut host_rng(random)?)?;
        output.copy_from_slice(&proof);
        Ok(())
    })
}
/// Setup writes caller-owned PK/VK buffers and lengths. Insufficient capacity returns 2.
/// Length pointers must be valid; caller may retry with returned capacities (fresh setup).
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_groth16_bn254_setup(
    circuit: *const u8,
    circuit_len: usize,
    random: Option<RandomCallback>,
    key: *mut u8,
    key_cap: usize,
    key_len: *mut usize,
    vk: *mut u8,
    vk_cap: usize,
    vk_len: *mut usize,
) -> i32 {
    ffi_result(|| {
        if key_len.is_null() || vk_len.is_null() {
            return Err(crate::RUSTCRYPTO_ERR_NULL_OUTPUT);
        }
        if circuit_len > MAX_CIRCUIT_BYTES {
            return Err(INVALID);
        }
        let definition =
            Circuit::from_bytes(crate::aead_common::optional_input(circuit, circuit_len)?)?;
        let (pk, vk_bytes) = setup(&definition, &mut host_rng(random)?)?;
        unsafe {
            *key_len = pk.len();
            *vk_len = vk_bytes.len();
        }
        let key_out = crate::aead_common::output_buffer(key, key_cap, pk.len())?;
        let vk_out = crate::aead_common::output_buffer(vk, vk_cap, vk_bytes.len())?;
        key_out.copy_from_slice(&pk);
        vk_out.copy_from_slice(&vk_bytes);
        Ok(())
    })
}
