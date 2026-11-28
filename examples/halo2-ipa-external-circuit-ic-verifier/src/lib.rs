//! Verify-only ICP canister for the external Halo2 IPA / BN254 `ChainCircuit`
//! (circuit id `0x10001`, 17 public values).
//!
//! # What is verified
//!
//! The verifying key is pinned **at build time** through
//! `HALO2_IPA_EXTERNAL_APPROVED_VK`:
//!
//! ```text
//! const APPROVED_VK: &[u8] = include_bytes!(env!("HALO2_IPA_EXTERNAL_APPROVED_VK"));
//! ```
//!
//! It must be the V2-magic (`RCH2IPV2`) VK extracted from
//! `tests/fixtures/halo2_ipa_external_chain_v1.hex`. The canister checks the
//! pinned header (magic, circuit id `0x10001`, `k` in the profile range) on
//! every call, so a V1-magic or wrong-circuit key can never be used.
//!
//! There is **no** arbitrary-VK, witness, params, prover, or RNG entry point.
//! The canister imports only `ic0` functions and does not use threads, the
//! filesystem, the clock, or the network.
//!
//! # Reusing the external circuit
//!
//! The example crate `examples/halo2-ipa-external-circuit` is a real Cargo
//! path dependency with its `verify-only` feature enabled:
//!
//! ```toml
//! halo2-ipa-external-circuit = { path = "../halo2-ipa-external-circuit", features = ["verify-only"] }
//! ```
//!
//! `verify-only` makes the example crate expand
//! [`halo2_ipa_export_circuit_verifier!`](rust_crypto_ffi::halo2_ipa_export_circuit_verifier)
//! instead of the full prepare/prove adapter and enables
//! `rustcrypto-ffi/halo2-ipa-verify-only` through feature unification. There is
//! no source copy and no rewritten example source: the `ChainCircuit` type
//! compiled into this canister is exactly the crate's own type. The canister
//! calls
//! [`halo2_ipa_registry::verify::<ChainCircuit>`](rust_crypto_ffi::halo2_ipa_registry::verify)
//! directly.
//!
//! # Link step
//!
//! This crate builds a `staticlib`, not a `cdylib`. `rustcrypto-ffi` exposes
//! many `#[no_mangle]` C ABI functions; rustc's `cdylib` linker additionally
//! exports every one of them, which would keep prover and unrelated crypto
//! code in the module. [`link-canister.sh`](../../link-canister.sh) links the
//! archive with an explicit two-symbol export list and `--gc-sections`, so the
//! final wasm exports only `canister_update verify` and
//! `rustcrypto_halo2_ipa_external_chain_verify`, and imports only `ic0`.
//!
//! # Wire format
//!
//! ```text
//! request:  v1 proof bytes || v1 instances bytes
//! proof:    "RCH2IPF1" | proof_len u32 BE | transcript
//! instances:"RCH2IPI1" | 1 column | 17 values of 32-byte canonical BE Fr
//! reply:    i32 status LE | u64 verifier instructions LE | u32 pages LE
//! ```
//!
//! The proof/instances split is derived from the validated proof envelope
//! header. The whole argument must fit within `2 MiB` proof + `1 MiB`
//! instances + `12` header bytes; larger calls are rejected with
//! `INVALID_LENGTH` before `msg_arg_data_copy`.
//!
//! `status == 0` only on success. Tampered proofs, wrong instances, V1-magic
//! key/proof encodings, wrong circuit ids, non-canonical field elements,
//! trailing bytes, and oversized inputs return the non-zero status constants
//! from [`rust_crypto_ffi`].

use core::ffi::c_int;

use halo2_ipa_external_circuit::ChainCircuit;
use rust_crypto_ffi::halo2_ipa::{
    HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS, HALO2_IPA_BN254_MAX_INSTANCE_VALUES,
    HALO2_IPA_BN254_VK_V2_MAGIC,
};
use rust_crypto_ffi::halo2_ipa_registry::{verify, ApprovedCircuit};
use rust_crypto_ffi::{
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY, RUSTCRYPTO_OK,
};

/// Pinned V2 verifying key, provided at build time.
const APPROVED_VK: &[u8] = include_bytes!(env!("HALO2_IPA_EXTERNAL_APPROVED_VK"));

/// `"RCH2IPV2"` magic (8) + circuit id (4) + `k` (4) + payload length (4).
/// Mirrors `rustcrypto-ffi`'s private `VK_HEADER_LEN`.
const VK_HEADER_LEN: usize = 20;

/// Upper bound for the v1 proof transcript (matches the `ChainCircuit` profile).
const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
/// Upper bound for the v1 instances blob. Mirrors `rustcrypto-ffi`'s private
/// `MAX_INSTANCES_BLOB_LEN` so this pre-copy guard accepts exactly what the
/// registry verifier accepts. The circuit uses 560 bytes.
const MAX_INSTANCES_BYTES: usize = 8
    + 4
    + HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS * 4
    + HALO2_IPA_BN254_MAX_INSTANCE_VALUES * 32;
/// `"RCH2IPF1"` magic + `proof_len u32 BE`.
const PROOF_HEADER_LEN: usize = 12;

const _: () = assert!(PROOF_HEADER_LEN + 8 <= MAX_PROOF_BYTES);

/// The verifier must not consume entropy. `halo2-axiom` compiles an unused
/// `AccumulatorStrategy` that names `OsRng`, so `getrandom` must link on
/// wasm32-unknown-unknown. A fail-closed stub keeps the module free of
/// `wasm-bindgen` / Web Crypto imports.
#[cfg(target_arch = "wasm32")]
fn no_entropy(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(no_entropy);

#[link(wasm_import_module = "ic0")]
unsafe extern "C" {
    fn msg_arg_data_size() -> i32;
    fn msg_arg_data_copy(dst: i32, offset: i32, size: i32);
    fn msg_reply_data_append(src: i32, size: i32);
    fn msg_reply();
    fn performance_counter(counter: i32) -> i64;
}

/// Validates the compile-time pinned VK header before any proof is read.
///
/// This rejects V1-magic keys, a wrong circuit id, a `k` outside the profile
/// range, and a payload length that does not match the envelope.
fn pinned_vk_status() -> c_int {
    if APPROVED_VK.len() < VK_HEADER_LEN || &APPROVED_VK[..8] != HALO2_IPA_BN254_VK_V2_MAGIC {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    let profile = ChainCircuit::profile();
    let circuit_id = u32::from_be_bytes([
        APPROVED_VK[8],
        APPROVED_VK[9],
        APPROVED_VK[10],
        APPROVED_VK[11],
    ]);
    let k = u32::from_be_bytes([
        APPROVED_VK[12],
        APPROVED_VK[13],
        APPROVED_VK[14],
        APPROVED_VK[15],
    ]);
    let vk_len = u32::from_be_bytes([
        APPROVED_VK[16],
        APPROVED_VK[17],
        APPROVED_VK[18],
        APPROVED_VK[19],
    ]) as usize;
    if circuit_id != profile.circuit_id
        || !(profile.min_k..=profile.max_k).contains(&k)
        || vk_len != APPROVED_VK.len() - VK_HEADER_LEN
    {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    RUSTCRYPTO_OK
}

/// Decodes the proof/instances split from the proof envelope header.
fn split_argument(total: usize) -> Option<(usize, usize)> {
    if total < PROOF_HEADER_LEN {
        return None;
    }
    let mut header = [0u8; PROOF_HEADER_LEN];
    // The caller has already checked that `total` fits the canister guard.
    unsafe {
        msg_arg_data_copy(header.as_mut_ptr() as i32, 0, PROOF_HEADER_LEN as i32);
    }
    if &header[..8] != b"RCH2IPF1" {
        return None;
    }
    let proof_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if proof_len == 0 || proof_len > MAX_PROOF_BYTES {
        return None;
    }
    let proof_total = PROOF_HEADER_LEN.checked_add(proof_len)?;
    if proof_total >= total {
        return None;
    }
    let instances_len = total - proof_total;
    if instances_len > MAX_INSTANCES_BYTES {
        return None;
    }
    Some((proof_total, instances_len))
}

fn memory_pages() -> u32 {
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::memory_size(0) as u32
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

/// Raw update entry point. Takes `v1 proof bytes || v1 instances bytes`.
#[unsafe(export_name = "canister_update verify")]
pub extern "C" fn verify_update() {
    let total = unsafe { msg_arg_data_size() };
    let max_argument = MAX_PROOF_BYTES + MAX_INSTANCES_BYTES + PROOF_HEADER_LEN;
    let mut status = RUSTCRYPTO_ERR_INVALID_LENGTH;
    let mut instructions = 0u64;

    if total > 0 && (total as usize) <= max_argument {
        let total = total as usize;
        if let Some((proof_total, instances_len)) = split_argument(total) {
            // The pinned key is checked before the proof bytes are copied or
            // decoded, even though it is a compile-time constant.
            status = pinned_vk_status();
            if status == RUSTCRYPTO_OK {
                let mut input = vec![0u8; total];
                unsafe {
                    msg_arg_data_copy(input.as_mut_ptr() as i32, 0, total as i32);
                }
                let start = unsafe { performance_counter(0) };
                status = match verify::<ChainCircuit>(
                    APPROVED_VK,
                    &input[..proof_total],
                    &input[proof_total..proof_total + instances_len],
                ) {
                    Ok(()) => RUSTCRYPTO_OK,
                    Err(error) => error,
                };
                instructions = (unsafe { performance_counter(0) } - start) as u64;
            }
        } else {
            status = RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT;
        }
    }

    let mut reply = [0u8; 16];
    reply[..4].copy_from_slice(&status.to_le_bytes());
    reply[4..12].copy_from_slice(&instructions.to_le_bytes());
    reply[12..].copy_from_slice(&memory_pages().to_le_bytes());
    unsafe {
        msg_reply_data_append(reply.as_ptr() as i32, reply.len() as i32);
        msg_reply();
    }
}

/// C ABI verifier that uses only the pinned VK. It accepts no key material, so
/// a static-link consumer can call it without being able to substitute a VK.
///
/// Returns `RUSTCRYPTO_OK` on success or a non-zero status code.
#[unsafe(export_name = "rustcrypto_halo2_ipa_external_chain_verify")]
pub extern "C" fn verify_pinned(
    proof_ptr: *const u8,
    proof_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    if pinned_vk_status() != RUSTCRYPTO_OK {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    rust_crypto_ffi::halo2_ipa_registry::ffi_verify::<ChainCircuit>(
        APPROVED_VK.as_ptr(),
        APPROVED_VK.len(),
        proof_ptr,
        proof_len,
        instances_ptr,
        instances_len,
    )
}
