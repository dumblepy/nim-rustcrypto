//! `wasm32-unknown-unknown` entry point for the Halo2 IPA/BN254 v1 fixture
//! smoke test.
//!
//! Reuses the native example's panic-free check set through a module include so
//! both runtimes exercise identical assertions. The exported `extern "C"`
//! function returns 0 on success or a bit mask describing the failed checks.
//!
//! Note: `rustcrypto-ffi/Cargo.toml` is owned by another change and does not
//! declare a `crate-type = ["cdylib"]` entry for this example. Cargo therefore
//! builds it as a wasm bin target, which still exports the `#[unsafe(no_mangle)]`
//! function below (plus `memory`) and is instantiated by
//! `ci/halo2_ipa_wasm_smoke.mjs` without running `main`.

#[allow(dead_code)]
#[path = "halo2_ipa_verify.rs"]
mod fixture_smoke;

fn main() {}

#[unsafe(no_mangle)]
pub extern "C" fn halo2_ipa_verify_fixture() -> i32 {
    fixture_smoke::smoke()
}
