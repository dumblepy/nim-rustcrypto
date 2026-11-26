//! `wasm32-unknown-unknown` entry point for the Halo2 v1 fixture smoke test.
//!
//! Built as a cdylib and called from `ci/halo2_wasm_smoke.mjs`. Returns 0 on
//! success or a bit mask describing the failed check.

mod support {
    pub mod halo2_fixture;
}

#[unsafe(no_mangle)]
pub extern "C" fn halo2_verify_fixture() -> i32 {
    support::halo2_fixture::smoke()
}
