#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Requirements: wasm-bindgen-cli 0.2.129, Node >= 22, clang with wasm support.
artifacts="$(mktemp -d)"
cd "$repo_root/rustcrypto-ffi"
rustup target add wasm32-unknown-unknown wasm32-wasip1
cargo run --locked --release --example groth16_prover_setup -- "$artifacts"
cargo build --locked --release --example groth16_verify_stdin --target wasm32-wasip1
cargo build --locked --release --manifest-path ../web/groth16-prover/Cargo.toml --target wasm32-unknown-unknown --target-dir target
wasm-bindgen target/wasm32-unknown-unknown/release/groth16_browser.wasm --target web --out-dir ../web/groth16-prover/pkg
cd "$repo_root/web/groth16-prover"
npm ci
npx playwright install chromium
node smoke.cjs "$artifacts" "$repo_root/rustcrypto-ffi/target/wasm32-wasip1/release/examples/groth16_verify_stdin.wasm" "$artifacts/measurements.json"
cd "$repo_root/rustcrypto-ffi"
GROTH16_APPROVED_VK="$artifacts/verifying-key.bin" cargo build --locked --release --manifest-path ../examples/groth16-ic-verifier/Cargo.toml --target wasm32-unknown-unknown --target-dir target
cd "$repo_root/web/groth16-prover"
node ic-smoke.cjs "$artifacts" "$repo_root/rustcrypto-ffi/target/wasm32-unknown-unknown/release/groth16_ic_verifier.wasm"
echo "Development artifacts and measurements: $artifacts"
