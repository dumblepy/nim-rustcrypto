#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Requirements: wasm-bindgen-cli 0.2.129, Node >= 22, clang with wasm support.
artifacts="$(mktemp -d)"
cd "$repo_root/rustcrypto-ffi"
cargo_target_dir="${CARGO_TARGET_DIR:-$repo_root/rustcrypto-ffi/target}"
mkdir -p "$cargo_target_dir"
export CARGO_TARGET_DIR="$(cd "$cargo_target_dir" && pwd)"
if [[ "${ZKP_RUST_WASM_TARGETS_INSTALLED:-0}" != "1" ]]; then
  rustup target add wasm32-unknown-unknown wasm32-wasip1
fi
cargo run --locked --release --example groth16_prover_setup -- "$artifacts"
cargo build --locked --release --example groth16_verify_stdin --target wasm32-wasip1
cargo build --locked --release --manifest-path ../web/groth16-prover/Cargo.toml --target wasm32-unknown-unknown
wasm-bindgen "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/groth16_browser.wasm" --target web --out-dir ../web/groth16-prover/pkg
cd "$repo_root/web/groth16-prover"
if [[ "${GROTH16_BROWSER_DEPS_INSTALLED:-0}" != "1" ]]; then
  npm ci
  npx playwright install chromium
fi
node smoke.cjs "$artifacts" "$CARGO_TARGET_DIR/wasm32-wasip1/release/examples/groth16_verify_stdin.wasm" "$artifacts/measurements.json"
cd "$repo_root/rustcrypto-ffi"
GROTH16_APPROVED_VK="$artifacts/verifying-key.bin" cargo build --locked --release --manifest-path ../examples/groth16-ic-verifier/Cargo.toml --target wasm32-unknown-unknown
cd "$repo_root/web/groth16-prover"
node ic-smoke.cjs "$artifacts" "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/groth16_ic_verifier.wasm"
echo "Development artifacts and measurements: $artifacts"
