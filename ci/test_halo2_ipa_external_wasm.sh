#!/usr/bin/env bash
# External Halo2 IPA/BN254 circuit (ChainCircuit) browser Web Worker smoke.
#
# Builds the standalone wasm-bindgen adapter for the external
# `examples/halo2-ipa-external-circuit-wasm` (which depends on the external
# circuit crate by path and calls the compile-time registry API), runs
# `wasm-bindgen --target web`, and drives headless Chromium through a plain
# HTTP origin without COOP/COEP. The prover runs in a module Worker under
# `crossOriginIsolated === false`; the main thread verifies. The smoke also
# re-verifies the worker proof and the committed native fixture in Node's own
# wasm instance. A build success alone is not a pass.
#
# Usage: bash ci/test_halo2_ipa_external_wasm.sh [artifact-dir]
# Environment: CARGO_TARGET_DIR, ZKP_RUST_WASM_TARGETS_INSTALLED=1.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${1:-$(mktemp -d)}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
web_dir="$repo_root/web/halo2-ipa-external-circuit"
manifest="$repo_root/examples/halo2-ipa-external-circuit-wasm/Cargo.toml"

cargo_target_dir="${CARGO_TARGET_DIR:-$web_dir/target}"
mkdir -p "$cargo_target_dir"
export CARGO_TARGET_DIR="$(cd "$cargo_target_dir" && pwd)"
echo "External Halo2 IPA web artifacts: $artifacts"
echo "CARGO_TARGET_DIR: $CARGO_TARGET_DIR"

if [[ "${ZKP_RUST_WASM_TARGETS_INSTALLED:-0}" != "1" ]]; then
  rustup target add wasm32-unknown-unknown
fi

if [[ ! -d "$repo_root/web/groth16-prover/node_modules/playwright" ]]; then
  echo "Playwright is required. Run: (cd web/groth16-prover && npm ci && npx playwright install chromium)" >&2
  exit 1
fi

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "wasm-bindgen CLI 0.2.129 is required (cargo install wasm-bindgen-cli --version 0.2.129)" >&2
  exit 1
fi
wasm_bindgen_version="$(wasm-bindgen --version | awk '{print $2}')"
if [[ "$wasm_bindgen_version" != "0.2.129" ]]; then
  echo "warning: wasm-bindgen CLI is $wasm_bindgen_version, crate pins =0.2.129" >&2
fi

cd "$repo_root"
echo "==> Build external ChainCircuit wasm32-unknown-unknown adapter"
cargo build --locked --release --manifest-path "$manifest" --target wasm32-unknown-unknown

wasm="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/halo2_ipa_external_circuit_wasm.wasm"
[[ -s "$wasm" ]] || { echo "missing wasm: $wasm" >&2; exit 1; }

echo "==> wasm-bindgen --target web"
rm -rf "$web_dir/pkg"
wasm-bindgen "$wasm" \
  --target web \
  --out-dir "$web_dir/pkg" \
  --out-name halo2_ipa_external_circuit_wasm

echo "==> Browser Worker smoke"
node "$web_dir/smoke.mjs" "$artifacts"

{
  uname -sm
  rustc --version
  cargo --version
  node --version
  wasm-bindgen --version
  printf '%s %s bytes\n' "$wasm" "$(stat -c%s "$wasm")"
  printf '%s %s bytes\n' "$web_dir/pkg/halo2_ipa_external_circuit_wasm_bg.wasm" \
    "$(stat -c%s "$web_dir/pkg/halo2_ipa_external_circuit_wasm_bg.wasm")"
} | tee "$artifacts/environment.txt"

echo "External Halo2 IPA ChainCircuit browser Web Worker checks passed"
