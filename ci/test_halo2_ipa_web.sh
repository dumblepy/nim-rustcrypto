#!/usr/bin/env bash
# Halo2 IPA/BN254 browser Web Worker build + smoke.
#
# Builds the standalone wasm-bindgen adapter (which reuses the reviewed
# rustcrypto-ffi C ABI through path-included modules), runs `wasm-bindgen
# --target web`, and drives headless Chromium through a plain HTTP origin
# without COOP/COEP. The prover must actually run in a module Worker under
# `crossOriginIsolated === false`; a build success alone is not a pass.
#
# Usage: bash ci/test_halo2_ipa_web.sh [artifact-dir]
# Environment: CARGO_TARGET_DIR, ZKP_RUST_WASM_TARGETS_INSTALLED=1.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${1:-$(mktemp -d)}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
web_dir="$repo_root/web/halo2-ipa-prover"

cargo_target_dir="${CARGO_TARGET_DIR:-$web_dir/target}"
mkdir -p "$cargo_target_dir"
export CARGO_TARGET_DIR="$(cd "$cargo_target_dir" && pwd)"
echo "Halo2 IPA web artifacts: $artifacts"
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
echo "==> Build wasm32-unknown-unknown adapter"
cargo build --locked --release --manifest-path "$web_dir/Cargo.toml" --target wasm32-unknown-unknown

wasm="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/halo2_ipa_prover.wasm"
[[ -s "$wasm" ]] || { echo "missing wasm: $wasm" >&2; exit 1; }

echo "==> wasm-bindgen --target web"
rm -rf "$web_dir/pkg"
wasm-bindgen "$wasm" \
  --target web \
  --out-dir "$web_dir/pkg" \
  --out-name halo2_ipa_prover

echo "==> Browser Worker smoke"
node "$web_dir/smoke.mjs" "$artifacts"

{
  uname -sm
  rustc --version
  cargo --version
  node --version
  wasm-bindgen --version
  printf '%s %s bytes\n' "$wasm" "$(stat -c%s "$wasm")"
  printf '%s %s bytes\n' "$web_dir/pkg/halo2_ipa_prover_bg.wasm" \
    "$(stat -c%s "$web_dir/pkg/halo2_ipa_prover_bg.wasm")"
} | tee "$artifacts/environment.txt"

echo "Halo2 IPA browser Web Worker checks passed"
