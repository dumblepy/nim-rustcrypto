#!/usr/bin/env bash
# Halo2 KZG/BN254 wasm build, symbol, link, and runtime smoke checks.
#
# Builds both wasm static archives, checks the four Halo2 C ABI symbols with
# llvm-nm, and executes the committed v1 fixture through the same C ABI in
# Node's WASI (wasm32-wasip1) and in a plain WebAssembly instance
# (wasm32-unknown-unknown). Also runs the native fixture smoke for comparison.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${1:-$(mktemp -d)}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
echo "Halo2 wasm artifacts: $artifacts"

cd "$repo_root/rustcrypto-ffi"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/rustcrypto-ffi/target}"
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"

if [[ "${ZKP_RUST_WASM_TARGETS_INSTALLED:-0}" != "1" ]]; then
  rustup target add wasm32-unknown-unknown wasm32-wasip1
fi

echo "==> Build wasm static archives"
cargo build --locked --release --lib --target wasm32-unknown-unknown
cargo build --locked --release --lib --target wasm32-wasip1

echo "==> Locate llvm-nm"
llvm_nm=""
for candidate in llvm-nm llvm-nm-21 llvm-nm-20 llvm-nm-19 llvm-nm-18; do
  if command -v "$candidate" >/dev/null 2>&1; then
    llvm_nm="$(command -v "$candidate")"
    break
  fi
done
if [[ -z "$llvm_nm" ]]; then
  llvm_nm="$(find "$(rustc --print sysroot)" -type f -name llvm-nm 2>/dev/null | head -n 1 || true)"
fi
if [[ -z "$llvm_nm" ]]; then
  echo "llvm-nm was not found; install LLVM tools to verify archive symbols" >&2
  exit 1
fi

symbols=(
  rustcrypto_halo2_kzg_bn254_verify
  rustcrypto_halo2_kzg_bn254_params_validate
  rustcrypto_halo2_kzg_bn254_vk_validate
  rustcrypto_halo2_kzg_bn254_instances_validate
)
archives=(
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/librust_crypto_ffi.a"
  "$CARGO_TARGET_DIR/wasm32-wasip1/release/librust_crypto_ffi.a"
)

echo "==> Check Halo2 C ABI symbols"
symbol_report="$artifacts/symbols.txt"
"$llvm_nm" --version | head -n 1 > "$symbol_report"
for archive in "${archives[@]}"; do
  [[ -s "$archive" ]] || { echo "missing archive: $archive" >&2; exit 1; }
  defined="$("$llvm_nm" --defined-only -g "$archive" 2>/dev/null | awk '{print $NF}')"
  for symbol in "${symbols[@]}"; do
    if ! grep -qx "$symbol" <<<"$defined"; then
      echo "missing $symbol in $archive" >&2
      exit 1
    fi
    printf '%s %s\n' "$archive" "$symbol" >> "$symbol_report"
  done
  echo "$(basename "$archive"): all Halo2 symbols present"
done

echo "==> Native fixture smoke"
cargo run --locked --release --example halo2_verify

echo "==> wasm fixture smoke (wasm32-wasip1 via Node WASI)"
cargo build --locked --release --example halo2_verify --target wasm32-wasip1
node "$repo_root/ci/halo2_wasm_smoke.mjs" \
  "$CARGO_TARGET_DIR/wasm32-wasip1/release/examples/halo2_verify.wasm"

echo "==> wasm fixture smoke (wasm32-unknown-unknown via WebAssembly)"
cargo build --locked --release --example halo2_verify_web --target wasm32-unknown-unknown
node "$repo_root/ci/halo2_wasm_smoke.mjs" \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/examples/halo2_verify_web.wasm"

{
  uname -sm
  rustc --version
  node --version
  "$llvm_nm" --version | head -n 1
  for archive in "${archives[@]}"; do
    printf '%s %s bytes\n' "$archive" "$(stat -c%s "$archive")"
  done
  for wasm in \
    "$CARGO_TARGET_DIR/wasm32-wasip1/release/examples/halo2_verify.wasm" \
    "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/examples/halo2_verify_web.wasm"; do
    printf '%s %s bytes\n' "$(basename "$wasm")" "$(stat -c%s "$wasm")"
  done
} | tee "$artifacts/environment.txt"

echo "Halo2 wasm checks passed"
