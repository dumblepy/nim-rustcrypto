#!/usr/bin/env bash
# Poseidon2/BN254 wasm build, symbol, link, and runtime smoke checks.
#
# Builds both wasm static archives, checks the two Poseidon2 C ABI symbols with
# llvm-nm, and executes the permutation/hash KATs through the same C ABI in
# Node's WASI (wasm32-wasip1) and in a plain WebAssembly instance
# (wasm32-unknown-unknown). Also runs the native smoke for comparison.
#
# Usage: bash ci/test_poseidon2_wasm.sh [artifact-dir]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${1:-$(mktemp -d)}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
echo "Poseidon2 wasm artifacts: $artifacts"

cd "$repo_root/rustcrypto-ffi"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/rustcrypto-ffi/target}"
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"

if [[ "${POSEIDON2_RUST_WASM_TARGETS_INSTALLED:-0}" != "1" ]]; then
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
  rustcrypto_poseidon2_bn254_permute
  rustcrypto_poseidon2_bn254_hash
)
archives=(
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/librust_crypto_ffi.a"
  "$CARGO_TARGET_DIR/wasm32-wasip1/release/librust_crypto_ffi.a"
)

echo "==> Check Poseidon2 C ABI symbols"
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
  echo "$(basename "$archive"): all Poseidon2 symbols present"
done

echo "==> Native smoke"
cargo run --locked --release --example poseidon2_smoke

echo "==> wasm smoke (wasm32-wasip1 via Node WASI)"
cargo build --locked --release --example poseidon2_smoke --target wasm32-wasip1
node "$repo_root/ci/poseidon2_wasm_smoke.mjs" \
  "$CARGO_TARGET_DIR/wasm32-wasip1/release/examples/poseidon2_smoke.wasm"

echo "==> wasm smoke (wasm32-unknown-unknown cdylib via WebAssembly)"
# Cargo.toml is owned by another task and has no `[[example]]` entry for this
# cdylib, so the example is compiled directly and linked against the same
# wasm32 static archive that the Nim wrapper links. Declaring the C ABI in the
# example (instead of linking the whole crate as an rlib) keeps the module to
# the Poseidon2 code path and gives it zero host imports.
web_wasm="$artifacts/poseidon2_web.wasm"
rustc --edition 2024 --crate-type cdylib \
  --target wasm32-unknown-unknown \
  -C opt-level=3 -C strip=symbols \
  -L "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release" \
  -l static=rust_crypto_ffi \
  examples/poseidon2_web.rs \
  -o "$web_wasm"
node "$repo_root/ci/poseidon2_wasm_smoke.mjs" "$web_wasm"

{
  uname -sm
  rustc --version
  node --version
  "$llvm_nm" --version | head -n 1
  for archive in "${archives[@]}"; do
    printf '%s %s bytes\n' "$archive" "$(stat -c%s "$archive")"
  done
  for wasm in \
    "$CARGO_TARGET_DIR/wasm32-wasip1/release/examples/poseidon2_smoke.wasm" \
    "$web_wasm"; do
    printf '%s %s bytes\n' "$wasm" "$(stat -c%s "$wasm")"
  done
} | tee "$artifacts/environment.txt"

echo "Poseidon2 wasm checks passed"
