#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Rust tests"
cd "$repo_root/rustcrypto-ffi"
cargo test
cargo build --release --lib
test -s target/release/librust_crypto_ffi.a

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "==> Skip wasm/wasi cross-build on macOS (use Linux CI for wasm targets; blst needs clang with wasm32 support)"
else
  rustup target add wasm32-unknown-unknown wasm32-wasip1
  cargo build --release --lib --target wasm32-unknown-unknown
  cargo build --release --lib --target wasm32-wasip1
  test -s target/wasm32-unknown-unknown/release/librust_crypto_ffi.a
  test -s target/wasm32-wasip1/release/librust_crypto_ffi.a
fi

echo "==> Sync Rust static library"
cd "$repo_root"
nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim

echo "==> Nim tests"
cd "$repo_root"
nimble test -y

echo "==> Nim exec smoke (native Linux x86_64, ci/rustcrypto_exec_smoke.nim)"
nim r --hints:off --warnings:off --path:src ci/rustcrypto_exec_smoke.nim
