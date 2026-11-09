#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root/rustcrypto-ffi"
cargo build --locked --release --lib
cd "$repo_root"
archive_dir="src/rustcrypto/vendor/rustcrypto-ffi/linux-x86_64"
mkdir -p "$archive_dir"
cp rustcrypto-ffi/target/release/librust_crypto_ffi.a "$archive_dir/librust_crypto_ffi-linux-x86_64.a"
nim c --hints:off tests/hpke_interop.nim
cd web/hpke-interop
npm ci
npx playwright install chromium
npm test
