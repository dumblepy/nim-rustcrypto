#!/usr/bin/env bash
# Verifies that the vendored halo2-axiom builds without warnings.
#
# This is a non-mutating CI/local check. If it fails, run
# `ci/fix_halo2_axiom_warnings.sh` to apply rustfix suggestions, then review and
# commit the vendored changes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root/rustcrypto-ffi"

echo "==> halo2-axiom native (dev)"
cargo rustc --locked -p halo2-axiom --lib -- -D warnings

echo "==> halo2-axiom wasm32-unknown-unknown (release)"
cargo rustc --locked --release -p halo2-axiom --lib --target wasm32-unknown-unknown -- -D warnings

echo "==> halo2-axiom wasm32-wasip1 (release)"
cargo rustc --locked --release -p halo2-axiom --lib --target wasm32-wasip1 -- -D warnings

echo "halo2-axiom builds without warnings"
