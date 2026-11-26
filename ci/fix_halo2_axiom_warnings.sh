#!/usr/bin/env bash
# Applies rustfix suggestions to the vendored halo2-axiom and verifies the
# result for native and both wasm targets.
#
# `cargo fix` only addresses machine-applicable suggestions. Cross-target
# warnings (for example an import used only with `multicore`) may still need
# manual `#[cfg(...)]` changes. Run this locally, review the diff under
# rustcrypto-ffi/third_party/halo2-axiom-0.5.3, then commit.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root/rustcrypto-ffi"

echo "==> Applying cargo fix to vendored halo2-axiom"
cargo fix --lib -p halo2-axiom --allow-dirty "$@"

echo "==> Review the diff under third_party/halo2-axiom-0.5.3 before committing"
"$repo_root/ci/check_halo2_axiom_warnings.sh"
