#!/usr/bin/env bash
# Halo2 IPA C ABI / generic registry codec robustness gate.
#
# Runs the deterministic codec fuzz / DoS / panic-resistance integration test.
# Set HALO2_IPA_CODEC_SKIP_VERIFY_ONLY=1 to skip the verifier-only pass.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root/rustcrypto-ffi"

echo "==> halo2 IPA codec robustness (default: prover + verifier paths)"
cargo test --locked --test halo2_ipa_codec_robustness

if [[ "${HALO2_IPA_CODEC_SKIP_VERIFY_ONLY:-0}" != "1" ]]; then
  echo "==> halo2 IPA codec robustness (halo2-ipa-verify-only: no prover symbols)"
  cargo test --locked --features halo2-ipa-verify-only --test halo2_ipa_codec_robustness
fi
