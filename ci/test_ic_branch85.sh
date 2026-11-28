#!/usr/bin/env bash
# Builds and exercises the branch-85 ICP canisters under PocketIC.
#
# Usage: ci/test_ic_branch85.sh [artifact-dir]
#
# The script fails on any assertion mismatch: fixture IPA proof verification,
# tamper rejection, Poseidon2 KAT, bounded inputs, or WASM imports other than
# `ic0`.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${1:-$(mktemp -d)}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"

cargo_target_dir="${CARGO_TARGET_DIR:-$repo_root/rustcrypto-ffi/target}"
mkdir -p "$cargo_target_dir"
export CARGO_TARGET_DIR="$(cd "$cargo_target_dir" && pwd)"

if [[ "${ZKP_RUST_WASM_TARGETS_INSTALLED:-0}" != "1" ]]; then
  rustup target add wasm32-unknown-unknown
fi

if [[ ! -d "$repo_root/web/groth16-prover/node_modules/@dfinity/pic" ]]; then
  echo "PocketIC is required. Run: (cd web/groth16-prover && npm ci)" >&2
  exit 1
fi

node "$repo_root/web/ic-branch85/extract-fixture.cjs" \
  "$repo_root/tests/fixtures/halo2_ipa_bn254_v1.hex" \
  "$artifacts"

cd "$repo_root"
HALO2_IPA_APPROVED_VK="$artifacts/vk.bin" \
  cargo build --locked --release \
    --features halo2-ipa-verify-only,halo2-ipa-params-cache \
    --manifest-path examples/halo2-ipa-ic-verifier/Cargo.toml \
    --target wasm32-unknown-unknown

cargo build --locked --release \
  --manifest-path examples/poseidon2-ic-hash/Cargo.toml \
  --target wasm32-unknown-unknown

ipa_wasm="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/halo2_ipa_ic_verifier.wasm"
poseidon_wasm="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/poseidon2_ic_hash.wasm"
for wasm in "$ipa_wasm" "$poseidon_wasm"; do
  if [[ ! -f "$wasm" ]]; then
    echo "missing wasm: $wasm" >&2
    exit 1
  fi
done

node "$repo_root/web/ic-branch85/ic-smoke.cjs" \
  "$artifacts" "$ipa_wasm" "$poseidon_wasm"

node -e '
const fs = require("node:fs");
const path = require("node:path");
const [artifactDir] = process.argv.slice(1);
const report = JSON.parse(fs.readFileSync(path.join(artifactDir, "ic-measurements.json"), "utf8"));
const ipa = report.halo2IpaVerify;
const hash = report.poseidon2Hash;
console.log("IC branch-85 measurements");
console.log(`  halo2-ipa wasm: ${report.wasm.halo2Ipa.bytes} bytes, ${report.wasm.halo2Ipa.functions.total} functions, imports: ${report.wasm.halo2Ipa.imports.map((i) => i.module + "." + i.name).join(", ")}`);
console.log(`  poseidon2 wasm: ${report.wasm.poseidon2.bytes} bytes, ${report.wasm.poseidon2.functions.total} functions, imports: ${report.wasm.poseidon2.imports.map((i) => i.module + "." + i.name).join(", ")}`);
console.log(`  IPA verify: status ${ipa.status}, cold instructions ${ipa.coldInstructions}, warm instructions ${ipa.warmInstructions}, memory ${ipa.memoryBytes} bytes (${ipa.memoryPages} pages), warm memory ${ipa.warmMemoryBytes} bytes`);
console.log(`  Poseidon2 [1,2,3]: status ${hash.status}, instructions ${hash.instructions}, memory ${hash.memoryBytes} bytes, digest ${hash.digest}`);
console.log(`  tamper/rejection statuses: proof ${ipa.tamperedProofStatus}, instance ${ipa.tamperedInstancesStatus}, oversized ${ipa.oversizedDirectGuard.status}, bad-envelope ${ipa.badEnvelopeStatus}, bad-length ${hash.badLengthStatus}, non-canonical ${hash.nonCanonicalStatus}, >12 inputs ${hash.tooManyStatus}`);
' "$artifacts"

echo "Measurements: $artifacts/ic-measurements.json"
