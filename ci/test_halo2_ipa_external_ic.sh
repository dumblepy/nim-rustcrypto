#!/usr/bin/env bash
# Builds and exercises the verify-only ICP canister for the external Halo2 IPA
# ChainCircuit (`examples/halo2-ipa-external-circuit`).
#
# The canister links the external circuit as a real Cargo path dependency with
# its `verify-only` feature. Because `rustcrypto-ffi` has many `#[no_mangle]`
# C ABI exports, a `cdylib` build would export all of them; the crate builds a
# staticlib and `link-canister.sh` links it with only the two verifier exports.
#
# Usage: ci/test_halo2_ipa_external_ic.sh [artifact-dir]
#
# The script fails on any assertion mismatch: fixture proof verification,
# tampered proof, wrong instances, bad envelope, V1-magic / VK artifacts,
# non-canonical and trailing bytes, oversized input, WASM imports other than
# `ic0`, or prover symbols in the module.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/tests/fixtures/halo2_ipa_external_chain_v1.hex"
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

if [[ ! -f "$fixture" ]]; then
  echo "missing external fixture: $fixture" >&2
  exit 1
fi

node "$repo_root/web/ic-external-circuit/extract-fixture.cjs" "$fixture" "$artifacts"

cd "$repo_root"
HALO2_IPA_EXTERNAL_APPROVED_VK="$artifacts/vk.bin" \
  cargo build --locked --release \
    --features halo2-ipa-verify-only,halo2-ipa-params-cache \
    --manifest-path examples/halo2-ipa-external-circuit-ic-verifier/Cargo.toml \
    --target wasm32-unknown-unknown

wasm="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/halo2_ipa_external_circuit_ic_verifier.wasm"
# The crate is a staticlib so rustc does not add `--export` for every
# `rustcrypto-ffi` `#[no_mangle]` symbol. Link with the two verifier exports.
bash "$repo_root/examples/halo2-ipa-external-circuit-ic-verifier/link-canister.sh" "$wasm"
if [[ ! -f "$wasm" ]]; then
  echo "missing wasm: $wasm" >&2
  exit 1
fi

# Symbol inspection. GNU nm cannot read wasm; use llvm-nm from the system LLVM
# install or from the Rust toolchain when the llvm-tools component is present.
find_nm() {
  if command -v llvm-nm >/dev/null 2>&1; then
    command -v llvm-nm
    return
  fi
  local candidate
  for candidate in /usr/lib/llvm-*/bin/llvm-nm "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-nm; do
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  done
  return 1
}

nm_bin="$(find_nm)" || {
  echo "llvm-nm is required for the symbol check" >&2
  exit 1
}
symbols="$artifacts/wasm-symbols.txt"
"$nm_bin" "$wasm" >"$symbols"

for required in "canister_update verify" "rustcrypto_halo2_ipa_external_chain_verify"; do
  if ! grep -Fq " T $required" "$symbols"; then
    echo "missing verifier symbol: $required" >&2
    cat "$symbols" >&2
    exit 1
  fi
done

if grep -Eq '[[:space:]]T[[:space:]].*(_prepare|_prove|_pk_validate|keygen|create_proof)' "$symbols"; then
  echo "prover/keygen symbol found in verify-only wasm" >&2
  grep -E '[[:space:]]T[[:space:]].*(_prepare|_prove|_pk_validate|keygen|create_proof)' "$symbols" >&2
  exit 1
fi

echo "wasm symbols: $(wc -l <"$symbols") exports, verifier present, prover absent"

node "$repo_root/web/ic-external-circuit/ic-smoke.cjs" "$artifacts" "$wasm"

node -e '
const fs = require("node:fs");
const path = require("node:path");
const [artifactDir] = process.argv.slice(1);
const report = JSON.parse(fs.readFileSync(path.join(artifactDir, "ic-measurements.json"), "utf8"));
const verify = report.verify;
const imports = report.wasm.imports.map((entry) => entry.module + "." + entry.name).join(", ");
console.log("IC external ChainCircuit verify measurements");
console.log(`  wasm: ${report.wasm.bytes} bytes, ${report.wasm.functions.total} functions, imports: ${imports}`);
console.log(`  circuit: id ${report.fixture.circuitId}, k ${report.fixture.k}, VK ${report.fixture.vkBytes} bytes, proof ${report.fixture.proofBytes} bytes, instances ${report.fixture.instancesBytes} bytes`);
console.log(`  verify: status ${verify.status}, cold ${verify.coldInstructions} instructions, warm ${verify.warmInstructions} instructions, memory ${verify.memoryBytes} bytes (${verify.memoryPages} pages)`);
console.log(`  negative statuses: proof ${verify.tamperedProofStatus}, instances ${verify.wrongInstancesStatus}, bad-envelope ${verify.badEnvelopeStatus}, v1-magic ${verify.v1MagicStatus}, vk-artifact ${verify.vkArtifactStatus}, non-canonical ${verify.nonCanonicalStatus}, trailing ${verify.trailingStatus}, oversized ${verify.oversizedDirectGuard.status}`);
' "$artifacts"

echo "Measurements: $artifacts/ic-measurements.json"
