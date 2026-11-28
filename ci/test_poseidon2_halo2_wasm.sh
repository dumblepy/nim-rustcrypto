#!/usr/bin/env bash
# Poseidon2 Halo2 custom-gate / IPA prove-verify execution smoke.
#
# Builds the example for wasm32-wasip1, runs it natively, then executes the wasm
# command module through Node's WASI (preview1). This is a runtime check: the
# custom gate is synthesized, keygen/prove/verify run in wasm, and the negative
# digest/proof checks must reject, not merely compile.
#
# Usage: bash ci/test_poseidon2_halo2_wasm.sh [artifact-dir]
#
# No wasm-bindgen and no network access are required. Proving this gate in wasm
# is slow by design (k = 10), so the runtime timeout is generous.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${1:-$(mktemp -d)}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
echo "Poseidon2 Halo2 wasm artifacts: $artifacts"

run_timeout_seconds="${POSEIDON2_HALO2_WASM_TIMEOUT_SECONDS:-1800}"
expected_digest="23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8"

cd "$repo_root/rustcrypto-ffi"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/rustcrypto-ffi/target}"
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"

if [[ "${POSEIDON2_HALO2_RUST_WASM_TARGETS_INSTALLED:-0}" != "1" ]]; then
  if ! rustup target list --installed | grep -qx "wasm32-wasip1"; then
    rustup target add wasm32-wasip1
  fi
fi

example="poseidon2_halo2_wasm"
wasm="$CARGO_TARGET_DIR/wasm32-wasip1/release/examples/${example}.wasm"
native_stdout="$artifacts/native.json"
wasm_stdout="$artifacts/wasm.json"

echo "==> Build wasm32-wasip1 example"
cargo build --locked --release --example "$example" --target wasm32-wasip1

echo "==> Native prove/verify smoke"
native_start="$(date +%s%N)"
timeout "$run_timeout_seconds" cargo run --locked --release --example "$example" \
  | tee "$native_stdout"
native_end="$(date +%s%N)"
native_wall_ms=$(( (native_end - native_start) / 1000000 ))

[[ -s "$wasm" ]] || { echo "missing wasm example: $wasm" >&2; exit 1; }
wasm_size="$(stat -c%s "$wasm")"

echo "==> wasm32-wasip1 prove/verify smoke (Node WASI)"
wasm_start="$(date +%s%N)"
timeout "$run_timeout_seconds" node "$repo_root/ci/poseidon2_halo2_wasm_smoke.mjs" "$wasm" \
  | tee "$wasm_stdout"
wasm_end="$(date +%s%N)"
wasm_wall_ms=$(( (wasm_end - wasm_start) / 1000000 ))

echo "==> Validate native/wasm reports"
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";

const [
  nativeReportPath,
  wasmReportPath,
  wasmBinaryPath,
  expectedDigest,
  wasmSize,
  nativeWallMs,
  wasmWallMs,
  environmentPath,
  measurementsPath,
] = process.argv.slice(1);

function lastJson(path) {
  const line = readFileSync(path, "utf8")
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter((value) => value.startsWith("{") && value.endsWith("}"))
    .at(-1);
  if (!line) {
    throw new Error(`no JSON report in ${path}`);
  }
  return JSON.parse(line);
}

const nativeReport = lastJson(nativeReportPath);
const wasmReport = lastJson(wasmReportPath);
const failures = [];

function check(report, expectedTarget, label) {
  if (report.target !== expectedTarget) {
    failures.push(`${label} target is ${report.target}, expected ${expectedTarget}`);
  }
  if (report.digest !== expectedDigest) {
    failures.push(`${label} digest is ${report.digest}, expected ${expectedDigest}`);
  }
  for (const key of ["digest_ok", "verified", "wrong_rejected", "tampered_rejected"]) {
    if (report[key] !== true) {
      failures.push(`${label} ${key} is ${report[key]}, expected true`);
    }
  }
  for (const key of ["k", "rows", "vk_bytes", "pk_bytes", "proof_bytes"]) {
    if (!Number.isInteger(report[key]) || report[key] <= 0) {
      failures.push(`${label} ${key} is not a positive integer: ${report[key]}`);
    }
  }
  return report;
}

check(nativeReport, "native", "native");
check(wasmReport, "wasm", "wasm");

if (nativeReport.digest !== wasmReport.digest) {
  failures.push("native and wasm digests differ");
}
if (nativeReport.rows !== wasmReport.rows) {
  failures.push("native and wasm row counts differ");
}

const environment = [
  `node: ${process.version}`,
  `wasm: ${wasmBinaryPath} ${wasmSize} bytes`,
  `native_wall_ms: ${nativeWallMs}`,
  `wasm_wall_ms: ${wasmWallMs}`,
  `expected_digest: ${expectedDigest}`,
].join("\n") + "\n";
writeFileSync(environmentPath, environment);

const measurements = {
  expected_digest: expectedDigest,
  wasm_bytes: Number(wasmSize),
  native_wall_ms: Number(nativeWallMs),
  wasm_wall_ms: Number(wasmWallMs),
  native: nativeReport,
  wasm: wasmReport,
};
writeFileSync(measurementsPath, `${JSON.stringify(measurements, null, 2)}\n`);

if (failures.length !== 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(
  `native: ${nativeReport.digest} rows=${nativeReport.rows} proof=${nativeReport.proof_bytes}B ` +
    `keygen=${nativeReport.keygen_ms}ms prove=${nativeReport.prove_ms}ms verify=${nativeReport.verify_ms}ms`,
);
console.log(
  `wasm:   ${wasmReport.digest} rows=${wasmReport.rows} proof=${wasmReport.proof_bytes}B ` +
    `keygen=${wasmReport.keygen_ms}ms prove=${wasmReport.prove_ms}ms verify=${wasmReport.verify_ms}ms ` +
    `wall=${wasmWallMs}ms size=${wasmSize}B`,
);
' "$native_stdout" "$wasm_stdout" "$wasm" "$expected_digest" "$wasm_size" \
  "$native_wall_ms" "$wasm_wall_ms" \
  "$artifacts/environment.txt" "$artifacts/measurements.json"

{
  uname -sm
  rustc --version
  cargo --version
  node --version
  printf '%s %s bytes\n' "$wasm" "$wasm_size"
  printf 'native_wall_ms %s\n' "$native_wall_ms"
  printf 'wasm_wall_ms %s\n' "$wasm_wall_ms"
  printf 'wasm_sha256 %s\n' "$(sha256sum "$wasm" | awk '{print $1}')"
} >> "$artifacts/environment.txt"

echo "Poseidon2 Halo2 wasm checks passed"
