// Runs the Poseidon2 Halo2 custom-gate IPA prove/verify smoke in a wasm runtime.
//
// Usage:
//   node ci/poseidon2_halo2_wasm_smoke.mjs path/to/poseidon2_halo2_wasm.wasm
//
// The expected input is a wasm32-wasip1 command module (`_start`). It is run
// through `node:wasi` with `version: "preview1"` and `returnOnExit: true`; the
// module stdout is captured and forwarded, and a non-zero exit status fails the
// runner.
//
// A non-WASI module is also accepted when it exports
// `poseidon2_halo2_smoke` (no such build is produced by the current CI script);
// in that case the harness stubs every function import with a throwing stub so
// that an accidental host dependency fails loudly.
import { closeSync, mkdtempSync, openSync, readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WASI } from "node:wasi";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error(
    "usage: node ci/poseidon2_halo2_wasm_smoke.mjs <poseidon2_halo2_wasm.wasm>",
  );
  process.exit(2);
}

const bytes = await readFile(wasmPath);
const wasm = await WebAssembly.compile(bytes);

function stubFunctionImports(module) {
  const imports = {};
  for (const entry of WebAssembly.Module.imports(module)) {
    if (entry.kind !== "function") {
      throw new Error(
        `unsupported wasm import kind: ${entry.kind} (${entry.module}.${entry.name})`,
      );
    }
    (imports[entry.module] ??= {})[entry.name] = () => {
      throw new Error(`unexpected wasm import call: ${entry.module}.${entry.name}`);
    };
  }
  return imports;
}

const exports = WebAssembly.Module.exports(wasm);
const isWasiCommand = exports.some((entry) => entry.name === "_start");
const isExportSmoke = exports.some(
  (entry) => entry.name === "poseidon2_halo2_smoke",
);

let status;
let stdout = "";

if (isWasiCommand) {
  const dir = mkdtempSync(join(tmpdir(), "poseidon2-halo2-wasm-"));
  const stdoutPath = join(dir, "stdout.txt");
  const stdoutFd = openSync(stdoutPath, "w");
  const wasi = new WASI({
    version: "preview1",
    args: ["poseidon2_halo2_wasm"],
    env: {},
    returnOnExit: true,
    stdout: stdoutFd,
  });
  const instance = await WebAssembly.instantiate(wasm, wasi.getImportObject());
  try {
    status = wasi.start(instance);
  } finally {
    closeSync(stdoutFd);
  }
  stdout = readFileSync(stdoutPath, "utf8");
} else if (isExportSmoke) {
  const instance = await WebAssembly.instantiate(wasm, stubFunctionImports(wasm));
  status = instance.exports.poseidon2_halo2_smoke();
} else {
  console.error(
    "wasm module exports neither _start nor poseidon2_halo2_smoke",
  );
  process.exit(2);
}

if (stdout) {
  process.stdout.write(stdout);
}

if (status !== 0) {
  console.error(`poseidon2 halo2 wasm smoke failed with exit status ${status}`);
  process.exit(status || 1);
}

// The JSON line is the measurement contract. Validate it here as well so a
// truncated or all-false run cannot pass by exiting 0 alone.
const jsonLine = stdout
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line.startsWith("{") && line.endsWith("}"))
  .at(-1);

if (jsonLine) {
  let report;
  try {
    report = JSON.parse(jsonLine);
  } catch (error) {
    console.error(`failed to parse smoke JSON: ${error}`);
    process.exit(1);
  }
  const required = [
    "target",
    "rows",
    "vk_bytes",
    "pk_bytes",
    "proof_bytes",
    "keygen_ms",
    "prove_ms",
    "verify_ms",
    "digest_ok",
    "verified",
    "wrong_rejected",
    "tampered_rejected",
  ];
  const missing = required.filter((key) => !(key in report));
  if (missing.length !== 0) {
    console.error(`smoke JSON is missing fields: ${missing.join(", ")}`);
    process.exit(1);
  }
  for (const key of [
    "digest_ok",
    "verified",
    "wrong_rejected",
    "tampered_rejected",
  ]) {
    if (report[key] !== true) {
      console.error(`smoke check ${key} is not true`);
      process.exit(1);
    }
  }
} else if (isWasiCommand) {
  console.error("wasm smoke produced no JSON report on stdout");
  process.exit(1);
}

console.log(
  `poseidon2 halo2 wasm smoke: ok${jsonLine ? " (json checks passed)" : ""}`,
);
