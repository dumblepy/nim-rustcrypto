// Runs the Poseidon2/BN254 smoke test in a wasm runtime.
//
// Usage:
//   node ci/poseidon2_wasm_smoke.mjs path/to/poseidon2_smoke.wasm      # wasm32-wasip1 (_start)
//   node ci/poseidon2_wasm_smoke.mjs path/to/poseidon2_web.wasm        # wasm32-unknown-unknown export
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node ci/poseidon2_wasm_smoke.mjs <poseidon2_smoke*.wasm>");
  process.exit(2);
}

const bytes = await readFile(wasmPath);
const wasm = await WebAssembly.compile(bytes);

const wasi = new WASI({
  version: "preview1",
  args: ["poseidon2_smoke"],
  env: {},
  returnOnExit: true,
});

// Poseidon2 is a pure function: it must not import randomness, clocks, or any
// other host service. A cdylib may still carry unused imports from its
// dependency graph; stub every function import so that any actual call fails
// loudly during the smoke run instead of being silently satisfied.
function stubFunctionImports(module) {
  const imports = {};
  for (const entry of WebAssembly.Module.imports(module)) {
    if (entry.kind !== "function") {
      throw new Error(`unsupported wasm import kind: ${entry.kind}`);
    }
    (imports[entry.module] ??= {})[entry.name] = () => {
      throw new Error(`unexpected wasm import call: ${entry.module}.${entry.name}`);
    };
  }
  return imports;
}

const isWasiCommand = WebAssembly.Module.exports(wasm).some((e) => e.name === "_start");
const instance = await WebAssembly.instantiate(
  wasm,
  isWasiCommand ? wasi.getImportObject() : stubFunctionImports(wasm),
);

let status;
if (typeof instance.exports._start === "function") {
  status = wasi.start(instance);
} else if (typeof instance.exports.poseidon2_smoke === "function") {
  status = instance.exports.poseidon2_smoke();
  if (status !== 0) {
    console.error(`poseidon2_smoke failed with status ${status}`);
    process.exit(1);
  }
} else {
  console.error("wasm module exports neither _start nor poseidon2_smoke");
  process.exit(2);
}

if (status !== 0) {
  console.error(`wasm smoke failed with exit status ${status}`);
  process.exit(status);
}
console.log(`${wasmPath}: poseidon2 wasm smoke: ok`);
