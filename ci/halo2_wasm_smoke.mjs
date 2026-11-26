// Runs the Halo2 v1 fixture smoke test in a wasm runtime.
//
// Usage:
//   node ci/halo2_wasm_smoke.mjs path/to/halo2_verify.wasm            # wasm32-wasip1 (_start)
//   node ci/halo2_wasm_smoke.mjs path/to/halo2_verify_web.wasm        # wasm32-unknown-unknown export
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node ci/halo2_wasm_smoke.mjs <halo2_verify*.wasm>");
  process.exit(2);
}

const bytes = await readFile(wasmPath);
const wasm = await WebAssembly.compile(bytes);

const wasi = new WASI({
  version: "preview1",
  args: ["halo2_verify"],
  env: {},
  returnOnExit: true,
});

// A WASI command module exports `_start`; a cdylib smoke module exports the
// Halo2 entry point instead. The latter may carry unused `getrandom`/wasm-bindgen
// imports from halo2-axiom's dependency graph; stub them so the run fails loudly
// if the verifier path ever requests entropy or other host services.
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
} else if (typeof instance.exports.halo2_verify_fixture === "function") {
  status = instance.exports.halo2_verify_fixture();
  if (status !== 0) {
    console.error(`halo2_verify_fixture failed with bits ${status.toString(2)}`);
    process.exit(1);
  }
} else {
  console.error("wasm module exports neither _start nor halo2_verify_fixture");
  process.exit(2);
}

if (status !== 0) {
  console.error(`wasm smoke failed with exit status ${status}`);
  process.exit(status);
}
console.log("halo2 wasm fixture smoke: ok");
