// Runs the Halo2 IPA/BN254 v1 fixture smoke test in a wasm runtime.
//
// Usage:
//   node ci/halo2_ipa_wasm_smoke.mjs path/to/halo2_ipa_verify.wasm       # wasm32-wasip1 (_start)
//   node ci/halo2_ipa_wasm_smoke.mjs path/to/halo2_ipa_verify_web.wasm   # wasm32-unknown-unknown export
//
// A WASI command module is executed via `node:wasi` (preview1,
// `returnOnExit: true`). A non-WASI module is instantiated with every function
// import replaced by a throwing stub, so a verifier that accidentally requests
// entropy or another host service fails loudly instead of silently succeeding.
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node ci/halo2_ipa_wasm_smoke.mjs <halo2_ipa_verify*.wasm>");
  process.exit(2);
}

const bytes = await readFile(wasmPath);
const wasm = await WebAssembly.compile(bytes);

const wasi = new WASI({
  version: "preview1",
  args: ["halo2_ipa_verify"],
  env: {},
  returnOnExit: true,
});

// The non-WASI module may still *import* entropy helpers pulled in by the
// proving/public C ABI surface. Stubbing every function import with a throw
// proves that the executed verify path itself never calls them. If a future
// change makes verification consume entropy or another host service, this
// harness fails instead of silently providing the service.
function stubFunctionImports(module) {
  const imports = {};
  for (const entry of WebAssembly.Module.imports(module)) {
    if (entry.kind !== "function") {
      throw new Error(`unsupported wasm import kind: ${entry.kind} (${entry.module}.${entry.name})`);
    }
    (imports[entry.module] ??= {})[entry.name] = () => {
      throw new Error(`unexpected wasm import call: ${entry.module}.${entry.name}`);
    };
  }
  return imports;
}

const isWasiCommand = WebAssembly.Module.exports(wasm).some(
  (entry) => entry.name === "_start",
);
const instance = await WebAssembly.instantiate(
  wasm,
  isWasiCommand ? wasi.getImportObject() : stubFunctionImports(wasm),
);

let status;
if (typeof instance.exports._start === "function") {
  status = wasi.start(instance);
} else if (typeof instance.exports.halo2_ipa_verify_fixture === "function") {
  status = instance.exports.halo2_ipa_verify_fixture();
  if (status !== 0) {
    console.error(`halo2_ipa_verify_fixture failed with bits ${status.toString(2)}`);
    process.exit(1);
  }
} else {
  console.error("wasm module exports neither _start nor halo2_ipa_verify_fixture");
  process.exit(2);
}

if (status !== 0) {
  console.error(`wasm smoke failed with exit status ${status}`);
  process.exit(status);
}
console.log("halo2 ipa bn254 wasm fixture smoke: ok");
