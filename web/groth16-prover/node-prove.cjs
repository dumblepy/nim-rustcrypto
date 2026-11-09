// Separate Node process so peak RSS excludes browser/WASI compilation in smoke.cjs.
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
(async () => {
  const dir = process.argv[2];
  const module = await import('./pkg/groth16_browser.js');
  const wasm = await module.default({ module_or_path: fs.readFileSync(path.join(__dirname, 'pkg/groth16_browser_bg.wasm')) });
  const read = name => fs.readFileSync(path.join(dir, name));
  const inputs = new Uint8Array(32); inputs[31] = 9;
  const witness = new Uint8Array(32); witness[31] = 3;
  const start = performance.now();
  let proof;
  try { proof = module.prove(read('circuit.bin'), read('proving-key.bin'), inputs, witness); }
  finally { witness.fill(0); }
  const ms = performance.now() - start;
  fs.writeFileSync(path.join(dir, 'node-proof.bin'), proof);
  console.log(JSON.stringify({ ms, wasmLinearMemoryHighWaterBytes: wasm.memory.buffer.byteLength, processPeakRssKiB: process.resourceUsage().maxRSS }));
})().catch(error => { console.error(error); process.exitCode = 1; });
