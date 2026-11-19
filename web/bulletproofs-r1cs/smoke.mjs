import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { WASI } from "node:wasi";

const [dir, wasiModule] = process.argv.slice(2);
const require = createRequire(new URL("../groth16-prover/package.json", import.meta.url));
const { chromium } = require("playwright");
const read = (name) => readFile(join(dir, name));
const [circuit, publicInputs, witness, context, native] = await Promise.all(
  ["circuit", "public", "witness", "context", "native"].map((name) => read(name + ".bin")),
);
const jsFile = "pkg/bulletproofs_r1cs_web.js";
const wasmFile = "pkg/bulletproofs_r1cs_web_bg.wasm";
const wasm = await read(wasmFile);
const bindings = await import(pathToFileURL(join(dir, jsFile)));
const { memory } = await bindings.default({ module_or_path: wasm });
const verifyStarted = performance.now();
assert(bindings.verify(circuit, publicInputs, context, native));
const verifierMs = performance.now() - verifyStarted;
const expected = bindings.proofCommitments(native);
assert(bindings.verifyWithCommitments(circuit, publicInputs, context, native, expected));
const reordered = new Uint8Array([...expected.slice(32), ...expected.slice(0, 32)]);
assert(!bindings.verifyWithCommitments(circuit, publicInputs, context, native, reordered));
const invalid = Uint8Array.from(native);
invalid[5] ^= 1;
assert.throws(() => bindings.verify(circuit, publicInputs, context, invalid), (error) => error === -1);
assert(!bindings.verify(circuit, publicInputs, new Uint8Array([1]), native));
const nodeWitness = Uint8Array.from(witness);
const start = performance.now();
const nodeProof = bindings.prove(circuit, publicInputs, nodeWitness, context);
const node = { proverMs: performance.now() - start, verifierMs, memoryBytes: memory.buffer.byteLength };
assert(nodeWitness.every((value) => value === 0));
assert.notDeepEqual(nodeProof, new Uint8Array(native));
await writeFile(join(dir, "node.bin"), nodeProof);

const openingWitness = Uint8Array.from(witness);
const blindings = new Uint8Array(expected.length);
blindings[0] = 1;
blindings[32] = 2;
const opening = bindings.proveWithBlindings(circuit, publicInputs, openingWitness, blindings, context);
assert(openingWitness.every((value) => value === 0));
assert(blindings.every((value) => value === 0));
assert(bindings.verify(circuit, publicInputs, context, opening));
assert(!bindings.verifyWithCommitments(circuit, publicInputs, context, opening, expected));
const invalidWitness = Uint8Array.from(witness);
invalidWitness[0] ^= 1;
assert.throws(() => bindings.prove(circuit, publicInputs, invalidWitness, context), (error) => error === -4);
assert(invalidWitness.every((value) => value === 0));

const routes = new Map([
  ["/", ["text/html", "<!doctype html><title>Bulletproofs R1CS PoC</title>"]],
  ["/worker.mjs", ["text/javascript", await readFile(new URL("./worker.mjs", import.meta.url))]],
  ["/" + jsFile, ["text/javascript", await read(jsFile)]],
  ["/" + wasmFile, ["application/wasm", wasm]],
]);
const server = createServer((req, res) => {
  const route = routes.get(req.url);
  if (!route) {
    res.writeHead(404).end();
    return;
  }
  const [type, body] = route;
  res.writeHead(200, {
    "content-type": type,
    "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'",
  }).end(body);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
let web;
let chromiumVersion;
try {
  browser = await chromium.launch();
  chromiumVersion = browser.version();
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}`, { timeout: 30_000 });
  const result = await page.evaluate(async ({ circuit, publicInputs, witness, context, native }) => {
    const worker = new Worker("/worker.mjs", { type: "module" });
    const packed = { circuit: Uint8Array.from(circuit), publicInputs: Uint8Array.from(publicInputs),
      context: Uint8Array.from(context) };
    const call = (data, transfer = []) => new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("worker timeout")), 30_000);
      worker.onmessage = ({ data }) => {
        clearTimeout(timer);
        if (data.error) reject(new Error(data.error));
        else resolve(data);
      };
      worker.onerror = (error) => {
        clearTimeout(timer);
        reject(new Error(error.message));
      };
      worker.postMessage({ ...packed, ...data }, transfer);
    });
    try {
      const checked = await call({ proof: Uint8Array.from(native) });
      const secret = Uint8Array.from(witness);
      const proved = await call({ witness: secret }, [secret.buffer]);
      return { valid: checked.result, proof: Array.from(proved.result),
        metrics: { proverMs: proved.metrics.milliseconds, verifierMs: checked.metrics.milliseconds,
          memoryBytes: proved.metrics.memoryBytes } };
    } finally {
      worker.terminate();
    }
  }, { circuit: [...circuit], publicInputs: [...publicInputs], witness: [...witness],
    context: [...context], native: [...native] });
  assert(result.valid);
  assert(bindings.verify(circuit, publicInputs, context, Uint8Array.from(result.proof)));
  await writeFile(join(dir, "web.bin"), Uint8Array.from(result.proof));
  web = result.metrics;
} finally {
  await browser?.close();
  server.close();
}

const wasiBytes = await readFile(wasiModule);
const wasi = new WASI({
  version: "preview1",
  args: ["r1cs", "verify", "/fixture", "web.bin"],
  preopens: { "/fixture": dir },
  returnOnExit: true,
});
const wasiInstance = await WebAssembly.instantiate(await WebAssembly.compile(wasiBytes), wasi.getImportObject());
const wasiStart = performance.now();
assert.equal(wasi.start(wasiInstance), 0);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const measurements = {
  node, web, nodeVersion: process.version, chromiumVersion,
  wasi: { startupAndVerifyMs: performance.now() - wasiStart,
    memoryBytes: wasiInstance.exports.memory.buffer.byteLength, binaryBytes: wasiBytes.length, sha256: sha256(wasiBytes) },
  browserWasm: { binaryBytes: wasm.length, sha256: sha256(wasm) },
};
await writeFile(join(dir, "wasm-measurements.json"), JSON.stringify(measurements, null, 2) + "\n");
