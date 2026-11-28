// Browser smoke for the Halo2 IPA/BN254 prover.
//
// Serves index.html / page.mjs / worker.mjs / pkg/* from this directory over a
// plain HTTP origin **without** COOP/COEP headers, then drives headless
// Chromium. The page proves inside a module Web Worker, verifies the proof and
// rejects a wrong public instance. This script independently re-verifies the
// worker-produced proof in Node's wasm instance.
//
// Usage: node smoke.mjs [artifact-dir]
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const webDir = fileURLToPath(new URL(".", import.meta.url));
const artifactDir = process.argv[2];
const pkgDir = join(webDir, "pkg");
const jsFile = "halo2_ipa_prover.js";
const wasmFile = "halo2_ipa_prover_bg.wasm";
const [indexHtml, pageMjs, workerMjs, pkgJs, wasm] = await Promise.all([
  readFile(join(webDir, "index.html")),
  readFile(join(webDir, "page.mjs")),
  readFile(join(webDir, "worker.mjs")),
  readFile(join(pkgDir, jsFile)),
  readFile(join(pkgDir, wasmFile)),
]);

const routes = new Map([
  ["/", ["text/html; charset=utf-8", indexHtml]],
  ["/index.html", ["text/html; charset=utf-8", indexHtml]],
  ["/page.mjs", ["text/javascript; charset=utf-8", pageMjs]],
  ["/worker.mjs", ["text/javascript; charset=utf-8", workerMjs]],
  [`/pkg/${jsFile}`, ["text/javascript; charset=utf-8", pkgJs]],
  [`/pkg/${wasmFile}`, ["application/wasm", wasm]],
]);

// Deliberately no Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy:
// the prover must work without cross-origin isolation or SharedArrayBuffer.
const server = createServer((request, response) => {
  const pathname = new URL(request.url, "http://127.0.0.1").pathname;
  const route = routes.get(pathname);
  if (!route) {
    response.writeHead(404, { "content-type": "text/plain" }).end("not found");
    return;
  }
  const [contentType, body] = route;
  response
    .writeHead(200, {
      "content-type": contentType,
      "cache-control": "no-store",
    })
    .end(body);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

const require = createRequire(new URL("../groth16-prover/package.json", import.meta.url));
const { chromium } = require("playwright");

let browser;
let result;
try {
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error?.stack ?? error)));
  page.on("console", (message) => {
    if (message.type() === "error") console.error("browser console:", message.text());
  });
  await page.goto(origin, { waitUntil: "load", timeout: 60_000 });
  await page.waitForFunction(() => window.__halo2IpaResult !== undefined, null, {
    timeout: 600_000,
  });
  result = await page.evaluate(() => window.__halo2IpaResult);
  assert.deepEqual(pageErrors, [], `page errors: ${pageErrors.join("\n")}`);
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}

assert.equal(result.error, undefined, result.error);
assert.equal(result.ok, true, "worker proof did not verify");
assert.equal(result.worker, true, "proving did not run in a Worker");
assert.equal(result.crossOriginIsolated, false, "expected a non-isolated origin");
assert.equal(result.abiVersion, 1);
assert.equal(result.circuitId, 1);
assert.equal(result.prepare.inWorker, true);
assert.equal(result.prove.inWorker, true);
assert.equal(result.prove.witnessZeroized, true, "worker witness was not zeroized");
assert.ok(result.prove.proofBytes > 0);
assert.equal(result.verify.ok, true);
assert.equal(result.verify.inWorker, true);
assert.equal(result.wrongInstance.ok, false, "wrong instance was accepted");
assert.equal(result.tamperedProof.ok, false, "tampered proof was accepted");
assert.equal(result.instances.length, 8 + 4 + 4 + 32);
assert.equal(result.instances.at(-1), 35, "expected public y = 35");

// Independent verification outside the worker, in Node's own wasm instance.
const bindings = await import(pathToFileURL(join(pkgDir, jsFile)));
const { memory } = await bindings.default({ module_or_path: wasm });
const vk = Uint8Array.from(result.vk);
const proof = Uint8Array.from(result.proof);
const instances = Uint8Array.from(result.instances);
const nodeVerifyStarted = performance.now();
assert.equal(bindings.verify(vk, proof, instances), true);
const nodeVerifyMs = performance.now() - nodeVerifyStarted;
const wrongInstances = instances.slice();
wrongInstances[wrongInstances.length - 1] ^= 1;
assert.equal(bindings.verify(vk, proof, wrongInstances), false);

const report = {
  prepare_ms: result.prepare.ms,
  prove_ms: result.prove.ms,
  verify_ms: result.verify.ms,
  wasm_bytes: wasm.length,
  worker: result.worker && result.prove.inWorker,
  chromiumVersion: browser?.version() ?? null,
  crossOriginIsolated: result.crossOriginIsolated,
  sharedArrayBufferAvailable: result.sharedArrayBufferAvailable,
  detail: {
    vk_bytes: result.prepare.vkBytes,
    pk_bytes: result.prepare.pkBytes,
    proof_bytes: result.prove.proofBytes,
    prepare_memory_bytes: result.prepare.memoryBytes,
    prove_memory_bytes: result.prove.memoryBytes,
    verify_memory_bytes: result.verify.memoryBytes,
    witness_zeroized: result.prove.witnessZeroized,
    wrong_instance_ok: result.wrongInstance.ok,
    tampered_proof_ok: result.tamperedProof.ok,
    node_verify_ms: nodeVerifyMs,
    node_verify_memory_bytes: memory.buffer.byteLength,
    nodeVersion: process.version,
  },
};
if (artifactDir) {
  await writeFile(
    join(artifactDir, "halo2-ipa-web-measurements.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
}
console.log(JSON.stringify(report, null, 2));
