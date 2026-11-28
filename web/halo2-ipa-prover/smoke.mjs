// Browser smoke for the Halo2 IPA/BN254 prover.
//
// Serves index.html / page.mjs / worker.mjs / pkg/* from this directory over a
// plain HTTP origin **without** COOP/COEP headers, then drives headless
// Chromium. The page prepares and proves two approved circuits sequentially in
// a module Web Worker, verifies both proofs, and rejects a wrong public
// instance / digest and a tampered proof. This script independently re-verifies
// both worker-produced proofs in Node's own wasm instance.
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
const POSEIDON2_DIGEST_HEX =
  "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8";
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

// --- Circuit 1 result object ------------------------------------------------
assert.ok(result.circuits, "missing per-circuit results");
const cubic = result.circuits.cubic;
assert.equal(cubic.circuitId, 1);
assert.equal(cubic.k, 8);
assert.equal(cubic.prepare.inWorker, true);
assert.equal(cubic.prove.inWorker, true);
assert.equal(cubic.prove.witnessZeroized, true);
assert.equal(cubic.verify.ok, true);
assert.equal(cubic.wrongInstance.ok, false);
assert.equal(cubic.tamperedProof.ok, false);
assert.ok(cubic.prove.proofBytes > 0);
assert.ok(cubic.prepare.vkBytes > 0);
assert.ok(cubic.prepare.pkBytes > 0);

// --- Circuit 2 result object (3-input Poseidon2 hash) ----------------------
const poseidon2 = result.circuits.poseidon2;
assert.ok(poseidon2, "missing Poseidon2 circuit result");
assert.equal(poseidon2.circuitId, 2);
assert.equal(poseidon2.k, 8);
assert.equal(poseidon2.prepare.inWorker, true);
assert.equal(poseidon2.prove.inWorker, true);
assert.equal(poseidon2.prove.witnessZeroized, true);
assert.ok(poseidon2.prepare.vkBytes > 0);
assert.ok(poseidon2.prepare.pkBytes > 0);
assert.ok(poseidon2.prove.proofBytes > 0);
assert.equal(poseidon2.verify.ok, true, "Poseidon2 proof did not verify");
assert.equal(poseidon2.verify.inWorker, true);
assert.equal(poseidon2.wrongDigest.ok, false, "wrong digest was accepted");
assert.equal(poseidon2.tamperedProof.ok, false, "tampered Poseidon2 proof was accepted");
assert.equal(poseidon2.digest, POSEIDON2_DIGEST_HEX);
assert.deepEqual(poseidon2.inputs, ["1", "2", "3"]);
// "RCH2IPI1" | 1 column | 4 values | digest | input0 | input1 | input2
assert.equal(poseidon2.instances.length, 8 + 4 + 4 + 4 * 32);
const poseidon2Instances = Uint8Array.from(poseidon2.instances);
assert.equal(
  Buffer.from(poseidon2Instances.subarray(16, 48)).toString("hex"),
  POSEIDON2_DIGEST_HEX,
  "published digest is not the KAT",
);
assert.equal(poseidon2Instances[48 + 31], 1);
assert.equal(poseidon2Instances[80 + 31], 2);
assert.equal(poseidon2Instances[112 + 31], 3);

// Independent verification outside the worker, in Node's own wasm instance.
const bindings = await import(pathToFileURL(join(pkgDir, jsFile)));
const { memory } = await bindings.default({ module_or_path: wasm });
// `verify` returns false for cryptographic failures and throws for malformed
// input; for the negative checks both mean "rejected".
const nodeVerify = (vk, proof, instances) => {
  try {
    return bindings.verify(vk, proof, instances) === true;
  } catch {
    return false;
  }
};

const cubicVk = Uint8Array.from(result.vk);
const cubicProof = Uint8Array.from(result.proof);
const cubicInstances = Uint8Array.from(result.instances);
const nodeVerifyStarted = performance.now();
assert.equal(nodeVerify(cubicVk, cubicProof, cubicInstances), true);
const nodeVerifyMs = performance.now() - nodeVerifyStarted;
const wrongInstances = cubicInstances.slice();
wrongInstances[wrongInstances.length - 1] ^= 1;
assert.equal(nodeVerify(cubicVk, cubicProof, wrongInstances), false);

const poseidon2Vk = Uint8Array.from(poseidon2.vk);
const poseidon2Proof = Uint8Array.from(poseidon2.proof);
const poseidon2NodeVerifyStarted = performance.now();
assert.equal(
  nodeVerify(poseidon2Vk, poseidon2Proof, poseidon2Instances),
  true,
  "Node could not verify the Poseidon2 proof",
);
const poseidon2NodeVerifyMs = performance.now() - poseidon2NodeVerifyStarted;
const wrongDigestInstances = poseidon2Instances.slice();
wrongDigestInstances[16 + 31] ^= 1;
assert.equal(
  nodeVerify(poseidon2Vk, poseidon2Proof, wrongDigestInstances),
  false,
  "Node accepted a wrong Poseidon2 digest",
);
const tamperedPoseidon2Proof = poseidon2Proof.slice();
tamperedPoseidon2Proof[tamperedPoseidon2Proof.length - 1] ^= 1;
assert.equal(
  nodeVerify(poseidon2Vk, tamperedPoseidon2Proof, poseidon2Instances),
  false,
  "Node accepted a tampered Poseidon2 proof",
);

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
    circuit_id: 1,
    k: 8,
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
  poseidon2: {
    prepare_ms: poseidon2.prepare.ms,
    prove_ms: poseidon2.prove.ms,
    verify_ms: poseidon2.verify.ms,
    wasm_bytes: wasm.length,
    detail: {
      circuit_id: 2,
      k: 8,
      input_count: 3,
      digest: poseidon2.digest,
      vk_bytes: poseidon2.prepare.vkBytes,
      pk_bytes: poseidon2.prepare.pkBytes,
      proof_bytes: poseidon2.prove.proofBytes,
      instances_bytes: poseidon2.instances.length,
      prepare_memory_bytes: poseidon2.prepare.memoryBytes,
      prove_memory_bytes: poseidon2.prove.memoryBytes,
      verify_memory_bytes: poseidon2.verify.memoryBytes,
      witness_zeroized: poseidon2.prove.witnessZeroized,
      wrong_digest_ok: poseidon2.wrongDigest.ok,
      tampered_proof_ok: poseidon2.tamperedProof.ok,
      node_verify_ms: poseidon2NodeVerifyMs,
      node_verify_memory_bytes: memory.buffer.byteLength,
      nodeVersion: process.version,
    },
  },
};
if (artifactDir) {
  await writeFile(
    join(artifactDir, "halo2-ipa-web-measurements.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
}
console.log(JSON.stringify(report, null, 2));
