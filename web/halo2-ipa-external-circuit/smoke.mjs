// Browser smoke for the external Halo2 IPA ChainCircuit adapter.
//
// Serves index.html / page.mjs / worker.mjs / pkg/* from this directory over a
// plain HTTP origin **without** COOP/COEP headers, then drives headless
// Chromium. The page prepares (k=6) and proves in a module Web Worker; the main
// thread verifies. This script independently re-verifies the worker proof and
// the committed native fixture in Node's own wasm instance.
//
// Usage: node smoke.mjs [artifact-dir]
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const webDir = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const artifactDir = process.argv[2];
const pkgDir = join(webDir, "pkg");
const jsFile = "halo2_ipa_external_circuit_wasm.js";
const wasmFile = "halo2_ipa_external_circuit_wasm_bg.wasm";
const fixtureFile = join(repoRoot, "tests/fixtures/halo2_ipa_external_chain_v1.hex");
const EXPECTED_VK_DIGEST =
  "d1d88261a86fa182c8e290a446d6ae6ac0e4f7923f9df6997aee33ef42f73e29";

const [indexHtml, pageMjs, workerMjs, pkgJs, wasm, fixtureText] = await Promise.all([
  readFile(join(webDir, "index.html")),
  readFile(join(webDir, "page.mjs")),
  readFile(join(webDir, "worker.mjs")),
  readFile(join(pkgDir, jsFile)),
  readFile(join(pkgDir, wasmFile)),
  readFile(fixtureFile, "utf8"),
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
  await page.waitForFunction(
    () => window.__halo2IpaExternalResult !== undefined,
    null,
    { timeout: 600_000 },
  );
  result = await page.evaluate(() => window.__halo2IpaExternalResult);
  assert.deepEqual(pageErrors, [], `page errors: ${pageErrors.join("\n")}`);
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}

assert.equal(result.error, undefined, result.error);
assert.equal(result.ok, true, "worker proof did not verify");
assert.equal(result.worker, true, "proving did not run in a Worker");
assert.equal(result.crossOriginIsolated, false, "expected a non-isolated origin");
assert.equal(result.sharedArrayBufferAvailable, false);
assert.equal(result.abiVersion, 1);
assert.equal(result.circuitId, 0x10001);
assert.equal(result.circuitVersion, 1);
assert.equal(result.instanceValues, 17, "expected 17 public values");
assert.equal(result.instanceColumns, 1);
assert.equal(result.witnessValues, 16);
assert.equal(result.k, 6);
assert.equal(result.prepare.inWorker, true);
assert.equal(result.prove.inWorker, true);
assert.equal(result.prove.witnessZeroized, true, "worker witness was not zeroized");
assert.equal(result.prepare.vkDigest, EXPECTED_VK_DIGEST, "VK pin drift");
assert.ok(result.prepare.vkBytes > 0);
assert.ok(result.prepare.pkBytes > 0);
assert.ok(result.prove.proofBytes > 0);
assert.equal(result.verify.ok, true);
assert.equal(result.verify.inWorker, true);
assert.equal(result.wrongInstance.ok, false, "wrong instance was accepted");
assert.equal(result.tamperedProof.ok, false, "tampered proof was accepted");
assert.equal(result.wrongCircuitId.ok, false, "relabelled circuit id was accepted");
assert.equal(result.wrongKey.ok, false, "corrupted VK was accepted");
// "RCH2IPI1" | 1 column | 17 values.
assert.equal(result.instances.length, 8 + 4 + 4 + 17 * 32);

// --- Node re-verification in its own wasm instance -------------------------
const bindings = await import(pathToFileURL(join(pkgDir, jsFile)));
const { memory } = await bindings.default({ module_or_path: wasm });
const nodeVerify = (vk, proof, instances) => {
  try {
    return bindings.verify(vk, proof, instances) === true;
  } catch {
    return false;
  }
};

const vk = Uint8Array.from(result.vk);
const proof = Uint8Array.from(result.proof);
const instances = Uint8Array.from(result.instances);
const nodeVerifyStarted = performance.now();
assert.equal(nodeVerify(vk, proof, instances), true, "Node could not verify worker proof");
const nodeVerifyMs = performance.now() - nodeVerifyStarted;

const wrongInstances = instances.slice();
wrongInstances[wrongInstances.length - 1] ^= 1;
assert.equal(nodeVerify(vk, proof, wrongInstances), false, "Node accepted a wrong instance");
const tamperedProof = proof.slice();
tamperedProof[tamperedProof.length - 1] ^= 1;
assert.equal(nodeVerify(vk, tamperedProof, instances), false, "Node accepted a tampered proof");
const relabelledVk = vk.slice();
new DataView(relabelledVk.buffer).setUint32(8, 0x10002, false);
assert.equal(nodeVerify(relabelledVk, proof, instances), false, "Node accepted a wrong circuit id");

// The committed native fixture must verify in this wasm instance too, and its
// deterministic VK must match the worker's freshly prepared VK.
const fixture = new Map();
for (const line of fixtureText.trim().split("\n")) {
  const separator = line.indexOf("=");
  fixture.set(line.slice(0, separator), Buffer.from(line.slice(separator + 1), "hex"));
}
const fixtureVk = new Uint8Array(fixture.get("VK"));
assert.equal(Buffer.from(vk).equals(Buffer.from(fixtureVk)), true, "worker VK != fixture VK");
assert.equal(
  Buffer.from(bindings.vk_sha256(fixtureVk)).toString("hex"),
  EXPECTED_VK_DIGEST,
  "fixture VK pin drift",
);
const fixtureProof = new Uint8Array(fixture.get("PROOF"));
const fixtureInstances = new Uint8Array(fixture.get("INSTANCES"));
const fixturePk = new Uint8Array(fixture.get("PK"));
const fixtureWitness = new Uint8Array(fixture.get("WITNESS"));
const fixtureVerifyStarted = performance.now();
assert.equal(
  nodeVerify(fixtureVk, fixtureProof, fixtureInstances),
  true,
  "Node could not verify the committed fixture",
);
const fixtureVerifyMs = performance.now() - fixtureVerifyStarted;

// --- Malformed inputs must return error statuses, not trap -----------------
// `panic = "abort"` is used on wasm, so a panic would surface as a
// `RuntimeError: unreachable`. Every rejected input below must instead throw
// the adapter's `... failed: status N` message, which proves the registry
// validated length / canonical Fr / trailing bytes before indexing.
const malformedChecks = {};
function expectStatusError(label, operation) {
  try {
    operation();
  } catch (error) {
    const message = String(error?.message ?? error);
    assert.ok(
      !/unreachable|RuntimeError/.test(message),
      `${label} trapped instead of returning a status: ${message}`,
    );
    assert.match(
      message,
      /failed: status \d+/,
      `${label} did not return an adapter status: ${message}`,
    );
    malformedChecks[label] = true;
    return;
  }
  assert.fail(`${label} was unexpectedly accepted`);
}

const trailingWitness = new Uint8Array(fixtureWitness.length + 1);
trailingWitness.set(fixtureWitness);
const nonCanonicalWitness = new Uint8Array(fixtureWitness.length).fill(0xff);
const nonCanonicalInstances = fixtureInstances.slice();
nonCanonicalInstances.fill(0xff, nonCanonicalInstances.length - 32);
const trailingInstances = new Uint8Array(fixtureInstances.length + 1);
trailingInstances.set(fixtureInstances);

expectStatusError("short_witness", () =>
  bindings.prove(fixturePk, fixtureWitness.slice(0, -1), fixtureInstances),
);
expectStatusError("trailing_witness", () =>
  bindings.prove(fixturePk, trailingWitness, fixtureInstances),
);
expectStatusError("noncanonical_witness", () =>
  bindings.prove(fixturePk, nonCanonicalWitness, fixtureInstances),
);
expectStatusError("short_instances", () =>
  bindings.prove(fixturePk, fixtureWitness, fixtureInstances.slice(0, -1)),
);
expectStatusError("trailing_instances", () =>
  bindings.verify(fixtureVk, fixtureProof, trailingInstances),
);
expectStatusError("noncanonical_instances", () =>
  bindings.verify(fixtureVk, fixtureProof, nonCanonicalInstances),
);
expectStatusError("truncated_vk", () =>
  bindings.verify(fixtureVk.slice(0, -1), fixtureProof, fixtureInstances),
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
    circuit_id: result.circuitId,
    circuit_version: result.circuitVersion,
    k: result.k,
    instance_values: result.instances.length,
    public_values: result.instanceValues,
    witness_values: result.witnessValues,
    vk_digest: result.prepare.vkDigest,
    vk_bytes: result.prepare.vkBytes,
    pk_bytes: result.prepare.pkBytes,
    proof_bytes: result.prove.proofBytes,
    instances_bytes: result.instances.length,
    prepare_memory_bytes: result.prepare.memoryBytes,
    prove_memory_bytes: result.prove.memoryBytes,
    verify_memory_bytes: result.verify.memoryBytes,
    witness_zeroized: result.prove.witnessZeroized,
    wrong_instance_ok: result.wrongInstance.ok,
    tampered_proof_ok: result.tamperedProof.ok,
    wrong_circuit_id_ok: result.wrongCircuitId.ok,
    wrong_key_ok: result.wrongKey.ok,
    malformed_inputs_rejected: Object.keys(malformedChecks),
    node_verify_ms: nodeVerifyMs,
    node_fixture_verify_ms: fixtureVerifyMs,
    node_verify_memory_bytes: memory.buffer.byteLength,
    nodeVersion: process.version,
  },
};
if (artifactDir) {
  await writeFile(
    join(artifactDir, "halo2-ipa-external-web-measurements.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
}
console.log(JSON.stringify(report, null, 2));
