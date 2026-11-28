// Main-thread orchestration for the external Halo2 IPA ChainCircuit smoke.
//
// The wasm module is imported only by worker.mjs. The Worker performs
// `prepare` (k=6, the example profile minimum) and `prove`; the main thread
// verifies. The statement is the 16-step `acc = acc^2 + input` chain over the
// private inputs 1..=16, publishing exactly 17 field elements:
// `[acc_1, .., acc_15, input_0, input_15]`.
//
// Negative checks: a wrong public instance, a tampered proof, a relabelled
// circuit id, and a corrupted VK must all be rejected.
const PROVE_TIMEOUT_MS = 600_000;

// BN254 scalar field modulus.
const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// Deterministic fixture/browser statement: private inputs 1..=16.
const INPUTS = Array.from({ length: 16 }, (_, index) => BigInt(index + 1));
// VK SHA-256 of the k=6 ChainCircuit fixture
// (tests/fixtures/halo2_ipa_external_chain_v1.hex).
const EXPECTED_VK_DIGEST =
  "d1d88261a86fa182c8e290a446d6ae6ac0e4f7923f9df6997aee33ef42f73e29";
const INSTANCES_MAGIC = new TextEncoder().encode("RCH2IPI1");

function encodeFr(value) {
  let remaining = BigInt(value);
  if (remaining < 0n) throw new Error("negative field element");
  if (remaining >= FR_MODULUS) throw new Error("field element is not canonical");
  const out = new Uint8Array(32);
  for (let index = 31; index >= 0; index -= 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

// v1 instances: "RCH2IPI1" | column_count u32 BE | count u32 BE | Fr(32 BE)*.
function encodeInstances(values) {
  const out = new Uint8Array(8 + 4 + 4 + 32 * values.length);
  out.set(INSTANCES_MAGIC, 0);
  const view = new DataView(out.buffer);
  view.setUint32(8, 1, false);
  view.setUint32(12, values.length, false);
  values.forEach((value, index) => {
    out.set(encodeFr(value), 16 + 32 * index);
  });
  return out;
}

// `chain_public_values` from the external crate, reproduced in JS.
function chainPublicValues(inputs) {
  let current = inputs[0];
  const accumulators = [current];
  for (let index = 1; index < inputs.length; index += 1) {
    current = (current * current + inputs[index]) % FR_MODULUS;
    accumulators.push(current);
  }
  const publicValues = accumulators.slice(1);
  publicValues.push(inputs[0]);
  publicValues.push(inputs[inputs.length - 1]);
  return publicValues;
}

function flipLastByte(bytes) {
  const out = bytes.slice();
  out[out.length - 1] ^= 1;
  return out;
}

// V2 VK envelope: magic(8) | circuit_id u32 BE(4) | k u32 BE(4) | len(4) | ...
function relabelCircuitId(bytes, circuitId) {
  const out = bytes.slice();
  new DataView(out.buffer).setUint32(8, circuitId, false);
  return out;
}

function corruptVkPayload(bytes) {
  const out = bytes.slice();
  out[out.length - 1] ^= 1;
  return out;
}

function concatBytes(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function callWorker(worker, op, payload = {}, transfer = []) {
  const id = callWorker.nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`worker ${op} timed out after ${PROVE_TIMEOUT_MS} ms`));
    }, PROVE_TIMEOUT_MS);
    const cleanup = () => {
      clearTimeout(timer);
      worker.removeEventListener("message", onMessage);
      worker.removeEventListener("error", onError);
    };
    const onMessage = ({ data }) => {
      if (data?.id !== id) return;
      cleanup();
      if (data.error) reject(new Error(data.error));
      else resolve(data);
    };
    const onError = (event) => {
      cleanup();
      reject(new Error(event.message || "worker error"));
    };
    worker.addEventListener("message", onMessage);
    worker.addEventListener("error", onError);
    worker.postMessage({ id, op, ...payload }, transfer);
  });
}
callWorker.nextId = 1;

// A malformed/foreign input makes the adapter throw; for negative checks that
// is the same outcome as `ok === false`.
async function expectRejected(promise) {
  try {
    const result = await promise;
    return { ok: result.ok === true };
  } catch {
    return { ok: false };
  }
}

async function run() {
  const crossOriginIsolated = globalThis.crossOriginIsolated === true;
  if (crossOriginIsolated !== false) {
    throw new Error(
      `expected crossOriginIsolated === false, got ${crossOriginIsolated}`,
    );
  }

  const publicValues = chainPublicValues(INPUTS);
  if (publicValues.length !== 17) {
    throw new Error(`expected 17 public values, got ${publicValues.length}`);
  }
  const witness = concatBytes(INPUTS.map((value) => encodeFr(value)));
  const instances = encodeInstances(publicValues);

  const worker = new Worker("./worker.mjs", { type: "module" });
  try {
    const info = await callWorker(worker, "info");
    if (info.abiVersion !== 1) throw new Error(`unexpected abi ${info.abiVersion}`);
    if (info.circuitId !== 0x10001) {
      throw new Error(`unexpected circuit ${info.circuitId}`);
    }
    if (info.circuitVersion !== 1) {
      throw new Error(`unexpected circuit version ${info.circuitVersion}`);
    }
    if (info.instanceValues !== 17) {
      throw new Error(`unexpected instance value count ${info.instanceValues}`);
    }
    if (info.instanceColumns !== 1) {
      throw new Error(`unexpected instance column count ${info.instanceColumns}`);
    }
    if (info.witnessValues !== 16) {
      throw new Error(`unexpected witness value count ${info.witnessValues}`);
    }

    const k = info.minK;
    const prepared = await callWorker(worker, "prepare", { k });
    const preparedSizes = {
      vkBytes: prepared.vk.length,
      pkBytes: prepared.pk.length,
    };
    if (prepared.vkDigest !== EXPECTED_VK_DIGEST) {
      throw new Error(
        `VK pin mismatch: ${prepared.vkDigest} != ${EXPECTED_VK_DIGEST}`,
      );
    }

    // Transfer the PK and witness copies to the worker. The worker zeroizes
    // the witness buffer after the Rust adapter has copied it.
    const proved = await callWorker(
      worker,
      "prove",
      { pk: prepared.pk, witness, instances },
      [prepared.pk.buffer, witness.buffer],
    );

    const verified = await callWorker(worker, "verify", {
      vk: prepared.vk,
      proof: proved.proof,
      instances,
    });

    const wrongInstance = await callWorker(worker, "verify", {
      vk: prepared.vk,
      proof: proved.proof,
      instances: flipLastByte(instances),
    });

    const tampered = proved.proof.slice();
    tampered[tampered.length - 1] ^= 1;
    const tamperedProof = await expectRejected(
      callWorker(worker, "verify", {
        vk: prepared.vk,
        proof: tampered,
        instances,
      }),
    );

    const wrongCircuitId = await expectRejected(
      callWorker(worker, "verify", {
        vk: relabelCircuitId(prepared.vk, 0x10002),
        proof: proved.proof,
        instances,
      }),
    );

    const wrongKey = await expectRejected(
      callWorker(worker, "verify", {
        vk: corruptVkPayload(prepared.vk),
        proof: proved.proof,
        instances,
      }),
    );

    return {
      ok: verified.ok === true,
      worker: proved.metrics.inWorker === true,
      crossOriginIsolated,
      sharedArrayBufferAvailable: typeof SharedArrayBuffer !== "undefined",
      abiVersion: info.abiVersion,
      circuitId: info.circuitId,
      circuitVersion: info.circuitVersion,
      instanceValues: publicValues.length,
      instanceColumns: info.instanceColumns,
      witnessValues: info.witnessValues,
      k,
      prepare: {
        ms: prepared.metrics.milliseconds,
        vkBytes: preparedSizes.vkBytes,
        pkBytes: preparedSizes.pkBytes,
        vkDigest: prepared.vkDigest,
        memoryBytes: prepared.metrics.memoryBytes,
        inWorker: prepared.metrics.inWorker,
      },
      prove: {
        ms: proved.metrics.milliseconds,
        proofBytes: proved.proof.length,
        memoryBytes: proved.metrics.memoryBytes,
        inWorker: proved.metrics.inWorker,
        witnessZeroized: proved.metrics.witnessZeroized,
      },
      verify: {
        ms: verified.metrics.milliseconds,
        ok: verified.ok,
        memoryBytes: verified.metrics.memoryBytes,
        inWorker: verified.metrics.inWorker,
      },
      wrongInstance: { ok: wrongInstance.ok },
      tamperedProof,
      wrongCircuitId,
      wrongKey,
      vk: Array.from(prepared.vk),
      proof: Array.from(proved.proof),
      instances: Array.from(instances),
    };
  } finally {
    worker.terminate();
  }
}

function publish(result) {
  window.__halo2IpaExternalResult = result;
  document.querySelector("#result").textContent = JSON.stringify(result);
}

run()
  .then(publish)
  .catch((error) => {
    publish({
      error: String(error?.stack ?? error),
      crossOriginIsolated: globalThis.crossOriginIsolated === true,
    });
  });
