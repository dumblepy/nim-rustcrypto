// Main-thread orchestration for the Halo2 IPA/BN254 browser smoke.
//
// The wasm module is imported only by worker.mjs. This page creates the worker,
// asks it to prepare (keygen) and prove, then asks it to verify the proof and to
// reject a wrong public instance. The final object is published on
// `window.__halo2IpaResult` for smoke.mjs.
const PROVE_TIMEOUT_MS = 600_000;
const INSTANCES_MAGIC = new TextEncoder().encode("RCH2IPI1");

function encodeFr(value) {
  let remaining = BigInt(value);
  if (remaining < 0n) throw new Error("negative field element");
  const out = new Uint8Array(32);
  for (let index = 31; index >= 0; index -= 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error("field element does not fit in 32 bytes");
  return out;
}

// v1 instances: "RCH2IPI1" | column_count u32 BE | count u32 BE | Fr(32 BE).
function encodeInstances(y) {
  const out = new Uint8Array(8 + 4 + 4 + 32);
  out.set(INSTANCES_MAGIC, 0);
  const view = new DataView(out.buffer);
  view.setUint32(8, 1, false);
  view.setUint32(12, 1, false);
  out.set(encodeFr(y), 16);
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

async function run() {
  const crossOriginIsolated = globalThis.crossOriginIsolated === true;
  if (crossOriginIsolated !== false) {
    throw new Error(
      `expected crossOriginIsolated === false, got ${crossOriginIsolated}`,
    );
  }

  const worker = new Worker("./worker.mjs", { type: "module" });
  try {
    const info = await callWorker(worker, "info");
    if (info.abiVersion !== 1) throw new Error(`unexpected abi ${info.abiVersion}`);
    if (info.circuitId !== 1) throw new Error(`unexpected circuit ${info.circuitId}`);

    // Deterministic transparent setup: same params for every caller at k=8.
    const prepared = await callWorker(worker, "prepare", { circuitId: 1, k: 8 });
    const preparedSizes = {
      vkBytes: prepared.vk.length,
      pkBytes: prepared.pk.length,
    };

    // Circuit 1: public y = x^3 + x + 5, witness x = 3 => y = 35.
    const witness = encodeFr(3n);
    const instances = encodeInstances(35n);
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

    const wrongInstances = instances.slice();
    wrongInstances[wrongInstances.length - 1] ^= 1;
    const wrong = await callWorker(worker, "verify", {
      vk: prepared.vk,
      proof: proved.proof,
      instances: wrongInstances,
    });

    const tamperedProof = proved.proof.slice();
    tamperedProof[tamperedProof.length - 1] ^= 1;
    const tampered = await callWorker(worker, "verify", {
      vk: prepared.vk,
      proof: tamperedProof,
      instances,
    }).catch(() => ({ ok: false }));

    return {
      ok: verified.ok === true,
      worker: proved.metrics.inWorker === true,
      crossOriginIsolated,
      sharedArrayBufferAvailable: typeof SharedArrayBuffer !== "undefined",
      abiVersion: info.abiVersion,
      circuitId: info.circuitId,
      maxProofLen: info.maxProofLen,
      prepare: {
        ms: prepared.metrics.milliseconds,
        vkBytes: preparedSizes.vkBytes,
        pkBytes: preparedSizes.pkBytes,
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
      wrongInstance: { ok: wrong.ok },
      tamperedProof: { ok: tampered.ok },
      vk: Array.from(prepared.vk),
      proof: Array.from(proved.proof),
      instances: Array.from(instances),
    };
  } finally {
    worker.terminate();
  }
}

function publish(result) {
  window.__halo2IpaResult = result;
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
