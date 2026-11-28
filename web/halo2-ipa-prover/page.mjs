// Main-thread orchestration for the Halo2 IPA/BN254 browser smoke.
//
// The wasm module is imported only by worker.mjs. This page creates the worker
// and runs two approved circuits sequentially:
//
// - circuit 1: cubic `y = x^3 + x + 5`, witness x = 3 => public y = 35.
// - circuit 2: 3-input Poseidon2 hash (k=8), witness = 3 canonical BE Fr and
//   public `[digest, input0, input1, input2]`.
//
// Both circuits are prepared and proved inside the Worker, then verified there.
// Wrong public inputs and a tampered proof must be rejected. The final object
// is published on `window.__halo2IpaResult` for smoke.mjs. The top-level
// `ok/worker/.../prepare/prove/verify/...` fields keep the circuit-1 shape for
// compatibility; `circuits` contains both results.
const PROVE_TIMEOUT_MS = 600_000;
const INSTANCES_MAGIC = new TextEncoder().encode("RCH2IPI1");
const POSEIDON2_INPUTS = [1n, 2n, 3n];
const POSEIDON2_DIGEST_HEX =
  "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8";

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

// v1 instances: "RCH2IPI1" | column_count u32 BE | count u32 BE | Fr(32 BE)*.
// Both approved circuits use a single column: cubic has 1 value, Poseidon2
// hash3 has 4 values `[digest, input0, input1, input2]`.
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

function flipLastByte(bytes) {
  const out = bytes.slice();
  out[out.length - 1] ^= 1;
  return out;
}

// v1 instances header is 16 bytes; the digest is the first 32-byte value.
function flipFirstValue(bytes) {
  const out = bytes.slice();
  out[16 + 31] ^= 1;
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

function summarize(
  circuitId,
  k,
  preparedSizes,
  prepared,
  proved,
  verified,
  wrong,
  tampered,
) {
  return {
    circuitId,
    k,
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
  };
}

// Runs prepare/prove/verify/negative checks for one circuit inside `worker`.
// `makeWrongInstances` defaults to flipping the last public byte; circuit 2
// overrides it to flip the digest (the first of its four public values).
async function runCircuit(
  worker,
  { circuitId, k, witness, instances, makeWrongInstances = flipLastByte },
) {
  const prepared = await callWorker(worker, "prepare", { circuitId, k });
  // The PK buffer is transferred (and therefore detached) below, so record
  // the sizes before handing it to the worker.
  const preparedSizes = {
    vkBytes: prepared.vk.length,
    pkBytes: prepared.pk.length,
  };

  // Transfer the PK and witness copies to the worker. The worker zeroizes the
  // witness buffer after the Rust adapter has copied it.
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

  const wrongInstances = makeWrongInstances(instances);
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
    result: summarize(
      circuitId,
      k,
      preparedSizes,
      prepared,
      proved,
      verified,
      wrong,
      tampered,
    ),
    prepared,
    proved,
    instances,
  };
}

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

    // Circuit 1: deterministic transparent setup at k=8. Public y = 35 for x=3.
    const cubic = await runCircuit(worker, {
      circuitId: 1,
      k: 8,
      witness: encodeFr(3n),
      instances: encodeInstances([35n]),
    });

    // Circuit 2: 3-input Poseidon2 hash, k=8. Witness is the concatenation of
    // three canonical 32-byte BE Fr values; digest is the Noir/Barretenberg
    // sponge KAT for [1, 2, 3].
    const poseidon2Digest = BigInt(`0x${POSEIDON2_DIGEST_HEX}`);
    const poseidon2 = await runCircuit(worker, {
      circuitId: 2,
      k: 8,
      witness: concatBytes(POSEIDON2_INPUTS.map((value) => encodeFr(value))),
      instances: encodeInstances([poseidon2Digest, ...POSEIDON2_INPUTS]),
      makeWrongInstances: flipFirstValue,
    });

    const cubicResult = {
      ...cubic.result,
      vk: Array.from(cubic.prepared.vk),
      proof: Array.from(cubic.proved.proof),
      instances: Array.from(cubic.instances),
    };
    const poseidon2Result = {
      ...poseidon2.result,
      // Circuit 2's negative check flips the digest value (not input2), so
      // expose it under the statement-specific name as well.
      wrongDigest: poseidon2.result.wrongInstance,
      digest: POSEIDON2_DIGEST_HEX,
      inputs: POSEIDON2_INPUTS.map((value) => value.toString()),
      vk: Array.from(poseidon2.prepared.vk),
      proof: Array.from(poseidon2.proved.proof),
      instances: Array.from(poseidon2.instances),
    };

    return {
      // Backwards-compatible circuit-1 fields.
      ok: cubic.result.verify.ok === true,
      worker: cubic.proved.metrics.inWorker === true,
      crossOriginIsolated,
      sharedArrayBufferAvailable: typeof SharedArrayBuffer !== "undefined",
      abiVersion: info.abiVersion,
      circuitId: info.circuitId,
      maxProofLen: info.maxProofLen,
      prepare: cubicResult.prepare,
      prove: cubicResult.prove,
      verify: cubicResult.verify,
      wrongInstance: cubicResult.wrongInstance,
      tamperedProof: cubicResult.tamperedProof,
      vk: cubicResult.vk,
      proof: cubicResult.proof,
      instances: cubicResult.instances,
      circuits: {
        cubic: cubicResult,
        poseidon2: poseidon2Result,
      },
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
