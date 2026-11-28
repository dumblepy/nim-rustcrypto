// Web Worker wrapper around the external `ChainCircuit` wasm-bindgen adapter.
//
// The worker owns the wasm instance. The main thread never imports the wasm
// module, so `prepare` / `prove` metrics are evidence that those steps happened
// off-thread. Messages are `{ id, op, ... }` and replies are `{ id, op, ... }`
// or `{ id, error }`.
import init, {
  abi_version,
  circuit_id,
  circuit_version,
  instance_columns,
  instance_values,
  max_k,
  max_proof_len,
  min_k,
  prepare,
  prove,
  verify,
  vk_sha256,
  witness_bytes,
  witness_values,
} from "./pkg/halo2_ipa_external_circuit_wasm.js";

let exportsPromise;

function ensureWasm() {
  exportsPromise ??= init(
    new URL("./pkg/halo2_ipa_external_circuit_wasm_bg.wasm", import.meta.url),
  );
  return exportsPromise;
}

function metrics(exports, started) {
  return {
    milliseconds: performance.now() - started,
    memoryBytes: exports.memory.buffer.byteLength,
    inWorker:
      typeof WorkerGlobalScope !== "undefined" &&
      self instanceof WorkerGlobalScope,
  };
}

function splitKeyMaterial(framed) {
  if (!(framed instanceof Uint8Array) || framed.length < 4) {
    throw new Error("prepare returned a truncated frame");
  }
  const view = new DataView(framed.buffer, framed.byteOffset, framed.byteLength);
  const vkLength = view.getUint32(0, false);
  if (vkLength > framed.length - 4) {
    throw new Error(`prepare returned bogus vk length ${vkLength}`);
  }
  return {
    vk: framed.slice(4, 4 + vkLength),
    pk: framed.slice(4 + vkLength),
  };
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

self.onmessage = async ({ data }) => {
  const { id, op } = data;
  try {
    const exports = await ensureWasm();
    if (op === "info") {
      self.postMessage({
        id,
        op,
        abiVersion: abi_version(),
        circuitId: circuit_id(),
        circuitVersion: circuit_version(),
        instanceValues: instance_values(),
        instanceColumns: instance_columns(),
        witnessValues: witness_values(),
        witnessBytes: witness_bytes(),
        minK: min_k(),
        maxK: max_k(),
        maxProofLen: max_proof_len(),
        metrics: metrics(exports, performance.now()),
      });
      return;
    }

    if (op === "prepare") {
      const started = performance.now();
      const framed = prepare(data.k ?? min_k());
      const { vk, pk } = splitKeyMaterial(framed);
      const digest = vk_sha256(vk);
      self.postMessage(
        {
          id,
          op,
          vk,
          pk,
          vkDigest: hex(digest),
          metrics: metrics(exports, started),
        },
        [vk.buffer, pk.buffer],
      );
      return;
    }

    if (op === "prove") {
      const started = performance.now();
      const witness = data.witness;
      let proof;
      try {
        proof = prove(data.pk, witness, data.instances);
      } finally {
        // The Rust copy is zeroized by the adapter; wipe the transferred
        // worker-side JS buffer too.
        if (witness instanceof Uint8Array) witness.fill(0);
      }
      const witnessZeroized =
        witness instanceof Uint8Array && witness.every((byte) => byte === 0);
      self.postMessage(
        {
          id,
          op,
          proof,
          metrics: { ...metrics(exports, started), witnessZeroized },
        },
        [proof.buffer],
      );
      return;
    }

    if (op === "verify") {
      const started = performance.now();
      const ok = verify(data.vk, data.proof, data.instances);
      self.postMessage({
        id,
        op,
        ok,
        metrics: metrics(exports, started),
      });
      return;
    }

    throw new Error(`unknown operation: ${String(op)}`);
  } catch (error) {
    self.postMessage({
      id,
      op,
      error: String(error?.stack ?? error),
    });
  }
};
