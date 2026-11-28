// Web Worker wrapper around the Halo2 IPA/BN254 wasm-bindgen adapter.
//
// The worker owns the wasm instance. The main thread never imports the wasm
// module, so `prove` metrics are evidence that proving happened off-thread.
// Messages are `{ id, op, ... }` and replies are `{ id, op, ... }` or
// `{ id, error }`.
import init, {
  abi_version,
  circuit_id,
  max_proof_len,
  prepare,
  prove,
  verify,
} from "./pkg/halo2_ipa_prover.js";

let exportsPromise;

function ensureWasm() {
  exportsPromise ??= init(
    new URL("./pkg/halo2_ipa_prover_bg.wasm", import.meta.url),
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
        maxProofLen: max_proof_len(),
        metrics: metrics(exports, performance.now()),
      });
      return;
    }

    if (op === "prepare") {
      const started = performance.now();
      const framed = prepare(data.circuitId ?? circuit_id(), data.k ?? 8);
      const { vk, pk } = splitKeyMaterial(framed);
      self.postMessage(
        {
          id,
          op,
          vk,
          pk,
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
