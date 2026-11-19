import init, { prove, proveWithBlindings, verify, verifyWithCommitments } from "./pkg/bulletproofs_r1cs_web.js";

let wasm;

function run({ circuit, publicInputs, witness, blindings, context, proof, expected }) {
  if (witness !== undefined) {
    return blindings === undefined
      ? prove(circuit, publicInputs, witness, context)
      : proveWithBlindings(circuit, publicInputs, witness, blindings, context);
  }
  return expected === undefined
    ? verify(circuit, publicInputs, context, proof)
    : verifyWithCommitments(circuit, publicInputs, context, proof, expected);
}

self.onmessage = async ({ data }) => {
  const { witness, blindings } = data;
  try {
    const { memory } = await (wasm ??= init());
    const started = performance.now();
    const result = run(data);
    const metrics = { milliseconds: performance.now() - started, memoryBytes: memory.buffer.byteLength };
    self.postMessage({ result, metrics }, result instanceof Uint8Array ? [result.buffer] : []);
  } catch (error) {
    self.postMessage({ error: String(error) });
  } finally {
    witness?.fill(0);
    blindings?.fill(0);
  }
};
