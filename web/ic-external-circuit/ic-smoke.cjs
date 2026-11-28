// PocketIC smoke + measurement for the external ChainCircuit verify-only canister.
//
// Usage:
//   node ic-smoke.cjs <artifact-dir> <halo2-ipa-external.wasm>
//
// `@dfinity/pic` is reused from `web/groth16-prover/node_modules` (which also
// bundles the PocketIC server binary) so this directory needs no own install.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');

const picRequire = createRequire(
  path.resolve(__dirname, '../groth16-prover/package.json'),
);
const { PocketIc, PocketIcServer } = picRequire('@dfinity/pic');
const picVersion = picRequire('@dfinity/pic/package.json').version;

const [artifactDir, wasmPath] = process.argv.slice(2);
if (!artifactDir || !wasmPath) {
  console.error('usage: node ic-smoke.cjs <artifact-dir> <halo2-ipa-external.wasm>');
  process.exit(2);
}

const MAX_IPA_INSTRUCTIONS = 30_000_000_000n;
const MAX_IPA_MEMORY_BYTES = 512 * 1024 * 1024;
const MAX_PROOF_BYTES = 2 * 1024 * 1024;
const MAX_INSTANCES_BYTES = 1024 * 1024;

function readVarUint(bytes, offset) {
  let result = 0;
  let shift = 0;
  let byte;
  do {
    if (offset >= bytes.length) throw new Error('truncated varuint');
    byte = bytes[offset++];
    result += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if (shift > 35) throw new Error('varuint too long');
  } while (byte & 0x80);
  return [result, offset];
}

function readName(bytes, offset) {
  const [length, next] = readVarUint(bytes, offset);
  return [bytes.subarray(next, next + length).toString('utf8'), next + length];
}

function functionCounts(bytes) {
  let offset = 8;
  let defined = 0;
  let imported = 0;
  while (offset < bytes.length) {
    const id = bytes[offset++];
    const [size, payloadStart] = readVarUint(bytes, offset);
    const payloadEnd = payloadStart + size;
    if (id === 2) {
      const [count, afterCount] = readVarUint(bytes, payloadStart);
      let cursor = afterCount;
      for (let index = 0; index < count; index += 1) {
        let module;
        let name;
        [module, cursor] = readName(bytes, cursor);
        [name, cursor] = readName(bytes, cursor);
        const kind = bytes[cursor++];
        assert(kind <= 4, `bad import kind for ${module}.${name}`);
        if (kind === 0) {
          imported += 1;
          [, cursor] = readVarUint(bytes, cursor);
        } else if (kind === 1) {
          cursor += 1;
          const [limitsFlags, afterFlags] = readVarUint(bytes, cursor);
          cursor = afterFlags;
          [, cursor] = readVarUint(bytes, cursor);
          if (limitsFlags & 1) [, cursor] = readVarUint(bytes, cursor);
        } else if (kind === 2) {
          const [flags, afterFlags] = readVarUint(bytes, cursor);
          cursor = afterFlags;
          [, cursor] = readVarUint(bytes, cursor);
          if (flags & 1) [, cursor] = readVarUint(bytes, cursor);
        } else if (kind === 3) {
          cursor += 2;
        } else if (kind === 4) {
          [, cursor] = readVarUint(bytes, cursor);
        }
      }
    } else if (id === 3) {
      [defined] = readVarUint(bytes, payloadStart);
    }
    offset = payloadEnd;
  }
  return { imported, defined, total: imported + defined };
}

function inspectWasm(file) {
  const bytes = fs.readFileSync(file);
  const module = new WebAssembly.Module(bytes);
  const imports = WebAssembly.Module.imports(module);
  const exports = WebAssembly.Module.exports(module);
  for (const entry of imports) {
    assert.equal(
      entry.module,
      'ic0',
      `unexpected wasm import ${entry.module}.${entry.name} in ${file}`,
    );
  }
  return {
    file: path.basename(file),
    bytes: bytes.length,
    imports,
    exports: exports.map((entry) => entry.name),
    functions: functionCounts(bytes),
  };
}

function sha256(buffer) {
  return require('node:crypto').createHash('sha256').update(buffer).digest('hex');
}

// Calls the update export against a mock `ic0` to exercise the pre-copy length
// guard for arguments larger than the IC ingress limit (2 MiB).
function directGuardCheck(file, exportName, argSize) {
  const bytes = fs.readFileSync(file);
  const module = new WebAssembly.Module(bytes);
  let memory;
  let copied = false;
  let reply = null;
  const imports = {
    ic0: {
      msg_arg_data_size: () => argSize,
      msg_arg_data_copy: () => {
        copied = true;
      },
      performance_counter: () => 0n,
      msg_reply_data_append: (src, size) => {
        reply = Buffer.from(new Uint8Array(memory.buffer, src, size));
      },
      msg_reply: () => {},
    },
  };
  const instance = new WebAssembly.Instance(module, imports);
  memory = instance.exports.memory;
  instance.exports[exportName]();
  assert(reply !== null, 'mock canister did not reply');
  return { status: reply.readInt32LE(0), argBytes: argSize, copied };
}

(async () => {
  const read = (name) => fs.readFileSync(path.join(artifactDir, name));
  const vk = read('vk.bin');
  const proof = read('proof.bin');
  const instances = read('instances.bin');
  const witness = read('witness.bin');

  assert.equal(vk.length, 158, 'external ChainCircuit VK length');
  assert.equal(vk.subarray(0, 8).toString('ascii'), 'RCH2IPV2', 'V2 VK magic');
  assert.equal(vk.readUInt32BE(8), 0x10001, 'ChainCircuit id');
  assert.equal(vk.readUInt32BE(12), 6, 'fixture k');
  assert.equal(proof.subarray(0, 8).toString('ascii'), 'RCH2IPF1', 'proof magic');
  assert.equal(instances.length, 8 + 4 + 4 + 17 * 32, 'instances length');
  assert.equal(instances.subarray(0, 8).toString('ascii'), 'RCH2IPI1', 'instances magic');
  assert.equal(instances.readUInt32BE(8), 1, 'instance column count');
  assert.equal(instances.readUInt32BE(12), 17, 'instance value count');
  assert.equal(witness.length, 16 * 32, 'witness length');

  const wasm = inspectWasm(wasmPath);
  for (const needed of ['canister_update verify', 'rustcrypto_halo2_ipa_external_chain_verify']) {
    assert(wasm.exports.includes(needed), `wasm must export ${needed}`);
  }
  for (const forbidden of wasm.exports) {
    assert(
      !/(^|_)prepare$|(^|_)prove$|keygen|create_proof/i.test(forbidden),
      `prover symbol exported from wasm: ${forbidden}`,
    );
  }

  const server = await PocketIcServer.start();
  let pic;
  try {
    pic = await PocketIc.create(server.getUrl());
    const canister = await pic.createCanister();
    await pic.addCycles(canister, 2_000_000_000_000n);
    await pic.installCode({ canisterId: canister, wasm: fs.readFileSync(wasmPath) });

    const verifyArg = Buffer.concat([proof, instances]);
    const cyclesBefore = await pic.getCyclesBalance(canister);
    const verifyReply = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: verifyArg }),
    );
    const cyclesAfter = await pic.getCyclesBalance(canister);
    assert.equal(verifyReply.length, 16, 'reply length');
    const status = verifyReply.readInt32LE(0);
    const coldInstructions = verifyReply.readBigUInt64LE(4);
    const pages = verifyReply.readUInt32LE(12);
    assert.equal(status, 0, 'fixture ChainCircuit proof must verify');
    assert(coldInstructions < MAX_IPA_INSTRUCTIONS, `instruction budget (${coldInstructions})`);
    assert(pages * 65536 < MAX_IPA_MEMORY_BYTES, `memory budget (${pages} pages)`);

    const warmReply = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: verifyArg }),
    );
    assert.equal(warmReply.length, 16, 'warm reply length');
    const warmStatus = warmReply.readInt32LE(0);
    const warmInstructions = warmReply.readBigUInt64LE(4);
    const warmPages = warmReply.readUInt32LE(12);
    assert.equal(warmStatus, 0, 'warm fixture proof must verify');
    assert(warmInstructions < MAX_IPA_INSTRUCTIONS, 'warm instruction budget');
    assert(warmInstructions <= coldInstructions, 'warm call should not exceed cold');

    const tamperedProof = Buffer.from(verifyArg);
    tamperedProof[proof.length - 1] ^= 1;
    const tamperedProofStatus = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: tamperedProof }),
    ).readInt32LE(0);
    assert.notEqual(tamperedProofStatus, 0, 'tampered proof must be rejected');

    const wrongInstances = Buffer.from(verifyArg);
    wrongInstances[verifyArg.length - 1] ^= 1;
    const wrongInstancesStatus = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: wrongInstances }),
    ).readInt32LE(0);
    assert.notEqual(wrongInstancesStatus, 0, 'wrong instances must be rejected');

    const badEnvelope = Buffer.alloc(1024 * 1024);
    badEnvelope.write('RCH2IPF1', 0, 'ascii');
    badEnvelope.writeUInt32BE(0xffffffff, 8);
    const badEnvelopeStatus = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: badEnvelope }),
    ).readInt32LE(0);
    assert.notEqual(badEnvelopeStatus, 0, 'impossible proof length must be rejected');

    // A V1-magic key artifact passed as the request cannot be mistaken for a
    // proof: the envelope magic is RCH2IPV1, not RCH2IPF1.
    const v1MagicArtifact = Buffer.concat([Buffer.alloc(158), instances]);
    v1MagicArtifact.write('RCH2IPV1', 0, 'ascii');
    const v1MagicStatus = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: v1MagicArtifact }),
    ).readInt32LE(0);
    assert.notEqual(v1MagicStatus, 0, 'V1-magic artifact must be rejected');

    // The pinned VK is not an input, but a request that starts with the VK
    // envelope must still fail the proof framing check.
    const vkArtifactStatus = Buffer.from(
      await pic.updateCall({
        canisterId: canister,
        method: 'verify',
        arg: Buffer.concat([vk, instances]),
      }),
    ).readInt32LE(0);
    assert.notEqual(vkArtifactStatus, 0, 'VK artifact must not be accepted as a proof');

    // Non-canonical trailing field element (all 0xff) in the last instance.
    const nonCanonical = Buffer.from(verifyArg);
    nonCanonical.fill(0xff, nonCanonical.length - 32);
    const nonCanonicalStatus = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: nonCanonical }),
    ).readInt32LE(0);
    assert.notEqual(nonCanonicalStatus, 0, 'non-canonical instance must be rejected');

    const trailingByte = Buffer.concat([verifyArg, Buffer.from([0])]);
    const trailingStatus = Buffer.from(
      await pic.updateCall({ canisterId: canister, method: 'verify', arg: trailingByte }),
    ).readInt32LE(0);
    assert.notEqual(trailingStatus, 0, 'trailing byte must be rejected');

    const oversized = Buffer.alloc(MAX_PROOF_BYTES + MAX_INSTANCES_BYTES + 13);
    const oversizedStatus = directGuardCheck(wasmPath, 'canister_update verify', oversized.length);
    assert.notEqual(oversizedStatus.status, 0, 'oversized argument must be rejected');
    assert.equal(oversizedStatus.copied, false, 'oversized argument rejected before copy');

    const report = {
      runtime: { pocketIc: picVersion, node: process.version },
      fixture: {
        vkBytes: vk.length,
        proofBytes: proof.length,
        instancesBytes: instances.length,
        witnessBytes: witness.length,
        vkSha256: sha256(vk),
        proofSha256: sha256(proof),
        circuitId: vk.readUInt32BE(8),
        k: vk.readUInt32BE(12),
      },
      wasm,
      verify: {
        status,
        coldInstructions: coldInstructions.toString(),
        warmInstructions: warmInstructions.toString(),
        warmStatus,
        memoryPages: pages,
        memoryBytes: pages * 65536,
        warmMemoryPages: warmPages,
        warmMemoryBytes: warmPages * 65536,
        updateCyclesDebited: (cyclesBefore - cyclesAfter).toString(),
        argBytes: verifyArg.length,
        tamperedProofStatus,
        wrongInstancesStatus,
        oversizedDirectGuard: oversizedStatus,
        badEnvelopeStatus,
        v1MagicStatus,
        vkArtifactStatus,
        nonCanonicalStatus,
        trailingStatus,
      },
      budgets: {
        maxInstructions: MAX_IPA_INSTRUCTIONS.toString(),
        maxMemoryBytes: MAX_IPA_MEMORY_BYTES,
      },
      note: 'Local PocketIC update cost includes ingress and execution fees. It is not a mainnet cycle quote. Instructions are the in-canister performance_counter delta.',
    };
    fs.writeFileSync(
      path.join(artifactDir, 'ic-measurements.json'),
      `${JSON.stringify(report, null, 2)}\n`,
    );
    console.log(JSON.stringify(report, null, 2));
  } finally {
    if (pic) await pic.tearDown();
    await server.stop();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
