// PocketIC smoke + measurement for the branch-85 ICP canisters.
//
// Usage:
//   node ic-smoke.cjs <artifact-dir> <halo2-ipa.wasm> <poseidon2.wasm>
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

const [artifactDir, ipaWasmPath, poseidonWasmPath] = process.argv.slice(2);
if (!artifactDir || !ipaWasmPath || !poseidonWasmPath) {
  console.error(
    'usage: node ic-smoke.cjs <artifact-dir> <halo2-ipa.wasm> <poseidon2.wasm>',
  );
  process.exit(2);
}

const EXPECTED_POSEIDON2_123 =
  '23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8';
const MAX_IPA_INSTRUCTIONS = 30_000_000_000n;
const MAX_IPA_MEMORY_BYTES = 512 * 1024 * 1024;
const MAX_POSEIDON2_INSTRUCTIONS = 10_000_000n;
const MAX_POSEIDON2_MEMORY_BYTES = 64 * 1024 * 1024;

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

// Counts imported and defined functions directly from the module binary so the
// report does not depend on a JS glue layer.
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

function inspectWasm(wasmPath) {
  const bytes = fs.readFileSync(wasmPath);
  const module = new WebAssembly.Module(bytes);
  const imports = WebAssembly.Module.imports(module);
  const exports = WebAssembly.Module.exports(module);
  for (const entry of imports) {
    assert.equal(
      entry.module,
      'ic0',
      `unexpected wasm import ${entry.module}.${entry.name} in ${wasmPath}`,
    );
  }
  const counts = functionCounts(bytes);
  return {
    file: path.basename(wasmPath),
    bytes: bytes.length,
    imports,
    exports: exports.map((entry) => entry.name),
    functions: counts,
  };
}

function sha256(buffer) {
  return require('node:crypto').createHash('sha256').update(buffer).digest('hex');
}

// Calls a canister update export directly against a mock `ic0` so the
// pre-allocation length guard can be exercised for arguments larger than the
// IC ingress message limit (2 MiB). Returns the status and whether the module
// copied the argument before rejecting it.
function directGuardCheck(wasmPath, exportName, argSize) {
  const bytes = fs.readFileSync(wasmPath);
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
  const proof = read('proof.bin');
  const instances = read('instances.bin');
  const approvedVk = read('vk.bin');
  assert.equal(approvedVk.length, 126, 'fixture VK length');

  const ipa = inspectWasm(ipaWasmPath);
  const poseidon2 = inspectWasm(poseidonWasmPath);

  const server = await PocketIcServer.start();
  let pic;
  try {
    pic = await PocketIc.create(server.getUrl());
    const ipaCanister = await pic.createCanister();
    const poseidonCanister = await pic.createCanister();
    await pic.addCycles(ipaCanister, 2_000_000_000_000n);
    await pic.addCycles(poseidonCanister, 2_000_000_000_000n);
    await pic.installCode({ canisterId: ipaCanister, wasm: fs.readFileSync(ipaWasmPath) });
    await pic.installCode({
      canisterId: poseidonCanister,
      wasm: fs.readFileSync(poseidonWasmPath),
    });

    // --- Halo2 IPA verify ------------------------------------------------
    const verifyArg = Buffer.concat([proof, instances]);
    const cyclesBeforeVerify = await pic.getCyclesBalance(ipaCanister);
    const verifyReply = Buffer.from(
      await pic.updateCall({ canisterId: ipaCanister, method: 'verify', arg: verifyArg }),
    );
    const cyclesAfterVerify = await pic.getCyclesBalance(ipaCanister);
    assert.equal(verifyReply.length, 16, 'IPA reply length');
    const verifyStatus = verifyReply.readInt32LE(0);
    const verifierInstructions = verifyReply.readBigUInt64LE(4);
    const verifierPages = verifyReply.readUInt32LE(12);
    assert.equal(verifyStatus, 0, 'fixture proof must verify');
    assert(
      verifierInstructions < MAX_IPA_INSTRUCTIONS,
      `verifier instruction budget (${verifierInstructions})`,
    );
    assert(
      verifierPages * 65536 < MAX_IPA_MEMORY_BYTES,
      `verifier memory budget (${verifierPages} pages)`,
    );

    const tamperedProof = Buffer.from(verifyArg);
    tamperedProof[proof.length - 1] ^= 1;
    const tamperedProofReply = Buffer.from(
      await pic.updateCall({
        canisterId: ipaCanister,
        method: 'verify',
        arg: tamperedProof,
      }),
    );
    const tamperedProofStatus = tamperedProofReply.readInt32LE(0);
    assert.notEqual(tamperedProofStatus, 0, 'tampered proof must be rejected');

    const tamperedInstances = Buffer.from(verifyArg);
    tamperedInstances[verifyArg.length - 1] ^= 1;
    const tamperedInstancesReply = Buffer.from(
      await pic.updateCall({
        canisterId: ipaCanister,
        method: 'verify',
        arg: tamperedInstances,
      }),
    );
    const tamperedInstancesStatus = tamperedInstancesReply.readInt32LE(0);
    assert.notEqual(
      tamperedInstancesStatus,
      0,
      'tampered instance must be rejected',
    );

    const oversized = Buffer.alloc(4 * 1024 * 1024 + 1024 * 1024 + 1);
    const oversizedStatus = directGuardCheck(
      ipaWasmPath,
      'canister_update verify',
      oversized.length,
    );
    assert.notEqual(oversizedStatus.status, 0, 'oversized argument must be rejected');
    assert.equal(
      oversizedStatus.copied,
      false,
      'oversized argument must be rejected before msg_arg_data_copy',
    );

    // The IC ingress message cap (2 MiB) is below the canister's 5 MiB guard,
    // so also exercise an in-envelope but impossible proof length through a
    // real update call.
    const badEnvelope = Buffer.alloc(1024 * 1024);
    badEnvelope.write('RCH2IPF1', 0, 'ascii');
    badEnvelope.writeUInt32BE(0xffffffff, 8);
    const badEnvelopeReply = Buffer.from(
      await pic.updateCall({
        canisterId: ipaCanister,
        method: 'verify',
        arg: badEnvelope,
      }),
    );
    const badEnvelopeStatus = badEnvelopeReply.readInt32LE(0);
    assert.notEqual(badEnvelopeStatus, 0, 'impossible proof length must be rejected');

    // --- Poseidon2 hash --------------------------------------------------
    const frBe = (value) => {
      const out = Buffer.alloc(32);
      out.writeBigUInt64BE(BigInt(value), 24);
      return out;
    };
    const poseidonArg = Buffer.concat([frBe(1), frBe(2), frBe(3)]);
    const cyclesBeforeHash = await pic.getCyclesBalance(poseidonCanister);
    const hashReply = Buffer.from(
      await pic.updateCall({
        canisterId: poseidonCanister,
        method: 'hash',
        arg: poseidonArg,
      }),
    );
    const cyclesAfterHash = await pic.getCyclesBalance(poseidonCanister);
    assert.equal(hashReply.length, 48, 'Poseidon2 reply length');
    const hashStatus = hashReply.readInt32LE(0);
    const hashInstructions = hashReply.readBigUInt64LE(4);
    const hashPages = hashReply.readUInt32LE(12);
    const digest = hashReply.subarray(16).toString('hex');
    assert.equal(hashStatus, 0, 'Poseidon2 hash must succeed');
    assert.equal(digest, EXPECTED_POSEIDON2_123, 'Poseidon2 [1,2,3] KAT');
    assert(hashInstructions < MAX_POSEIDON2_INSTRUCTIONS, 'hash instruction budget');
    assert(hashPages * 65536 < MAX_POSEIDON2_MEMORY_BYTES, 'hash memory budget');

    const badLengthReply = Buffer.from(
      await pic.updateCall({
        canisterId: poseidonCanister,
        method: 'hash',
        arg: Buffer.alloc(33),
      }),
    );
    const badLengthStatus = badLengthReply.readInt32LE(0);
    assert.notEqual(badLengthStatus, 0, 'non-multiple length must be rejected');

    const nonCanonicalReply = Buffer.from(
      await pic.updateCall({
        canisterId: poseidonCanister,
        method: 'hash',
        arg: Buffer.alloc(32, 0xff),
      }),
    );
    const nonCanonicalStatus = nonCanonicalReply.readInt32LE(0);
    assert.notEqual(nonCanonicalStatus, 0, 'non-canonical Fr must be rejected');

    const tooManyReply = Buffer.from(
      await pic.updateCall({
        canisterId: poseidonCanister,
        method: 'hash',
        arg: Buffer.alloc(13 * 32, 0),
      }),
    );
    const tooManyStatus = tooManyReply.readInt32LE(0);
    assert.notEqual(tooManyStatus, 0, '13 inputs must be rejected');

    const poseidonGuard = directGuardCheck(
      poseidonWasmPath,
      'canister_update hash',
      13 * 32,
    );
    assert.notEqual(poseidonGuard.status, 0, 'direct 13-input guard');
    assert.equal(poseidonGuard.copied, false, '13-input guard runs before copy');

    const report = {
      runtime: {
        pocketIc: picVersion,
        node: process.version,
      },
      fixture: {
        vkBytes: approvedVk.length,
        proofBytes: proof.length,
        instancesBytes: instances.length,
        vkSha256: sha256(approvedVk),
        proofSha256: sha256(proof),
      },
      wasm: { halo2Ipa: ipa, poseidon2 },
      halo2IpaVerify: {
        status: verifyStatus,
        verifierInstructions: verifierInstructions.toString(),
        memoryPages: verifierPages,
        memoryBytes: verifierPages * 65536,
        updateCyclesDebited: (cyclesBeforeVerify - cyclesAfterVerify).toString(),
        argBytes: verifyArg.length,
        tamperedProofStatus,
        tamperedInstancesStatus,
        oversizedDirectGuard: oversizedStatus,
        badEnvelopeStatus,
      },
      poseidon2Hash: {
        status: hashStatus,
        instructions: hashInstructions.toString(),
        memoryPages: hashPages,
        memoryBytes: hashPages * 65536,
        updateCyclesDebited: (cyclesBeforeHash - cyclesAfterHash).toString(),
        inputCount: 3,
        digest,
        expectedDigest: EXPECTED_POSEIDON2_123,
        badLengthStatus,
        nonCanonicalStatus,
        tooManyStatus,
        directGuard: poseidonGuard,
      },
      budgets: {
        halo2Ipa: {
          maxInstructions: MAX_IPA_INSTRUCTIONS.toString(),
          maxMemoryBytes: MAX_IPA_MEMORY_BYTES,
        },
        poseidon2: {
          maxInstructions: MAX_POSEIDON2_INSTRUCTIONS.toString(),
          maxMemoryBytes: MAX_POSEIDON2_MEMORY_BYTES,
        },
      },
      note: 'Local PocketIC update cost includes ingress and execution fees. It is not a mainnet cycle quote or an isolated per-verifier tariff. Instructions are the in-canister performance_counter delta, not a protocol fee.',
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
