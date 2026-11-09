const { PocketIc, PocketIcServer } = require('@dfinity/pic');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const [artifactDir, wasmPath] = process.argv.slice(2);
(async () => {
  const server = await PocketIcServer.start();
  let pic;
  try {
    pic = await PocketIc.create(server.getUrl());
    const canisterId = await pic.createCanister();
    await pic.addCycles(canisterId, 2_000_000_000_000n);
    await pic.installCode({ canisterId, wasm: fs.readFileSync(wasmPath) });
    const arg = Buffer.concat(['browser-proof.bin', 'public-inputs.bin'].map(n => fs.readFileSync(path.join(artifactDir, n))));
    const before = await pic.getCyclesBalance(canisterId);
    const response = Buffer.from(await pic.updateCall({ canisterId, method: 'verify', arg }));
    const after = await pic.getCyclesBalance(canisterId);
    assert.equal(response.readInt32LE(0), 0);
    const instructions = response.readBigUInt64LE(4);
    const pages = response.readUInt32LE(12);
    assert(instructions < 2_000_000_000n, 'verifier instruction smoke budget');
    assert(pages * 65536 < 256 * 1024 * 1024, 'verifier memory smoke budget');
    const bad = Buffer.from(arg); bad[bad.length - 1] ^= 1;
    const rejected = Buffer.from(await pic.updateCall({ canisterId, method: 'verify', arg: bad }));
    assert.notEqual(rejected.readInt32LE(0), 0);
    const report = { runtime: '@dfinity/pic ' + require('@dfinity/pic/package.json').version,
      verifierInstructions: instructions.toString(), updateCyclesDebited: (before - after).toString(), wasmLinearMemoryHighWaterBytes: pages * 65536,
      note: 'Local PocketIC update cost includes ingress/execution fees; not a mainnet quote or an isolated per-verifier cycle tariff.' };
    fs.writeFileSync(path.join(artifactDir, 'ic-measurements.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report));
  } finally { if (pic) await pic.tearDown(); await server.stop(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
