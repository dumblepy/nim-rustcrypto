// Extracts the committed external ChainCircuit fixture into raw files.
//
// Usage: node extract-fixture.cjs <fixture.hex> <artifact-dir>
//
// Writes vk.bin / proof.bin / instances.bin / witness.bin. The VK is the
// V2-magic (`RCH2IPV2`) key pinned by the verify-only canister at build time.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const [fixturePath, artifactDir] = process.argv.slice(2);
if (!fixturePath || !artifactDir) {
  console.error('usage: node extract-fixture.cjs <fixture.hex> <artifact-dir>');
  process.exit(2);
}

function parseFixture(file) {
  const text = fs.readFileSync(file, 'utf8').trim();
  if (!text) throw new Error(`empty fixture: ${file}`);
  return Object.fromEntries(
    text.split(/\r?\n/).map((line) => {
      const separator = line.indexOf('=');
      assert(separator > 0, `malformed fixture line: ${line.slice(0, 32)}`);
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
  );
}

const values = parseFixture(fixturePath);
const sections = {
  VK: 'vk.bin',
  PROOF: 'proof.bin',
  INSTANCES: 'instances.bin',
  WITNESS: 'witness.bin',
};

fs.mkdirSync(artifactDir, { recursive: true });
const sizes = {};
for (const [name, fileName] of Object.entries(sections)) {
  const hex = values[name];
  assert(hex !== undefined, `${fixturePath} is missing ${name}`);
  assert(hex.length % 2 === 0, `${fixturePath} ${name} has odd-length hex`);
  assert(/^[0-9a-fA-F]*$/.test(hex), `${fixturePath} ${name} is not hex`);
  const bytes = Buffer.from(hex, 'hex');
  fs.writeFileSync(path.join(artifactDir, fileName), bytes);
  sizes[name] = bytes.length;
}

assert.equal(values.VK.slice(0, 16), '5243483249505632', 'VK must use RCH2IPV2 magic');
console.log(JSON.stringify(sizes));
