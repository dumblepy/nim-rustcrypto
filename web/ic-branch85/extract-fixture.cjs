// Extracts the committed Halo2 IPA/BN254 v1 fixture sections into raw files.
//
// Usage: node extract-fixture.cjs <fixture.hex> <artifact-dir>
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const [fixturePath, artifactDir] = process.argv.slice(2);
if (!fixturePath || !artifactDir) {
  console.error('usage: node extract-fixture.cjs <fixture.hex> <artifact-dir>');
  process.exit(2);
}

const values = Object.fromEntries(
  fs
    .readFileSync(fixturePath, 'utf8')
    .trim()
    .split(/\r?\n/)
    .map((line) => {
      const separator = line.indexOf('=');
      assert(separator > 0, `malformed fixture line: ${line.slice(0, 32)}`);
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
);

const files = {
  VK: 'vk.bin',
  PROOF: 'proof.bin',
  INSTANCES: 'instances.bin',
  WITNESS: 'witness.bin',
};

fs.mkdirSync(artifactDir, { recursive: true });
for (const [name, file] of Object.entries(files)) {
  const hex = values[name];
  assert(hex !== undefined, `fixture is missing ${name}`);
  assert(hex.length % 2 === 0, `${name} has odd-length hex`);
  assert(/^[0-9a-fA-F]*$/.test(hex), `${name} is not hex`);
  fs.writeFileSync(path.join(artifactDir, file), Buffer.from(hex, 'hex'));
}

console.log(
  JSON.stringify(
    Object.fromEntries(
      Object.keys(files).map((name) => [
        name,
        Buffer.from(values[name], 'hex').length,
      ]),
    ),
  ),
);
