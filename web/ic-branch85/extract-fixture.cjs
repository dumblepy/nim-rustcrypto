// Extracts committed Halo2 IPA/BN254 v1 fixture sections into raw files.
//
// Usage: node extract-fixture.cjs <cubic-fixture.hex> <artifact-dir> [poseidon2-fixture.hex]
//
// The cubic fixture is written as vk.bin / proof.bin / instances.bin /
// witness.bin. When the optional Poseidon2 fixture is supplied, its sections
// are written with a `poseidon2_` prefix (poseidon2_vk.bin, ...).
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const [fixturePath, artifactDir, poseidon2FixturePath] = process.argv.slice(2);
if (!fixturePath || !artifactDir) {
  console.error(
    'usage: node extract-fixture.cjs <cubic-fixture.hex> <artifact-dir> [poseidon2-fixture.hex]',
  );
  process.exit(2);
}

function parseFixture(file) {
  return Object.fromEntries(
    fs
      .readFileSync(file, 'utf8')
      .trim()
      .split(/\r?\n/)
      .map((line) => {
        const separator = line.indexOf('=');
        assert(separator > 0, `malformed fixture line in ${file}: ${line.slice(0, 32)}`);
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
}

const sections = {
  VK: 'vk.bin',
  PROOF: 'proof.bin',
  INSTANCES: 'instances.bin',
  WITNESS: 'witness.bin',
};

function extract(file, prefix) {
  const values = parseFixture(file);
  const sizes = {};
  for (const [name, fileSuffix] of Object.entries(sections)) {
    const hex = values[name];
    assert(hex !== undefined, `${file} is missing ${name}`);
    assert(hex.length % 2 === 0, `${file} ${name} has odd-length hex`);
    assert(/^[0-9a-fA-F]*$/.test(hex), `${file} ${name} is not hex`);
    const bytes = Buffer.from(hex, 'hex');
    fs.writeFileSync(path.join(artifactDir, `${prefix}${fileSuffix}`), bytes);
    sizes[name] = bytes.length;
  }
  return sizes;
}

fs.mkdirSync(artifactDir, { recursive: true });
const report = { cubic: extract(fixturePath, '') };
if (poseidon2FixturePath) {
  report.poseidon2 = extract(poseidon2FixturePath, 'poseidon2_');
}
console.log(JSON.stringify(report));
