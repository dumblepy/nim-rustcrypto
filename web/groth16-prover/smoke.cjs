// Run after ci/test_groth16_web.sh builds WASM and creates ephemeral setup artifacts.
const { chromium } = require('playwright');
const { createServer } = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { WASI } = require('node:wasi');
const { execFileSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const assert = require('node:assert/strict');
const [artifactDir, wasiPath, reportPath] = process.argv.slice(2);
const read = name => fs.readFileSync(path.join(artifactDir, name));
const pkg = path.join(__dirname, 'pkg');
async function wasiVerify(vk, proof, inputs) {
  const file = path.join(artifactDir, 'verify-input.txt');
  fs.writeFileSync(file, [vk, proof, inputs].map(b => Buffer.from(b).toString('hex')).join('\n') + '\n');
  const fd = fs.openSync(file, 'r');
  try {
    const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {}, stdin: fd, returnOnExit: true });
    const mod = await WebAssembly.compile(fs.readFileSync(wasiPath));
    const instance = await WebAssembly.instantiate(mod, { wasi_snapshot_preview1: wasi.wasiImport });
    const start = performance.now();
    assert.equal(wasi.start(instance), 0);
    return { ms: performance.now() - start, wasmLinearMemoryHighWaterBytes: instance.exports.memory.buffer.byteLength };
  } finally { fs.closeSync(fd); }
}
(async () => {
  const server = createServer((req, res) => {
    try {
      let file;
      if (req.url === '/') file = path.join(__dirname, 'index.html');
      else if (/^\/pkg\/[\w.]+$/.test(req.url)) file = path.join(pkg, path.basename(req.url));
      else if (/^\/artifacts\/[\w.-]+$/.test(req.url)) file = path.join(artifactDir, path.basename(req.url));
      else { res.writeHead(404); return res.end(); }
      res.setHeader('Content-Type', file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.js') ? 'text/javascript' : file.endsWith('.html') ? 'text/html' : 'application/octet-stream');
      res.end(fs.readFileSync(file));
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser, browserServer, sampler;
  let browserSampledPeakRssKiB = 0;
  const rssTree = pid => {
    try {
      const rss = Number(fs.readFileSync(`/proc/${pid}/status`, 'utf8').match(/^VmRSS:\s+(\d+)/m)?.[1] || 0);
      const children = fs.readFileSync(`/proc/${pid}/task/${pid}/children`, 'utf8').trim().split(/\s+/).filter(Boolean);
      return rss + children.reduce((sum, child) => sum + rssTree(child), 0);
    } catch { return 0; }
  };
  try {
    browserServer = await chromium.launchServer({ headless: true, args: ['--no-sandbox'] });
    sampler = setInterval(() => { browserSampledPeakRssKiB = Math.max(browserSampledPeakRssKiB, rssTree(browserServer.process().pid)); }, 10);
    browser = await chromium.connect(browserServer.wsEndpoint());
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.waitForFunction(() => typeof window.runProof === 'function');
    const browserResult = await page.evaluate(() => window.runProof());
    assert.equal(browserResult.proof.length, 256);
    assert.equal(browserResult.rejectsBadWitness, true);
    assert.equal(browserResult.rejectsEntropyFailure, true);
    fs.writeFileSync(path.join(artifactDir, 'browser-proof.bin'), Buffer.from(browserResult.proof));
    fs.writeFileSync(path.join(artifactDir, 'public-inputs.bin'), Buffer.from(browserResult.inputs));
    const wasi = await wasiVerify(browserResult.vk, browserResult.proof, browserResult.inputs);
    const wrong = [...browserResult.inputs]; wrong[31] ^= 1;
    await assert.rejects(() => wasiVerify(browserResult.vk, browserResult.proof, wrong));
    const node = JSON.parse(execFileSync(process.execPath, [path.join(__dirname, 'node-prove.cjs'), artifactDir], { encoding: 'utf8' }));
    await wasiVerify(read('verifying-key.bin'), read('node-proof.bin'), browserResult.inputs);
    const report = { browserVersion: browser.version(), nodeVersion: process.version,
      browser: { ms: browserResult.ms, wasmLinearMemoryHighWaterBytes: browserResult.wasmLinearMemoryHighWaterBytes, sampledProcessTreePeakRssKiB: browserSampledPeakRssKiB }, wasi, node,
      note: 'Browser RSS samples sum process-tree RSS every 10 ms including shared pages and initialization; this is a sampled estimate. Node peak RSS is from a separate process. Linear memory is committed WASM memory high water. WASI timing is not ICP instruction/cycle measurement.' };
    for (const item of [report.browser, report.node, report.wasi]) {
      assert(item.ms < 30000, 'smoke budget: 30 seconds');
      assert(item.wasmLinearMemoryHighWaterBytes < 256 * 1024 * 1024, 'smoke budget: 256 MiB linear memory');
    }
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report));
  } finally { clearInterval(sampler); if (browser) await browser.close(); if (browserServer) await browserServer.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode = 1; });
