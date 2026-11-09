const { chromium, devices } = require("playwright");
const { build } = require("esbuild");
const { readFileSync, writeFileSync, mkdtempSync, rmSync } = require("node:fs");
const { execFileSync } = require("node:child_process");
const { createServer } = require("node:http");
const { tmpdir } = require("node:os");
const path = require("node:path");
const assert = require("node:assert/strict");

(async () => {
  const root = path.resolve(__dirname, "../..");
  const native = path.resolve(process.argv[2] || path.join(root, "tests/hpke_interop"));
  const fixture = path.join(root, "tests/fixtures/hpke/base.json");
  const vector = JSON.parse(readFileSync(fixture));
  const nativeWire = execFileSync(native, [fixture], { encoding: "utf8" }).trim();
  const temp = mkdtempSync(path.join(tmpdir(), "hpke-interop-"));
  let browser, extension, server;
  try {
    await build({ entryPoints: [path.join(__dirname, "browser.js")], bundle: true,
      format: "iife", platform: "browser", outfile: path.join(temp, "bundle.js") });
    const bundle = readFileSync(path.join(temp, "bundle.js"));
    server = createServer((req, res) => {
      res.setHeader("Content-Type", req.url === "/bundle.js" ? "text/javascript" : "text/html");
      res.end(req.url === "/bundle.js" ? bundle : '<script src="/bundle.js"></script>');
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${server.address().port}`;
    const launch = { headless: true, channel: "chromium", args: ["--no-sandbox"] };
    browser = await chromium.launch(launch);
    for (const [name, options] of [["Chromium", {}], ["mobile viewport emulation", devices["Pixel 7"]]]) {
      const context = await browser.newContext(options);
      const page = await context.newPage();
      await page.goto(url);
      const wire = await page.evaluate(input => globalThis.checkHpkeInterop(input), { vector, nativeWire });
      execFileSync(native, [fixture, wire]);
      assert.notEqual(wire, nativeWire);
      console.log(`${name}: RFC vector, Nim/Rust <-> JS, randomness, rejection OK`);
      await context.close();
    }
    writeFileSync(path.join(temp, "manifest.json"), JSON.stringify({ manifest_version: 3,
      name: "HPKE interoperability test", version: "1.0", background: { service_worker: "bundle.js" } }));
    extension = await chromium.launchPersistentContext(path.join(temp, "profile"), {
      ...launch, args: [...launch.args, `--disable-extensions-except=${temp}`, `--load-extension=${temp}`],
    });
    const worker = extension.serviceWorkers()[0] || await extension.waitForEvent("serviceworker");
    const wire = await worker.evaluate(input => globalThis.checkHpkeInterop(input), { vector, nativeWire });
    execFileSync(native, [fixture, wire]);
    console.log("Manifest V3 extension worker: RFC vector, Nim/Rust <-> JS OK");
  } finally {
    await extension?.close(); await browser?.close();
    if (server) await new Promise(resolve => server.close(resolve));
    rmSync(temp, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
