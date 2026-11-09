// Independent HPKE implementation: this bundle runs in browser and extension workers.
import { CipherSuite, KemId, KdfId, AeadId } from "hpke-js";
const hex = (bytes) => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
const bytes = (s) => Uint8Array.from(s.match(/../g) ?? [], h => parseInt(h, 16));

globalThis.checkHpkeInterop = async ({ vector: v, nativeWire }) => {
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305,
  });
  const recipientKey = await suite.kem.deserializePrivateKey(bytes(v.skRm).buffer);
  const recipientPublicKey = await suite.kem.deserializePublicKey(bytes(v.pkRm).buffer);
  const info = bytes(v.info);
  const { aad: aadHex, pt, ct } = v.encryptions[0];
  const aad = bytes(aadHex);
  async function open(wire, extra = {}) {
    const data = bytes(wire);
    return suite.open({ recipientKey, enc: data.slice(0, 32).buffer, info, ...extra }, data.slice(32).buffer, aad);
  }
  if (hex(await open(v.enc + ct)) !== pt) throw new Error("RFC vector mismatch");
  if (hex(await open(nativeWire)) !== pt) throw new Error("Nim to browser mismatch");
  const sealed = await suite.seal({ recipientPublicKey, info }, bytes(pt), aad);
  const wire = hex(sealed.enc) + hex(sealed.ct);
  if (hex(await open(wire)) !== pt) throw new Error("Browser roundtrip mismatch");
  // Both an altered context and an altered authentication tag must fail.
  for (const bad of [
    () => open(wire, { info: new Uint8Array([0]) }),
    () => open(wire.slice(0, -2) + (wire.endsWith("00") ? "01" : "00")),
  ]) {
    let rejected = false;
    try { await bad(); } catch { rejected = true; }
    if (!rejected) throw new Error("Browser accepted tampered data");
  }
  // Exercise the runtime CSPRNG/key generation, independent of public fixture keys.
  const pair = await suite.kem.generateKeyPair();
  const own = await suite.seal({ recipientPublicKey: pair.publicKey, info }, bytes(pt), aad);
  if (hex(await suite.open({ recipientKey: pair.privateKey, enc: own.enc, info }, own.ct, aad)) !== pt)
    throw new Error("Runtime key generation failed");
  return wire;
};
