## Known, public RFC fixture keys only. Never use this helper for application keys.
import std/[os, json, strutils]
import ../src/rustcrypto/algorithm/hpke
proc unhex(s: string): seq[byte] =
  for i in countup(0, s.high, 2): result.add byte(parseHexInt(s[i .. i+1]))
proc hex(data: openArray[byte]): string =
  for b in data: result.add toHex(b, 2).toLowerAscii
let v = parseFile(paramStr(1))
var sk: HpkeSecretKey
let bytes = unhex(v["skRm"].getStr)
for i in 0..<32: sk[i] = bytes[i]
let info = unhex(v["info"].getStr)
let aad = unhex(v["encryptions"][0]["aad"].getStr)
let msg = unhex(v["encryptions"][0]["pt"].getStr)
if paramCount() == 1:
  echo hex(Hpke.seal(Hpke.publicKey(sk), msg, aad, info))
else:
  doAssert Hpke.open(sk, unhex(paramStr(2)), aad, info) == msg
Hpke.clearSecretKey(sk)
