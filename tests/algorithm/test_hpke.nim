import std/[unittest, json, strutils, os]
import ../../src/rustcrypto

proc unhex(s: string): seq[byte] =
  for i in countup(0, s.high, 2): result.add byte(parseHexInt(s[i .. i+1]))
let vector = parseJson(readFile(currentSourcePath.parentDir.parentDir / "fixtures/hpke/base.json"))
proc secret(): HpkeSecretKey =
  let bytes = unhex(vector["skRm"].getStr)
  for i in 0..<32: result[i] = bytes[i]

suite "RFC 9180 HPKE Base":
  test "CFRG independent vector through Rust FFI":
    let sk = secret()
    check @(Hpke.publicKey(sk)) == unhex(vector["pkRm"].getStr)
    let record = vector["encryptions"][0]
    let wire = unhex(vector["enc"].getStr & record["ct"].getStr)
    check Hpke.open(sk, wire, unhex(record["aad"].getStr), unhex(vector["info"].getStr)) == unhex(record["pt"].getStr)
  test "roundtrip, randomness, empty plaintext":
    var sk = Hpke.generateSecretKey()
    let pk = Hpke.publicKey(sk)
    for msg in [newSeq[byte](), @[byte 1, 2, 3]]:
      let a = Hpke.seal(pk, msg, @[byte 4], @[byte 5])
      let b = Hpke.seal(pk, msg, @[byte 4], @[byte 5])
      check a != b
      check a.len == msg.len + HpkeOverhead
      check Hpke.open(sk, a, @[byte 4], @[byte 5]) == msg
    Hpke.clearSecretKey(sk)
    check sk == default(HpkeSecretKey)
  test "tamper, wrong recipient, AAD, info, malformed keys":
    let sk = secret()
    let pk = Hpke.publicKey(sk)
    let wire = Hpke.seal(pk, @[byte 1], @[byte 2], @[byte 3])
    for index in [0, 32, wire.high]:
      var changed = wire
      changed[index] = changed[index] xor 1
      expect ValueError: discard Hpke.open(sk, changed, @[byte 2], @[byte 3])
    expect ValueError: discard Hpke.open(Hpke.generateSecretKey(), wire, @[byte 2], @[byte 3])
    expect ValueError: discard Hpke.open(sk, wire, @[byte 4], @[byte 3])
    expect ValueError: discard Hpke.open(sk, wire, @[byte 2], @[byte 4])
    expect ValueError: discard Hpke.open(sk, newSeq[byte](47))
    expect ValueError: discard Hpke.seal(default(HpkePublicKey), @[])
    var noncanonical: HpkePublicKey
    for i in 0..<32: noncanonical[i] = 255
    expect ValueError: discard Hpke.seal(noncanonical, @[])
