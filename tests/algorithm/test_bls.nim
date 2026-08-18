import unittest
import std/sequtils
import rustcrypto/algorithm/bls

suite "bls12-381":
  test "privateKeyFromSeed deterministic":
    let material = "hello world (it's a secret!) very secret stuff"
    let sk = Bls.privateKeyFromSeed(cast[seq[byte]](material))
    let sk2 = Bls.privateKeyFromSeed(cast[seq[byte]](material))
    check sk == sk2
    check sk.len == 32

  test "sign verify single message":
    let msg = cast[seq[byte]]("this is the message")
    let seed = cast[seq[byte]]("this is the key and it is very secret")
    let sk = Bls.privateKeyFromSeed(seed)
    let pk = Bls.publicKey(sk)
    let sig = Bls.sign(msg, sk)
    check Bls.verify(msg, pk, sig)

  test "aggregate verify two distinct messages":
    let sk1 = Bls.privateKeyFromSeed(newSeqWith(40, 3'u8))
    let sk2 = Bls.privateKeyFromSeed(newSeqWith(40, 5'u8))
    let pk1 = Bls.publicKey(sk1)
    let pk2 = Bls.publicKey(sk2)
    let m1 = cast[seq[byte]]("left")
    let m2 = cast[seq[byte]]("right")
    let s1 = Bls.sign(m1, sk1)
    let s2 = Bls.sign(m2, sk2)
    let agg = Bls.aggregate([s1, s2])
    let h1 = Bls.hash(m1)
    let h2 = Bls.hash(m2)
    check Bls.verify(agg, [h1, h2], [pk1, pk2])

  test "verify rejects duplicate messages in batch":
    let sk1 = Bls.privateKeyFromSeed(newSeqWith(40, 7'u8))
    let sk2 = Bls.privateKeyFromSeed(newSeqWith(40, 8'u8))
    let pk1 = Bls.publicKey(sk1)
    let pk2 = Bls.publicKey(sk2)
    let msg = cast[seq[byte]]("same")
    let s1 = Bls.sign(msg, sk1)
    let s2 = Bls.sign(msg, sk2)
    let agg = Bls.aggregate([s1, s2])
    check not Bls.verifyMessages(agg, @[msg, msg], @[pk1, pk2])

  test "aggregate empty raises":
    expect ValueError:
      discard Bls.aggregate([])

  test "privateKeyFromSeed short raises":
    expect ValueError:
      discard Bls.privateKeyFromSeed([1'u8, 2'u8])

  test "pairingEq generator relation":
    let g1 = Bls.g1Generator(BlsG1Compressed)
    let g2 = Bls.g2Generator(BlsG2Compressed)
    let two = Bls.privateKeyFromDecimalString("2")
    let g1d = Bls.g1Mul(g1, two)
    let inv2 = Bls.scalarInvert(two)
    let g2d = Bls.g2Mul(g2, inv2)
    check Bls.pairingEq(g1, g2, g1d, g2d)

  test "aug g1 hash and verify via FFI":
    const skHex = "4242424242424242424242424242424242424242424242424242424242424242"
    let sk = fromHexScalar(skHex)
    let pkG2 = Bls.g2Mul(Bls.g2Generator(BlsG2Compressed), sk)
    let message = cast[seq[byte]]("aug g1 test message")
    let msgHash = Bls.hashAugG1(pkG2, message)
    let sig = Bls.g1Mul(msgHash, sk)
    check Bls.verifyAugG1(sig, msgHash, pkG2)
    check Bls.verifyAugG1Message(sig, message, pkG2)

  test "aug g1 verify rejects wrong message":
    const skHex = "4242424242424242424242424242424242424242424242424242424242424242"
    let sk = fromHexScalar(skHex)
    let pkG2 = Bls.g2Mul(Bls.g2Generator(BlsG2Compressed), sk)
    let message = cast[seq[byte]]("aug g1 test message")
    let msgHash = Bls.hashAugG1(pkG2, message)
    let sig = Bls.g1Mul(msgHash, sk)
    let other = cast[seq[byte]]("different message")
    check not Bls.verifyAugG1Message(sig, other, pkG2)

  test "minimal pk size API unchanged":
    let msg = cast[seq[byte]]("this is the message")
    let seed = cast[seq[byte]]("this is the key and it is very secret")
    let sk = Bls.privateKeyFromSeed(seed)
    let pk = Bls.publicKey(sk)
    let sig = Bls.sign(msg, sk)
    check Bls.verify(msg, pk, sig)
