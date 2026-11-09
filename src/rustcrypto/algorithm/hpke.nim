## RFC 9180 Base mode, suite (0x0020, 0x0001, 0x0003).
## Wire: enc[32] || ciphertext || tag[16]. Fresh encapsulation per message.
import ./[ffi, common]

type
  Hpke* = object
  HpkePublicKey* = array[32, byte]
  HpkeSecretKey* = array[32, byte]
const
  HpkeOverhead* = 48
  HpkeMaxPlaintextLen* = 16 * 1024 * 1024
  HpkeMaxContextLen* = 1024 * 1024

proc checked(status: cint) =
  if status != RustCryptoOk:
    raise newException(ValueError, "HPKE operation failed (status " & $status & ")")

proc checkContext(aad, info: openArray[byte]) =
  if aad.len > HpkeMaxContextLen or info.len > HpkeMaxContextLen:
    raise newException(ValueError, "HPKE context exceeds size limit")

proc generateSecretKey*(_: type Hpke): HpkeSecretKey =
  checked(hpkeGenerateSecretKeyRaw(bytesPtr(result), csize_t(result.len)))

proc publicKey*(_: type Hpke, sk: HpkeSecretKey): HpkePublicKey =
  checked(hpkePublicKeyRaw(bytesPtr(sk), csize_t(sk.len),
    bytesPtr(result), csize_t(result.len)))

proc clearSecretKey*(_: type Hpke, sk: var HpkeSecretKey) =
  ## Wipes this buffer only. Avoid copying keys; wipe other copies separately.
  checked(hpkeClearSecretKeyRaw(bytesPtr(sk), csize_t(sk.len)))

proc seal*(_: type Hpke, recipientPk: HpkePublicKey,
    plaintext: openArray[byte], aad: openArray[byte] = [],
    info: openArray[byte] = []): seq[byte] =
  checkContext(aad, info)
  if plaintext.len > HpkeMaxPlaintextLen:
    raise newException(ValueError, "HPKE plaintext exceeds size limit")
  result = newSeq[byte](plaintext.len + HpkeOverhead)
  checked(hpkeSealRaw(bytesPtr(recipientPk), csize_t(recipientPk.len),
    bytesPtr(info), csize_t(info.len), bytesPtr(aad), csize_t(aad.len),
    bytesPtr(plaintext), csize_t(plaintext.len), bytesPtr(result), csize_t(result.len)))

proc open*(_: type Hpke, recipientSk: HpkeSecretKey,
    sealed: openArray[byte], aad: openArray[byte] = [],
    info: openArray[byte] = []): seq[byte] =
  checkContext(aad, info)
  if sealed.len < HpkeOverhead or sealed.len > HpkeMaxPlaintextLen + HpkeOverhead:
    raise newException(ValueError, "HPKE ciphertext has invalid length")
  result = newSeq[byte](sealed.len - HpkeOverhead)
  checked(hpkeOpenRaw(bytesPtr(recipientSk), csize_t(recipientSk.len),
    bytesPtr(info), csize_t(info.len), bytesPtr(aad), csize_t(aad.len),
    bytesPtr(sealed), csize_t(sealed.len), bytesPtr(result), csize_t(result.len)))
