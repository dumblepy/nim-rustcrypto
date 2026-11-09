import ./ffi
import ./common

type
  Bn254* = object
  Bn254Fr* = array[Bn254FrLen, byte]
  Bn254G1* = array[Bn254G1Len, byte]
  Bn254G2* = array[Bn254G2Len, byte]

proc isCanonicalFr*(T: type Bn254; input: Bn254Fr): bool =
  ## Returns `true` only for canonical big-endian BN254 `Fr` encodings (< modulus).
  ## Non-canonical values are never reduced implicitly.
  bn254FrValidateRaw(
    cast[ptr uint8](unsafeAddr input[0]), csize_t(input.len)
  ) == RustCryptoOk

proc isValidG1*(T: type Bn254; point: Bn254G1): bool =
  ## Validates a canonical 64-byte G1 point (on-curve and subgroup checked).
  ## The all-zero encoding is accepted as the point at infinity.
  bn254G1ValidateRaw(
    cast[ptr uint8](unsafeAddr point[0]), csize_t(point.len)
  ) == RustCryptoOk

proc isValidG2*(T: type Bn254; point: Bn254G2): bool =
  ## Validates a canonical 128-byte G2 point (on-curve and subgroup checked).
  ## The all-zero encoding is accepted as the point at infinity.
  bn254G2ValidateRaw(
    cast[ptr uint8](unsafeAddr point[0]), csize_t(point.len)
  ) == RustCryptoOk

proc fromHexFr*(hex: string): Bn254Fr =
  ## Parses exactly 32 bytes of hex into a `Bn254Fr`. Canonicality is not checked here;
  ## use `Bn254.isCanonicalFr` when the value comes from an untrusted source.
  fromHexDigest[Bn254Fr](hex, Bn254FrLen)

proc fromHexG1*(hex: string): Bn254G1 =
  fromHexDigest[Bn254G1](hex, Bn254G1Len)

proc fromHexG2*(hex: string): Bn254G2 =
  fromHexDigest[Bn254G2](hex, Bn254G2Len)

proc frToHex*(value: Bn254Fr): string =
  bytesToHexString(value)

proc g1ToHex*(value: Bn254G1): string =
  bytesToHexString(value)

proc g2ToHex*(value: Bn254G2): string =
  bytesToHexString(value)
