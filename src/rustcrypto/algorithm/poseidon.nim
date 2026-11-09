import ./ffi
import ./common
import ./bn254

type
  PoseidonBn254* = object

proc hash*(T: type PoseidonBn254; inputs: openArray[Bn254Fr]): Bn254Fr =
  ## Computes the Circom-compatible Poseidon/x^5 hash over BN254 `Fr`.
  ##
  ## `inputs.len` must be between 1 and `PoseidonBn254MaxInputs` (12).
  ## Every input must be a canonical big-endian `Fr`; non-canonical values raise `ValueError`.
  if inputs.len < 1 or inputs.len > PoseidonBn254MaxInputs:
    raise newException(
      ValueError,
      "PoseidonBn254.hash requires 1.." & $PoseidonBn254MaxInputs & " inputs",
    )

  var buffer = newSeq[byte](inputs.len * Bn254FrLen)
  for i in 0 ..< inputs.len:
    for j in 0 ..< Bn254FrLen:
      buffer[i * Bn254FrLen + j] = inputs[i][j]

  var output: Bn254Fr
  raiseRustCryptoStatus(
    poseidonBn254HashRaw(
      bytesPtr(buffer),
      csize_t(buffer.len),
      csize_t(inputs.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_poseidon_bn254_hash",
  )
  output
