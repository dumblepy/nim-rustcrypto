import ./ffi
import ./common
import ./bn254

type
  Poseidon2Bn254* = object
    ## Namespace for the Noir/Barretenberg-compatible Poseidon2/BN254
    ## permutation and sponge.

proc permute*(
    T: type Poseidon2Bn254; state: array[Poseidon2Bn254Width, Bn254Fr]
): array[Poseidon2Bn254Width, Bn254Fr] =
  ## Permutes a width-4 Poseidon2/BN254 state.
  ##
  ## Every state element must be a canonical big-endian BN254 `Fr` value.
  ## Non-canonical values raise `ValueError`; no implicit reduction is done.
  var input: array[Poseidon2Bn254Width * Bn254FrLen, byte]
  for i in 0 ..< Poseidon2Bn254Width:
    for j in 0 ..< Bn254FrLen:
      input[i * Bn254FrLen + j] = state[i][j]

  var output: array[Poseidon2Bn254Width * Bn254FrLen, byte]
  raiseRustCryptoStatus(
    poseidon2Bn254PermuteRaw(
      cast[ptr uint8](addr input[0]),
      csize_t(input.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_poseidon2_bn254_permute",
  )

  for i in 0 ..< Poseidon2Bn254Width:
    for j in 0 ..< Bn254FrLen:
      result[i][j] = output[i * Bn254FrLen + j]

proc hash*(T: type Poseidon2Bn254; inputs: openArray[Bn254Fr]): Bn254Fr =
  ## Hashes `inputs` with the Noir/Barretenberg Poseidon2 sponge.
  ##
  ## `inputs.len` must be between 0 and `Poseidon2Bn254MaxInputs` (12).
  ## Every input must be a canonical big-endian BN254 `Fr` value; non-canonical
  ## values raise `ValueError`. Empty input is valid and returns the permutation
  ## of the all-zero state.
  if inputs.len > Poseidon2Bn254MaxInputs:
    raise newException(
      ValueError,
      "Poseidon2Bn254.hash requires 0.." & $Poseidon2Bn254MaxInputs & " inputs",
    )

  var buffer = newSeq[byte](inputs.len * Bn254FrLen)
  for i in 0 ..< inputs.len:
    for j in 0 ..< Bn254FrLen:
      buffer[i * Bn254FrLen + j] = inputs[i][j]

  var output: Bn254Fr
  raiseRustCryptoStatus(
    poseidon2Bn254HashRaw(
      bytesPtr(buffer),
      csize_t(buffer.len),
      csize_t(inputs.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    ),
    "rustcrypto_poseidon2_bn254_hash",
  )
  output
