import std/[os, monotimes, times, strutils]
import ../src/rustcrypto/algorithm/[bn254, groth16, groth16_prover]
let dir = paramStr(1)
proc bytes(path: string): seq[byte] =
  let data = readFile(path)
  for ch in data: result.add(byte(ch))
var circuit = Groth16Bn254Prover.circuit(1, 1)
let secret = circuit.privateInput(0)
let square = circuit.mul(secret, secret)
circuit.enforceEqual(square, circuit.publicInput(0))
let key = bytes(dir / "proving-key.bin")
let vk = bytes(dir / "verifying-key.bin")
let inputs = [fromHexFr("00".repeat(31) & "09")]
var witness = [fromHexFr("00".repeat(31) & "03")]
let start = getMonoTime()
let proof = Groth16Bn254Prover.prove(circuit, key, inputs, witness)
let milliseconds = (getMonoTime() - start).inMicroseconds.float / 1000.0
Groth16Bn254Prover.clearWitness(witness)
doAssert Groth16Bn254.verify(vk, proof, inputs)
doAssert milliseconds < 30000.0
echo "{\"nimProveMs\":", milliseconds, "}"
