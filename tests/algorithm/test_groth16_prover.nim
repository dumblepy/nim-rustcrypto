import std/[unittest, strutils]
import ../../src/rustcrypto/algorithm/[bn254, groth16, groth16_prover, poseidon]
proc fr(n: int): Bn254Fr =
  fromHexFr("00".repeat(31) & toHex(n, 2))
suite "Groth16 prover":
  test "native roundtrip through existing verifier":
    var circuit = Groth16Bn254Prover.circuit(1, 1)
    let secret = circuit.privateInput(0)
    let squared = circuit.mul(secret, secret)
    circuit.enforceEqual(squared, circuit.publicInput(0))
    let keys = Groth16Bn254Prover.setup(circuit)
    let proof = Groth16Bn254Prover.prove(circuit, keys.provingKey, [fr(9)], [fr(3)])
    check Groth16Bn254.verify(keys.verifyingKey, proof, [fr(9)])
    check not Groth16Bn254.verify(keys.verifyingKey, proof, [fr(8)])
    expect ValueError:
      discard Groth16Bn254Prover.prove(circuit, keys.provingKey, [fr(9)], [fr(4)])
    expect ValueError:
      discard Groth16Bn254Prover.prove(circuit, @[], [fr(9)], [fr(3)])
  test "Poseidon witness commitment is constrained":
    var circuit = Groth16Bn254Prover.circuit(1, 2)
    let digest = circuit.poseidon([circuit.privateInput(0), circuit.privateInput(1)])
    circuit.enforceEqual(digest, circuit.publicInput(0))
    let keys = Groth16Bn254Prover.setup(circuit)
    let inputs = [PoseidonBn254.hash([fr(1), fr(2)])]
    let proof = Groth16Bn254Prover.prove(circuit, keys.provingKey, inputs, [fr(1), fr(2)])
    check Groth16Bn254.verify(keys.verifyingKey, proof, inputs)
    expect ValueError:
      discard Groth16Bn254Prover.prove(circuit, keys.provingKey, inputs, [fr(1), fr(3)])
  test "builder validates bounds":
    expect ValueError: discard Groth16Bn254Prover.circuit(0, 1)
    var circuit = Groth16Bn254Prover.circuit(1, 1)
    expect ValueError: circuit.enforceRange(circuit.privateInput(0), 129)
    expect ValueError: discard circuit.poseidon([])

  test "caller-owned witness can be cleared":
    var witness = [fr(3), fr(7)]
    Groth16Bn254Prover.clearWitness(witness)
    check witness == [default(Bn254Fr), default(Bn254Fr)]
