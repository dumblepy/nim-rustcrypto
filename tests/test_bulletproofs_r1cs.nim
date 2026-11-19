when defined(rustcryptoBulletproofsR1csPoc):
  import std/[os, unittest]
  import rustcrypto

  proc bytes(path: string): seq[byte] =
    for value in readFile(path):
      result.add byte(value)

  proc elements[T](path: string): seq[T] =
    let encoded = bytes(path)
    doAssert encoded.len mod 32 == 0
    result = newSeq[T](encoded.len div 32)
    if encoded.len > 0:
      copyMem(addr result[0], unsafeAddr encoded[0], encoded.len)

  proc writeBytes(path: string; encoded: openArray[byte]) =
    var value = newString(encoded.len)
    for i, item in encoded:
      value[i] = char(item)
    writeFile(path, value)

  disableParamFiltering()
  let dir = paramStr(1)
  suite "Bulletproofs R1CS":
    test "native interoperability and statement binding":
      let circuit = BulletproofsR1cs.loadCircuit(bytes(dir / "circuit.bin"))
      let publicInputs = elements[BulletproofsR1csPublicInput](dir / "public.bin")
      let witness = elements[BulletproofsR1csWitness](dir / "witness.bin")
      let context = bytes(dir / "context.bin")
      let native = BulletproofsR1cs.loadProof(bytes(dir / "native.bin"))
      check BulletproofsR1cs.verify(circuit, publicInputs, context, native)
      check not BulletproofsR1cs.verify(circuit, publicInputs, @[1'u8], native)
      check BulletproofsR1cs.validatePublicInputs(publicInputs)
      check BulletproofsR1cs.validateCommitments(native.commitments)
      check native.commitments.len == 2
      check BulletproofsR1cs.verifyWithCommitments(circuit, publicInputs, context, native, native.commitments)
      let committed = native.commitments
      check not BulletproofsR1cs.verifyWithCommitments(
        circuit, publicInputs, context, native, [committed[1], committed[0]])
      let proof = BulletproofsR1csProver.prove(circuit, publicInputs, witness, context)
      check BulletproofsR1cs.verify(circuit, publicInputs, context, proof)
      var tampered = proof.toBytes
      tampered[5] = 0
      check not BulletproofsR1cs.validateProof(tampered)
      check BulletproofsR1cs.verify(circuit, publicInputs, context, proof)
      writeBytes(dir / "nim.bin", proof.toBytes)
      expect BulletproofsR1csError:
        discard BulletproofsR1cs.loadProof(@[1'u8])
      expect BulletproofsR1csError:
        discard BulletproofsR1csProver.prove(circuit, publicInputs, [], context)
      var noncanonical = newSeq[BulletproofsR1csPublicInput](publicInputs.len)
      for i in 0 ..< noncanonical.len:
        var encoded: array[32, byte]
        for value in encoded.mitems:
          value = 255
        noncanonical[i] = BulletproofsR1csPublicInput(encoded)
      check not BulletproofsR1cs.validatePublicInputs(noncanonical)
      expect BulletproofsR1csError:
        discard BulletproofsR1cs.verify(circuit, noncanonical, context, proof)
      if fileExists(dir / "web.bin"):
        let web = BulletproofsR1cs.loadProof(bytes(dir / "web.bin"))
        check BulletproofsR1cs.verify(circuit, publicInputs, context, web)

    test "proving with existing commitment openings":
      let circuit = BulletproofsR1cs.loadCircuit(bytes(dir / "circuit.bin"))
      let publicInputs = elements[BulletproofsR1csPublicInput](dir / "public.bin")
      let witness = elements[BulletproofsR1csWitness](dir / "witness.bin")
      let context = bytes(dir / "context.bin")
      var first, second: array[32, byte]
      first[0] = 2
      second[0] = 3
      let blindings = [BulletproofsR1csBlinding(first), BulletproofsR1csBlinding(second)]
      let original = BulletproofsR1csProver.prove(circuit, publicInputs, witness, context, blindings)
      let fresh = BulletproofsR1csProver.prove(circuit, publicInputs, witness, context, blindings)
      check BulletproofsR1cs.verifyWithCommitments(circuit, publicInputs, context, fresh, original.commitments)
      check fresh.toBytes != original.toBytes
