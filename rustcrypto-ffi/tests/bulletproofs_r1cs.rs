#![cfg(feature = "bulletproofs-r1cs-poc")]
#[path = "../examples/support/bulletproofs_fixture.rs"]
mod fixture;

use curve25519_dalek::scalar::Scalar;
use rust_crypto_ffi::bulletproofs_r1cs::*;

#[test]
fn gadgets_and_opening() {
    for example in [
        fixture::multiplication(),
        fixture::ranged(32),
        fixture::ranged(64),
        fixture::ranged(128),
        fixture::bounded_sum(32),
        fixture::bounded_sum(64),
    ] {
        let circuit = CircuitDefinition::from_bytes(&example.circuit).unwrap();
        let proof = circuit
            .prove(
                PublicInputs(&example.public),
                Witness(&example.witness),
                b"app",
            )
            .unwrap();
        assert_eq!(proof.len(), circuit.proof_len());
        assert!(
            circuit
                .verify(PublicInputs(&example.public), b"app", Proof(&proof))
                .unwrap()
        );
        let mut witness = example.witness.clone();
        witness[0] ^= 1;
        assert_eq!(
            circuit.prove(PublicInputs(&example.public), Witness(&witness), b"app"),
            Err(Error::Unsatisfied)
        );
    }
    let example = fixture::multiplication();
    let circuit = CircuitDefinition::from_bytes(&example.circuit).unwrap();
    let blindings = [Scalar::from(2u64).to_bytes(), Scalar::from(3u64).to_bytes()].concat();
    let proof = circuit
        .prove_with_blindings(
            PublicInputs(&example.public),
            Witness(&example.witness),
            Blindings(&blindings),
            b"app",
        )
        .unwrap();
    let expected: Vec<u8> = [(6u64, 2u64), (7, 3)]
        .iter()
        .flat_map(|&(v, r)| {
            bulletproofs::PedersenGens::default()
                .commit(Scalar::from(v), Scalar::from(r))
                .compress()
                .to_bytes()
        })
        .collect();
    assert_eq!(proof_commitments(Proof(&proof)).unwrap().0, expected);
    let verify = |commitments: &[u8]| {
        circuit.verify_with_commitments(
            PublicInputs(&example.public),
            b"app",
            Proof(&proof),
            Commitments(commitments),
        )
    };
    assert_eq!(verify(&expected), Ok(true));
    assert_eq!(verify(&expected[..32]), Err(Error::Count));
    assert_eq!(verify(&[0xff; 64]), Err(Error::Encoding));
    let reordered = [&expected[32..], &expected[..32]].concat();
    assert_eq!(verify(&reordered), Ok(false));
}

#[test]
fn fails_closed() {
    let example = fixture::multiplication();
    let circuit = CircuitDefinition::from_bytes(&example.circuit).unwrap();
    let proof = circuit
        .prove(
            PublicInputs(&example.public),
            Witness(&example.witness),
            b"app",
        )
        .unwrap();
    let verify = |public: &[u8], context: &[u8], proof: &[u8]| {
        circuit.verify(PublicInputs(public), context, Proof(proof))
    };
    assert_eq!(verify(&example.public, b"other", &proof), Ok(false));
    let mut public = example.public.clone();
    public[0] ^= 1;
    assert_eq!(verify(&public, b"app", &proof), Ok(false));
    let public = [&example.public[32..], &example.public[..32]].concat();
    assert_eq!(verify(&public, b"app", &proof), Ok(false));
    assert_eq!(verify(&[0xff; 64], b"app", &proof), Err(Error::Encoding));
    assert_eq!(
        verify(&example.public[..32], b"app", &proof),
        Err(Error::Count)
    );
    assert_eq!(
        verify(&example.public, &[0; MAX_CONTEXT_BYTES + 1], &proof),
        Err(Error::Limit)
    );
    let mut changed = proof.clone();
    changed[6] ^= 1;
    assert_eq!(verify(&example.public, b"app", &changed), Ok(false));
    changed[6] ^= 1;
    changed[5] ^= 1;
    assert_eq!(
        verify(&example.public, b"app", &changed),
        Err(Error::Encoding)
    );
    changed[5] ^= 1;
    changed[42 + 257] ^= 1;
    assert_eq!(verify(&example.public, b"app", &changed), Ok(false));
    let mut changed = proof.clone();
    let end = changed.len();
    let (prefix, suffix) = changed[end - 64..].split_at_mut(32);
    prefix.swap_with_slice(suffix);
    assert_eq!(verify(&example.public, b"app", &changed), Ok(false));
    changed[end - 32..].fill(0xff);
    assert_eq!(validate_proof(Proof(&changed)), Err(Error::Encoding));
    changed[end - 32..].fill(0);
    assert_eq!(validate_proof(Proof(&changed)), Err(Error::Encoding));
    let mut changed = proof.clone();
    changed[38] -= 1;
    assert_eq!(validate_proof(Proof(&changed)), Err(Error::Encoding));
    for len in 0..proof.len() {
        assert!(validate_proof(Proof(&proof[..len])).is_err());
    }
    let mut trailing = proof.clone();
    trailing.push(0);
    assert_eq!(validate_proof(Proof(&trailing)), Err(Error::Encoding));
    assert_eq!(
        validate_proof(Proof(&[0; MAX_PROOF_BYTES + 1])),
        Err(Error::Limit)
    );
    let mut too_large = example.circuit;
    too_large[10..12].copy_from_slice(&513u16.to_le_bytes());
    assert!(matches!(
        CircuitDefinition::from_bytes(&too_large),
        Err(Error::Limit)
    ));
}

#[test]
fn fixed_wire_proof() {
    // Captured from a native proof with OS-generated randomness.
    let hex = concat!(
        "425050460101e08a96c021f64efe309967226e705f98e2452cd63465022bfefc",
        "1d9b481f2b850200e1010066c02ddab9955e6a42bb514fa7f3c262ec0d7f0e4c",
        "dee8430b3b5c4ce2d4472f04d26737f32647ad49de5e3c14b6377da594db0ea9",
        "89ab8228d904b182cc4f74389f896e42639fed7fda0a65ff2a985cdf6f398bea",
        "c1057548f142bb2e4dd0467a286ddf02e7145541c91e503b12303f417e51ce4d",
        "a41bfd801b97ef09b9da0ad47fc19310ceb8fcdb01582e035da66d60f378eed9",
        "82d1a364d85cfdaaca2f64069cf2b1dc675001dea18cfe03e7dce6cb020d1683",
        "c40d1510804132821d8028da28f47c25bec2cf936f3f2f36db0171fd0b83be0f",
        "178ee37582be651942aa275e3b93004e1372bef99c65d270b5d1618afa687490",
        "b14ff89971b75ff0c7cd4630cd463a4a2103d4cc9bf852a4cac034f5d9991a34",
        "6d8857191dc9dc28e2c70e8a78e3b34e23cf414799e29c3a998b2aa91e422301",
        "bb493be778ea8cebdaff09c3b9ca94f90dfe096c0e83cb7d9518e5c180472ba1",
        "e3ec08411286707c8aa008f87853103aa6faf12b32d119190ba060fd48ccd7b1",
        "13d7c9652d3626fa7b576890fd08c892d71bad5700a4bf73e628c1749efa9178",
        "36473ac01025a9b5e2466b22c0843bf8b2e4b9be4a399068a3adfce8f894700f",
        "4a748bf5d35f7b652e810032ffce6b2b32f0e0e709aa4e86187a1543395659db",
        "4c9281648ec3ec55d09b0eaa64bf7c8dbf53c69ece54aebfb7062b42178bcda5",
        "6ddbfdd334852881ac8b4648bacf950eb72c1557a8b97517a571a794e6b14cf1",
        "619225d6d87b9f0009357a",
    );
    let proof: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let example = fixture::multiplication();
    let circuit = CircuitDefinition::from_bytes(&example.circuit).unwrap();
    assert_eq!(validate_proof(Proof(&proof)), Ok(()));
    assert_eq!(
        circuit.verify(
            PublicInputs(&example.public),
            b"nim-rustcrypto/interop/v1",
            Proof(&proof)
        ),
        Ok(true)
    );
}
