use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{R1CSVar, alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use light_poseidon::{Poseidon, PoseidonHasher};
use rand::{SeedableRng, rngs::StdRng};
use rust_crypto_ffi::groth16_prover_ffi::*;
use rust_crypto_ffi::{fixture, groth16_prover::*};
fn field(n: u64) -> [u8; 32] {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    b
}
fn square() -> Circuit {
    let mut c = Circuit::new(1, 1).unwrap();
    let a = c.private(0).unwrap();
    let b = c.mul(a, a).unwrap();
    c.equal(b, c.public(0).unwrap()).unwrap();
    c
}
#[test]
fn all_poseidon_arities_match_native() {
    for arity in 1..=12 {
        for offset in [0u64, 1, 42] {
            let values: Vec<_> = (0..arity).map(|i| Fr::from(offset + i as u64)).collect();
            let cs = ConstraintSystem::new_ref();
            let vars: Vec<_> = values
                .iter()
                .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).unwrap())
                .collect();
            let output = poseidon_gadget(&vars).unwrap();
            assert_eq!(
                output.value().unwrap(),
                Poseidon::<Fr>::new_circom(arity)
                    .unwrap()
                    .hash(&values)
                    .unwrap()
            );
            assert!(cs.is_satisfied().unwrap());
        }
    }
    let cs = ConstraintSystem::new_ref();
    let values = [[1u8; 32], [2u8; 32]];
    let vars: Vec<_> = values
        .iter()
        .map(|v| FpVar::new_witness(cs.clone(), || Ok(Fr::from_be_bytes_mod_order(v))).unwrap())
        .collect();
    let digest = poseidon_gadget(&vars).unwrap().value().unwrap();
    assert_eq!(
        fixture::encode_public_inputs(&[digest]),
        vec![
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ]
    );
}
#[test]
fn setup_prove_and_reject_bad_witness_keys_and_encodings() {
    let c = square();
    assert_eq!(
        Circuit::from_bytes(&c.to_bytes()).unwrap().to_bytes(),
        c.to_bytes()
    );
    let mut rng = StdRng::seed_from_u64(70); // test-only
    let (pk, vk) = setup(&c, &mut rng).unwrap();
    let proof = prove(&c, &pk, &field(9), &field(3), &mut rng).unwrap();
    assert_eq!(proof.len(), 256);
    assert_eq!(&vk[..8], b"RCG16V1\0");
    // Exercise the unchanged C ABI verifier (also used by Nim and WASI).
    unsafe extern "C" {
        fn rustcrypto_groth16_bn254_verify(
            vk: *const u8,
            vl: usize,
            p: *const u8,
            pl: usize,
            i: *const u8,
            il: usize,
            n: usize,
        ) -> i32;
    }
    assert_eq!(
        unsafe {
            rustcrypto_groth16_bn254_verify(
                vk.as_ptr(),
                vk.len(),
                proof.as_ptr(),
                256,
                field(9).as_ptr(),
                32,
                1,
            )
        },
        0
    );
    assert_ne!(
        unsafe {
            rustcrypto_groth16_bn254_verify(
                vk.as_ptr(),
                vk.len(),
                proof.as_ptr(),
                256,
                field(10).as_ptr(),
                32,
                1,
            )
        },
        0
    );
    assert!(prove(&c, &pk, &field(9), &field(4), &mut rng).is_err());
    assert!(prove(&c, &pk, &[255; 32], &field(3), &mut rng).is_err());
    assert!(prove(&c, &pk, &field(9), &[], &mut rng).is_err());
    let mut other = Circuit::new(1, 1).unwrap();
    other
        .equal(other.public(0).unwrap(), other.private(0).unwrap())
        .unwrap();
    assert!(prove(&other, &pk, &field(3), &field(3), &mut rng).is_err());
    let (_, wrong_vk) = setup(&c, &mut rng).unwrap();
    assert_ne!(verify_v1(&wrong_vk, &proof, &field(9)), 0);
    let mut bomb = pk.clone();
    let offset = 368 + c.to_bytes().len();
    bomb[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(prove(&c, &bomb, &field(9), &field(3), &mut rng).is_err());
    let mut trailing = pk.clone();
    trailing.push(0);
    assert!(prove(&c, &trailing, &field(9), &field(3), &mut rng).is_err());
    for n in [0, 8, 12, pk.len() - 1] {
        assert!(prove(&c, &pk[..n], &field(9), &field(3), &mut rng).is_err());
    }
    let mut bad = c.to_bytes();
    bad.push(0);
    assert!(Circuit::from_bytes(&bad).is_err());
    assert!(Circuit::from_bytes(&[255; 32]).is_err());
}
#[test]
fn gadgets_reject_false_membership_authorization_and_overflow() {
    let mut c = Circuit::new(3, 5).unwrap();
    let public: Vec<_> = (0..3).map(|i| c.public(i).unwrap()).collect();
    let secret = c.private(0).unwrap();
    let value = c.private(1).unwrap();
    let sibling = c.private(2).unwrap();
    let dir = c.private(3).unwrap();
    let context = c.private(4).unwrap();
    let root = c.merkle_root(value, &[sibling], &[dir]).unwrap();
    c.equal(root, public[0]).unwrap();
    let prf = c.prf(field(7), secret, context).unwrap();
    c.equal(prf, public[1]).unwrap();
    let sum = c.bounded_sum(&[value, sibling], 64).unwrap();
    c.equal(sum, public[2]).unwrap();
    let hash = |values: &[u64]| {
        Poseidon::<Fr>::new_circom(values.len())
            .unwrap()
            .hash(&values.iter().map(|x| Fr::from(*x)).collect::<Vec<_>>())
            .unwrap()
    };
    let pub_bytes =
        fixture::encode_public_inputs(&[hash(&[3, 4]), hash(&[7, 11, 12]), Fr::from(7u64)]);
    let private =
        |s, v, sib, d, ctx| [field(s), field(v), field(sib), field(d), field(ctx)].concat();
    let mut rng = StdRng::seed_from_u64(71);
    let (pk, vk) = setup(&c, &mut rng).unwrap();
    let proof = prove(&c, &pk, &pub_bytes, &private(11, 3, 4, 0, 12), &mut rng).unwrap();
    assert_eq!(verify_v1(&vk, &proof, &pub_bytes), 0);
    let mut reordered = pub_bytes.clone();
    reordered[..32].copy_from_slice(&pub_bytes[32..64]);
    reordered[32..64].copy_from_slice(&pub_bytes[..32]);
    assert_ne!(verify_v1(&vk, &proof, &reordered), 0);
    for bad in [
        private(10, 3, 4, 0, 12),
        private(11, 3, 4, 1, 12),
        private(11, 3, 4, 2, 12),
        private(11, 4, 4, 0, 12),
        private(11, 3, 4, 0, 13),
    ] {
        assert!(prove(&c, &pk, &pub_bytes, &bad, &mut rng).is_err());
    }
    for bits in [64, 128] {
        let mut range = Circuit::new(1, 1).unwrap();
        let w = range.private(0).unwrap();
        let sum = range.bounded_sum(&[w, w], bits).unwrap();
        range.equal(sum, range.public(0).unwrap()).unwrap();
        let (key, _) = setup(&range, &mut rng).unwrap();
        let mut high = [0u8; 32];
        high[32 - bits as usize / 8] = 0x80;
        let mut overflow_sum = [0u8; 32];
        overflow_sum[31 - bits as usize / 8] = 1;
        assert!(prove(&range, &key, &overflow_sum, &high, &mut rng).is_err());
    }
}
#[test]
fn ffi_rejects_null_entropy_and_output() {
    let c = square().to_bytes();
    let mut pk_len = 0;
    let mut vk_len = 0;
    assert_eq!(
        rustcrypto_groth16_bn254_setup(
            c.as_ptr(),
            c.len(),
            None,
            core::ptr::null_mut(),
            0,
            &mut pk_len,
            core::ptr::null_mut(),
            0,
            &mut vk_len
        ),
        19
    );
    assert_eq!(
        rustcrypto_groth16_bn254_setup(
            c.as_ptr(),
            c.len(),
            None,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            &mut vk_len
        ),
        1
    );
    assert_ne!(
        rustcrypto_groth16_bn254_prove(
            core::ptr::null(),
            MAX_CIRCUIT_BYTES + 1,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            None,
            core::ptr::null_mut(),
            0
        ),
        0
    );
}

#[test]
fn callback_failure_does_not_touch_outputs_and_parser_is_bounded() {
    unsafe extern "C" fn fail(_: *mut u8, _: usize) -> i32 {
        1
    }
    let c = square().to_bytes();
    let mut output = [0xabu8; 256];
    assert_eq!(
        rustcrypto_groth16_bn254_prove(
            c.as_ptr(),
            c.len(),
            core::ptr::null(),
            0,
            field(9).as_ptr(),
            32,
            field(3).as_ptr(),
            32,
            Some(fail),
            output.as_mut_ptr(),
            256
        ),
        19
    );
    assert_eq!(output, [0xab; 256]);
    let mut rng = StdRng::seed_from_u64(72);
    use rand::RngCore;
    for n in 0..512 {
        let mut bytes = vec![0; n];
        rng.fill_bytes(&mut bytes);
        assert!(Circuit::from_bytes(&bytes).is_err());
    }
    let mut count_bomb = c.clone();
    count_bomb[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Circuit::from_bytes(&count_bomb).is_err());
    let mut forward = c.clone();
    forward[23..27].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Circuit::from_bytes(&forward).is_err());
}

#[test]
fn thirty_two_level_merkle_path_fits_the_constraint_budget() {
    let mut c = Circuit::new(1, 65).unwrap();
    let siblings: Vec<_> = (1..33).map(|i| c.private(i).unwrap()).collect();
    let directions: Vec<_> = (33..65).map(|i| c.private(i).unwrap()).collect();
    let root = c
        .merkle_root(c.private(0).unwrap(), &siblings, &directions)
        .unwrap();
    c.equal(root, c.public(0).unwrap()).unwrap();
    assert!(Circuit::from_bytes(&c.to_bytes()).is_ok());
}
