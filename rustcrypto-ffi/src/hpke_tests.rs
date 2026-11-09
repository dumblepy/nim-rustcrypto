use super::*;
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn rfc9180_base_vector_and_rejection() {
    let sk = hex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    let mut pk = [0u8; 32];
    unsafe {
        assert_eq!(
            rustcrypto_hpke_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 32),
            0
        );
    }
    assert_eq!(
        pk.as_slice(),
        hex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
    );
    let info = hex("4f6465206f6e2061204772656369616e2055726e");
    let aad = hex("436f756e742d30");
    let mut wire = hex(
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
    );
    let expected = hex("4265617574792069732074727574682c20747275746820626561757479");
    let mut out = vec![0xa5; expected.len()];
    unsafe {
        assert_eq!(
            rustcrypto_hpke_open(
                sk.as_ptr(),
                32,
                info.as_ptr(),
                info.len(),
                aad.as_ptr(),
                aad.len(),
                wire.as_ptr(),
                wire.len(),
                out.as_mut_ptr(),
                out.len()
            ),
            0
        );
    }
    assert_eq!(out, expected);
    for i in [0, 32, wire.len() - 1] {
        wire[i] ^= 1;
        out.fill(0xa5);
        unsafe {
            assert_ne!(
                rustcrypto_hpke_open(
                    sk.as_ptr(),
                    32,
                    info.as_ptr(),
                    info.len(),
                    aad.as_ptr(),
                    aad.len(),
                    wire.as_ptr(),
                    wire.len(),
                    out.as_mut_ptr(),
                    out.len()
                ),
                0
            );
        }
        assert!(out.iter().all(|b| *b == 0xa5));
        wire[i] ^= 1;
    }
}
#[test]
fn roundtrip_empty_and_invalid_inputs() {
    unsafe {
        let mut sk = [0; 32];
        let mut pk = [0; 32];
        assert_eq!(rustcrypto_hpke_generate_secret_key(sk.as_mut_ptr(), 32), 0);
        assert_eq!(
            rustcrypto_hpke_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 32),
            0
        );
        let mut wire = [0; 48];
        let mut second = [0; 48];
        let n = core::ptr::null();
        for out in [&mut wire, &mut second] {
            assert_eq!(
                rustcrypto_hpke_seal(pk.as_ptr(), 32, n, 0, n, 0, n, 0, out.as_mut_ptr(), 48),
                0
            );
        }
        assert_ne!(wire, second);
        assert_eq!(
            rustcrypto_hpke_open(
                sk.as_ptr(),
                32,
                n,
                0,
                n,
                0,
                wire.as_ptr(),
                48,
                core::ptr::null_mut(),
                0
            ),
            0
        );
        let zero = [0; 32];
        assert_ne!(
            rustcrypto_hpke_seal(zero.as_ptr(), 32, n, 0, n, 0, n, 0, wire.as_mut_ptr(), 48),
            0
        );
        assert_ne!(
            rustcrypto_hpke_seal(pk.as_ptr(), 32, n, 1, n, 0, n, 0, wire.as_mut_ptr(), 48),
            0
        );
        assert_ne!(
            rustcrypto_hpke_seal(pk.as_ptr(), 31, n, 0, n, 0, n, 0, wire.as_mut_ptr(), 48),
            0
        );
        assert_ne!(
            rustcrypto_hpke_seal(pk.as_ptr(), 32, n, 0, n, 0, n, 0, wire.as_mut_ptr(), 47),
            0
        );
        assert_ne!(
            rustcrypto_hpke_open(
                sk.as_ptr(),
                32,
                n,
                0,
                n,
                0,
                wire.as_ptr(),
                47,
                n as *mut u8,
                0
            ),
            0
        );
        assert_ne!(rustcrypto_hpke_public_key(n, 32, pk.as_mut_ptr(), 32), 0);
        assert_ne!(
            rustcrypto_hpke_generate_secret_key(core::ptr::null_mut(), 32),
            0
        );
    }
}

#[test]
fn low_order_noncanonical_and_limits_leave_output_unchanged() {
    unsafe {
        let n = core::ptr::null();
        let mut out = [0xa5; 48];
        let mut one = [0; 32];
        one[0] = 1;
        let mut prime = [0xff; 32];
        prime[0] = 0xed;
        prime[31] = 0x7f;
        let low_order = hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        for pk in [
            &[0u8; 32][..],
            &one[..],
            &prime[..],
            &[0xffu8; 32][..],
            &low_order[..],
        ] {
            assert_ne!(
                rustcrypto_hpke_seal(pk.as_ptr(), 32, n, 0, n, 0, n, 0, out.as_mut_ptr(), 48),
                0
            );
            assert_eq!(out, [0xa5; 48]);
        }
        assert_eq!(
            rustcrypto_hpke_seal(
                one.as_ptr(),
                32,
                n,
                0,
                n,
                0,
                n,
                MAX + 1,
                out.as_mut_ptr(),
                48
            ),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
        assert_eq!(
            rustcrypto_hpke_seal(
                one.as_ptr(),
                32,
                n,
                CONTEXT_MAX + 1,
                n,
                0,
                n,
                0,
                out.as_mut_ptr(),
                48
            ),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
        assert_eq!(
            rustcrypto_hpke_open(
                one.as_ptr(),
                32,
                n,
                0,
                n,
                0,
                n,
                usize::MAX,
                out.as_mut_ptr(),
                48
            ),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
        assert_eq!(out, [0xa5; 48]);
        assert_eq!(rustcrypto_hpke_clear_secret_key(one.as_mut_ptr(), 32), 0);
        assert_eq!(one, [0; 32]);
    }
}

#[test]
fn contexts_and_wrong_key_never_release_plaintext() {
    unsafe {
        let sk = [7; 32];
        let mut pk = [0; 32];
        let n = core::ptr::null();
        assert_eq!(
            rustcrypto_hpke_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 32),
            0
        );
        let mut wire = [0; 51];
        let msg = [1, 2, 3];
        let context = [8];
        let bad = [9];
        assert_eq!(
            rustcrypto_hpke_seal(
                pk.as_ptr(),
                32,
                context.as_ptr(),
                1,
                context.as_ptr(),
                1,
                msg.as_ptr(),
                3,
                wire.as_mut_ptr(),
                51
            ),
            0
        );
        let wrong_sk = [9; 32];
        for (key, info, aad) in [
            (&wrong_sk, context.as_ptr(), context.as_ptr()),
            (&sk, bad.as_ptr(), context.as_ptr()),
            (&sk, context.as_ptr(), bad.as_ptr()),
        ] {
            let mut out = [0xa5; 3];
            assert_eq!(
                rustcrypto_hpke_open(
                    key.as_ptr(),
                    32,
                    info,
                    1,
                    aad,
                    1,
                    wire.as_ptr(),
                    51,
                    out.as_mut_ptr(),
                    3
                ),
                RUSTCRYPTO_ERR_AUTHENTICATION_FAILED
            );
            assert_eq!(out, [0xa5; 3]);
        }
        let mut out = [0xa5; 3];
        wire[..32].fill(0);
        assert_ne!(
            rustcrypto_hpke_open(
                sk.as_ptr(),
                32,
                n,
                0,
                n,
                0,
                wire.as_ptr(),
                51,
                out.as_mut_ptr(),
                3
            ),
            0
        );
        assert_eq!(out, [0xa5; 3]);
    }
}

#[test]
fn panics_are_contained() {
    assert_eq!(
        boundary(|| -> Result<(), c_int> { panic!("test panic") }),
        RUSTCRYPTO_ERR_PANIC
    );
}

struct EntropyGuard;
impl Drop for EntropyGuard {
    fn drop(&mut self) {
        TEST_ENTROPY.with(|cell| *cell.borrow_mut() = None);
    }
}
#[test]
fn entropy_failure_never_writes_outputs() {
    TEST_ENTROPY.with(|cell| *cell.borrow_mut() = Some(Err(())));
    let _guard = EntropyGuard;
    unsafe {
        let sk = [7; 32];
        let mut pk = [0; 32];
        let mut out = [0xa5; 48];
        let n = core::ptr::null();
        assert_eq!(
            rustcrypto_hpke_generate_secret_key(out.as_mut_ptr(), 32),
            RUSTCRYPTO_ERR_RANDOM_FAILED
        );
        assert_eq!(out, [0xa5; 48]);
        assert_eq!(
            rustcrypto_hpke_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 32),
            0
        );
        assert_eq!(
            rustcrypto_hpke_seal(pk.as_ptr(), 32, n, 0, n, 0, n, 0, out.as_mut_ptr(), 48),
            RUSTCRYPTO_ERR_RANDOM_FAILED
        );
        assert_eq!(out, [0xa5; 48]);
    }
}

#[test]
fn seal_matches_cfrg_vector_through_ffi() {
    let ikme = hex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
    let pkrm = hex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    let info = hex("4f6465206f6e2061204772656369616e2055726e");
    let enc = hex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    let aad = hex("436f756e742d30");
    let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
    let ct = hex(
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
    );
    TEST_ENTROPY.with(|cell| *cell.borrow_mut() = Some(Ok(ikme.try_into().unwrap())));
    let _guard = EntropyGuard;
    let mut out = vec![0; pt.len() + 48];
    unsafe {
        assert_eq!(
            rustcrypto_hpke_seal(
                pkrm.as_ptr(),
                32,
                info.as_ptr(),
                info.len(),
                aad.as_ptr(),
                aad.len(),
                pt.as_ptr(),
                pt.len(),
                out.as_mut_ptr(),
                out.len()
            ),
            0
        );
    }
    assert_eq!(out, [enc, ct].concat());
}
