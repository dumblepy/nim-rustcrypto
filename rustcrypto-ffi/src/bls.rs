//! BLS12-381 curve operations and BLS signing APIs (FFI implementation, `blst` backend).
//!
//! Scalar encoding matches the prior `bls12_381` / `bls-signatures` surface: 32-byte **little-endian**
//! canonical field element representation.

use crate::{
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_ERR_RANDOM_FAILED, RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_OK, aead_common,
};
use blst::{
    blst_final_exp, blst_fp12_is_one, blst_fp12_mul, blst_fr_add, blst_fr_from_scalar, blst_fr_mul,
    blst_hash_to_g1, blst_hash_to_g2, blst_lendian_from_scalar, blst_p1_add_or_double_affine,
    blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_affine_is_inf, blst_p1_affine_serialize,
    blst_p1_cneg, blst_p1_deserialize, blst_p1_from_affine, blst_p1_generator, blst_p1_mult,
    blst_p1_to_affine, blst_p1_uncompress, blst_p2_add_or_double_affine, blst_p2_affine_compress,
    blst_p2_affine_in_g2, blst_p2_affine_is_inf, blst_p2_affine_serialize, blst_p2_cneg,
    blst_p2_deserialize, blst_p2_from_affine, blst_p2_generator, blst_p2_mult, blst_p2_to_affine,
    blst_p2_uncompress, blst_scalar_from_fr, blst_scalar_from_hexascii, blst_scalar_from_lendian,
    blst_scalar_from_le_bytes, blst_sk_check, blst_sk_inverse, blst_fp12, blst_fr, blst_p1,
    blst_p1_affine, blst_p2, blst_p2_affine, blst_scalar, min_pk, min_sig, BLST_ERROR,
};
use core::ffi::c_int;
use core::mem::MaybeUninit;
use hkdf::Hkdf;
use sha2::Sha256;
#[cfg(not(target_arch = "wasm32"))]
use rand_core::{OsRng, RngCore};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const BLS12_381_SCALAR_LEN: usize = 32;
pub const BLS12_381_G1_COMPRESSED_LEN: usize = 48;
pub const BLS12_381_G1_UNCOMPRESSED_LEN: usize = 96;
pub const BLS12_381_G2_COMPRESSED_LEN: usize = 96;
pub const BLS12_381_G2_UNCOMPRESSED_LEN: usize = 192;

const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const AUG_G1_CSUITE: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";
const KEYGEN_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

fn compressed_flag(compressed: c_int) -> Result<bool, c_int> {
    match compressed {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
    }
}

fn blst_err_to_cint(err: BLST_ERROR) -> c_int {
    match err {
        BLST_ERROR::BLST_SUCCESS => RUSTCRYPTO_OK,
        BLST_ERROR::BLST_VERIFY_FAIL => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
        BLST_ERROR::BLST_PK_IS_INFINITY => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
        _ => RUSTCRYPTO_ERR_INVALID_PARAMETER,
    }
}

fn read_scalar(bytes: &[u8; BLS12_381_SCALAR_LEN]) -> Result<blst_scalar, c_int> {
    let mut s = blst_scalar::default();
    unsafe {
        blst_scalar_from_lendian(&mut s, bytes.as_ptr());
        if !blst_sk_check(&s) {
            return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
        }
    }
    Ok(s)
}

fn write_scalar_le(s: &blst_scalar) -> [u8; BLS12_381_SCALAR_LEN] {
    let mut out = [0u8; BLS12_381_SCALAR_LEN];
    unsafe {
        blst_lendian_from_scalar(out.as_mut_ptr(), s);
    }
    out
}

fn scalar_from_okm(okm: &[u8; 48]) -> Result<blst_scalar, c_int> {
    let mut wide = [0u8; 64];
    wide[16..].copy_from_slice(okm);
    wide.reverse();
    let mut s = blst_scalar::default();
    if unsafe { blst_scalar_from_le_bytes(&mut s, wide.as_ptr(), wide.len()) } {
        Ok(s)
    } else {
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    }
}

fn key_gen_from_ikm(ikm: &[u8]) -> Result<blst_scalar, c_int> {
    if ikm.len() < 32 {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut msg = ikm.to_vec();
    msg.push(0);
    let hk = Hkdf::<Sha256>::new(Some(KEYGEN_SALT), &msg);
    let mut okm = [0u8; 48];
    hk.expand(&[0u8, 48u8], &mut okm)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)?;
    scalar_from_okm(&okm)
}

fn min_pk_secret_from_le(bytes: &[u8; BLS12_381_SCALAR_LEN]) -> Result<min_pk::SecretKey, c_int> {
    let s = read_scalar(bytes)?;
    if unsafe { blst_sk_check(&s) } {
        Ok(unsafe { core::mem::transmute::<blst_scalar, min_pk::SecretKey>(s) })
    } else {
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    }
}

fn g1_decode(point: &[u8], compressed: bool) -> Result<blst_p1_affine, c_int> {
    let mut out = blst_p1_affine::default();
    let err = if compressed {
        if point.len() != BLS12_381_G1_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        unsafe { blst_p1_uncompress(&mut out, point.as_ptr()) }
    } else if point.len() == BLS12_381_G1_UNCOMPRESSED_LEN {
        unsafe { blst_p1_deserialize(&mut out, point.as_ptr()) }
    } else {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    if !unsafe { blst_p1_affine_in_g1(&out) } {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    Ok(out)
}

fn g2_decode(point: &[u8], compressed: bool) -> Result<blst_p2_affine, c_int> {
    let mut out = blst_p2_affine::default();
    let err = if compressed {
        if point.len() != BLS12_381_G2_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        unsafe { blst_p2_uncompress(&mut out, point.as_ptr()) }
    } else if point.len() == BLS12_381_G2_UNCOMPRESSED_LEN {
        unsafe { blst_p2_deserialize(&mut out, point.as_ptr()) }
    } else {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    if !unsafe { blst_p2_affine_in_g2(&out) } {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    Ok(out)
}

fn g1_encode_affine(p: &blst_p1_affine, compressed: bool, out: &mut [u8]) -> Result<(), c_int> {
    if compressed {
        if out.len() < BLS12_381_G1_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        unsafe {
            blst_p1_affine_compress(out.as_mut_ptr(), p);
        }
    } else {
        if out.len() < BLS12_381_G1_UNCOMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        unsafe {
            blst_p1_affine_serialize(out.as_mut_ptr(), p);
        }
    }
    Ok(())
}

fn g1_is_canonical_compressed(point: &[u8; BLS12_381_G1_COMPRESSED_LEN]) -> bool {
    let Ok(p) = g1_decode(point, true) else {
        return false;
    };
    let mut buf = [0u8; BLS12_381_G1_COMPRESSED_LEN];
    unsafe {
        blst_p1_affine_compress(buf.as_mut_ptr(), &p);
    }
    buf == *point
}

fn g2_is_canonical_compressed(point: &[u8; BLS12_381_G2_COMPRESSED_LEN]) -> bool {
    let Ok(p) = g2_decode(point, true) else {
        return false;
    };
    let mut buf = [0u8; BLS12_381_G2_COMPRESSED_LEN];
    unsafe {
        blst_p2_affine_compress(buf.as_mut_ptr(), &p);
    }
    buf == *point
}

fn g2_encode_affine(p: &blst_p2_affine, compressed: bool, out: &mut [u8]) -> Result<(), c_int> {
    if compressed {
        if out.len() < BLS12_381_G2_COMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        unsafe {
            blst_p2_affine_compress(out.as_mut_ptr(), p);
        }
    } else {
        if out.len() < BLS12_381_G2_UNCOMPRESSED_LEN {
            return Err(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        }
        unsafe {
            blst_p2_affine_serialize(out.as_mut_ptr(), p);
        }
    }
    Ok(())
}

fn g1_affine_to_projective(p: &blst_p1_affine) -> blst_p1 {
    let mut out = blst_p1::default();
    unsafe {
        blst_p1_from_affine(&mut out, p);
    }
    out
}

fn g2_affine_to_projective(p: &blst_p2_affine) -> blst_p2 {
    let mut out = blst_p2::default();
    unsafe {
        blst_p2_from_affine(&mut out, p);
    }
    out
}

fn g1_projective_to_affine(p: &blst_p1) -> blst_p1_affine {
    let mut out = blst_p1_affine::default();
    unsafe {
        blst_p1_to_affine(&mut out, p);
    }
    out
}

fn g2_projective_to_affine(p: &blst_p2) -> blst_p2_affine {
    let mut out = blst_p2_affine::default();
    unsafe {
        blst_p2_to_affine(&mut out, p);
    }
    out
}

fn hash_to_g2(msg: &[u8]) -> blst_p2 {
    let mut out = blst_p2::default();
    unsafe {
        blst_hash_to_g2(
            &mut out,
            msg.as_ptr(),
            msg.len(),
            CSUITE.as_ptr(),
            CSUITE.len(),
            core::ptr::null(),
            0,
        );
    }
    out
}

fn hash_to_g1_aug(public_key: &[u8], message: &[u8]) -> Result<blst_p1, c_int> {
    let _pk = g2_decode(public_key, true)?;
    let mut out = blst_p1::default();
    unsafe {
        blst_hash_to_g1(
            &mut out,
            message.as_ptr(),
            message.len(),
            AUG_G1_CSUITE.as_ptr(),
            AUG_G1_CSUITE.len(),
            public_key.as_ptr(),
            public_key.len(),
        );
    }
    Ok(out)
}

fn fp12_mul_assign(acc: &mut blst_fp12, other: &blst_fp12) {
    unsafe {
        blst_fp12_mul(acc, acc, other);
    }
}

fn fp12_is_identity(f: &blst_fp12) -> bool {
    unsafe { blst_fp12_is_one(f) }
}

fn verify_aggregate_impl(
    signature: &blst_p2_affine,
    hashes: &[blst_p2_affine],
    public_keys: &[blst_p1_affine],
) -> c_int {
    if hashes.is_empty() || public_keys.is_empty() {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    if hashes.len() != public_keys.len() {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    if hashes.len() == 1 && unsafe { blst_p1_affine_is_inf(&public_keys[0]) } {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            if hashes[i] == hashes[j] {
                return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
            }
        }
    }

    let mut acc = blst_fp12::default();
    let mut ok = true;
    for (pk, h) in public_keys.iter().zip(hashes.iter()) {
        if unsafe { blst_p1_affine_is_inf(pk) } {
            ok = false;
        }
        fp12_mul_assign(&mut acc, &blst_fp12::miller_loop(h, pk));
    }
    if !ok {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }

    let mut g1_gen = unsafe { *blst_p1_generator() };
    unsafe {
        blst_p1_cneg(&mut g1_gen, true);
    }
    let g1_neg = g1_projective_to_affine(&g1_gen);
    fp12_mul_assign(&mut acc, &blst_fp12::miller_loop(signature, &g1_neg));

    let mut fe = MaybeUninit::<blst_fp12>::uninit();
    unsafe {
        blst_final_exp(fe.as_mut_ptr(), &acc);
    }
    let fe = unsafe { fe.assume_init() };
    if fp12_is_identity(&fe) {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

fn verify_g1_aug_hash_impl(
    signature: &blst_p1_affine,
    hash: &blst_p1_affine,
    public_key: &blst_p2_affine,
) -> c_int {
    if unsafe { blst_p2_affine_is_inf(public_key) } {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    if unsafe { blst_p1_affine_is_inf(signature) } {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }
    if unsafe { blst_p1_affine_is_inf(hash) } {
        return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
    }

    let mut g2_gen = unsafe { *blst_p2_generator() };
    unsafe {
        blst_p2_cneg(&mut g2_gen, true);
    }
    let g2_neg = g2_projective_to_affine(&g2_gen);

    let mut acc = blst_fp12::miller_loop(&g2_neg, signature);
    fp12_mul_assign(&mut acc, &blst_fp12::miller_loop(public_key, hash));

    let mut fe = MaybeUninit::<blst_fp12>::uninit();
    unsafe {
        blst_final_exp(fe.as_mut_ptr(), &acc);
    }
    let fe = unsafe { fe.assume_init() };
    if fp12_is_identity(&fe) {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

type FrBinOp = unsafe extern "C" fn(*mut blst_fr, *const blst_fr, *const blst_fr);

fn scalar_fr_binop(lhs: &blst_scalar, rhs: &blst_scalar, op: FrBinOp) -> Result<blst_scalar, c_int> {
    let mut la = blst_fr::default();
    let mut ra = blst_fr::default();
    let mut out = blst_fr::default();
    unsafe {
        blst_fr_from_scalar(&mut la, lhs);
        blst_fr_from_scalar(&mut ra, rhs);
        op(&mut out, &la, &ra);
    }
    let mut s = blst_scalar::default();
    unsafe {
        blst_scalar_from_fr(&mut s, &out);
    }
    if !unsafe { blst_sk_check(&s) } {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    Ok(s)
}

// --- FFI: scalar ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_validate(scalar: *const u8, scalar_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_validate_impl(scalar, scalar_len))).unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_validate_impl(scalar: *const u8, scalar_len: usize) -> c_int {
    let s = match aead_common::fixed_input(
        scalar,
        scalar_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut arr = [0u8; BLS12_381_SCALAR_LEN];
    arr.copy_from_slice(s);
    if read_scalar(&arr).is_err() {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_random(output: *mut u8, output_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_random_impl(output, output_len))).unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_random_impl(output: *mut u8, output_len: usize) -> c_int {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (output, output_len);
        return RUSTCRYPTO_ERR_RANDOM_FAILED;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        for _ in 0..64 {
            OsRng.fill_bytes(out);
            let mut arr = [0u8; BLS12_381_SCALAR_LEN];
            arr.copy_from_slice(out);
            if read_scalar(&arr).is_ok() {
                return RUSTCRYPTO_OK;
            }
        }
        RUSTCRYPTO_ERR_RANDOM_FAILED
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_add(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        scalar_binop_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, blst_fr_add)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_mul(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        scalar_binop_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, blst_fr_mul)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_binop_impl(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    op: FrBinOp,
) -> c_int {
    let lb = match aead_common::fixed_input(
        lhs,
        lhs_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let rb = match aead_common::fixed_input(
        rhs,
        rhs_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut la = [0u8; BLS12_381_SCALAR_LEN];
    let mut ra = [0u8; BLS12_381_SCALAR_LEN];
    la.copy_from_slice(lb);
    ra.copy_from_slice(rb);
    let a = match read_scalar(&la) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let b = match read_scalar(&ra) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let r = match scalar_fr_binop(&a, &b, op) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
        Ok(o) => o,
        Err(e) => return e,
    };
    out.copy_from_slice(&write_scalar_le(&r));
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_scalar_invert(
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| scalar_invert_impl(scalar, scalar_len, output, output_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn scalar_invert_impl(scalar: *const u8, scalar_len: usize, output: *mut u8, output_len: usize) -> c_int {
    let sb = match aead_common::fixed_input(
        scalar,
        scalar_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut arr = [0u8; BLS12_381_SCALAR_LEN];
    arr.copy_from_slice(sb);
    let s = match read_scalar(&arr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut inv = blst_scalar::default();
    unsafe {
        blst_sk_inverse(&mut inv, &s);
    }
    if !unsafe { blst_sk_check(&inv) } {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
        Ok(o) => o,
        Err(e) => return e,
    };
    out.copy_from_slice(&write_scalar_le(&inv));
    RUSTCRYPTO_OK
}

// --- FFI: G1 / G2 generators ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_generator(
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let req = if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        };
        let out = match aead_common::output_buffer(output, output_len, req) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let g = g1_projective_to_affine(unsafe { &*blst_p1_generator() });
        if g1_encode_affine(&g, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_generator(
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let req = if compressed {
            BLS12_381_G2_COMPRESSED_LEN
        } else {
            BLS12_381_G2_UNCOMPRESSED_LEN
        };
        let out = match aead_common::output_buffer(output, output_len, req) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let g = g2_projective_to_affine(unsafe { &*blst_p2_generator() });
        if g2_encode_affine(&g, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

// --- validate / add / neg / mul ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_validate(
    point: *const u8,
    point_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let plen = if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        };
        let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
            Ok(b) => b,
            Err(e) => return e,
        };
        if g1_decode(pb, compressed).is_err() {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_validate(
    point: *const u8,
    point_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let compressed = match compressed_flag(compressed) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let plen = if compressed {
            BLS12_381_G2_COMPRESSED_LEN
        } else {
            BLS12_381_G2_UNCOMPRESSED_LEN
        };
        let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
            Ok(b) => b,
            Err(e) => return e,
        };
        if g2_decode(pb, compressed).is_err() {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_add(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        g1_g2_add_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, compressed, true)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_add(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        g1_g2_add_impl(lhs, lhs_len, rhs, rhs_len, output, output_len, compressed, false)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g1_g2_add_impl(
    lhs: *const u8,
    lhs_len: usize,
    rhs: *const u8,
    rhs_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
    is_g1: bool,
) -> c_int {
    let compressed = match compressed_flag(compressed) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let plen = if is_g1 {
        if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        }
    } else if compressed {
        BLS12_381_G2_COMPRESSED_LEN
    } else {
        BLS12_381_G2_UNCOMPRESSED_LEN
    };
    let lb = match aead_common::fixed_input(lhs, lhs_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let rb = match aead_common::fixed_input(rhs, rhs_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, plen) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if is_g1 {
        let a = match g1_decode(lb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let b = match g1_decode(rb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut sum = blst_p1::default();
        unsafe {
            blst_p1_add_or_double_affine(&mut sum, &g1_affine_to_projective(&a), &b);
        }
        let aff = g1_projective_to_affine(&sum);
        if g1_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    } else {
        let a = match g2_decode(lb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let b = match g2_decode(rb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut sum = blst_p2::default();
        unsafe {
            blst_p2_add_or_double_affine(&mut sum, &g2_affine_to_projective(&a), &b);
        }
        let aff = g2_projective_to_affine(&sum);
        if g2_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_neg(
    point: *const u8,
    point_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g_neg_impl(point, point_len, output, output_len, compressed, true)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_neg(
    point: *const u8,
    point_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g_neg_impl(point, point_len, output, output_len, compressed, false)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g_neg_impl(
    point: *const u8,
    point_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
    is_g1: bool,
) -> c_int {
    let compressed = match compressed_flag(compressed) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let plen = if is_g1 {
        if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        }
    } else if compressed {
        BLS12_381_G2_COMPRESSED_LEN
    } else {
        BLS12_381_G2_UNCOMPRESSED_LEN
    };
    let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, plen) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if is_g1 {
        let p = match g1_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut n = g1_affine_to_projective(&p);
        unsafe {
            blst_p1_cneg(&mut n, true);
        }
        let aff = g1_projective_to_affine(&n);
        if g1_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    } else {
        let p = match g2_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut n = g2_affine_to_projective(&p);
        unsafe {
            blst_p2_cneg(&mut n, true);
        }
        let aff = g2_projective_to_affine(&n);
        if g2_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    }
    RUSTCRYPTO_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g1_mul(
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        g_mul_impl(point, point_len, scalar, scalar_len, output, output_len, compressed, true)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_g2_mul(
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        g_mul_impl(point, point_len, scalar, scalar_len, output, output_len, compressed, false)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g_mul_impl(
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    scalar_len: usize,
    output: *mut u8,
    output_len: usize,
    compressed: c_int,
    is_g1: bool,
) -> c_int {
    let compressed = match compressed_flag(compressed) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let plen = if is_g1 {
        if compressed {
            BLS12_381_G1_COMPRESSED_LEN
        } else {
            BLS12_381_G1_UNCOMPRESSED_LEN
        }
    } else if compressed {
        BLS12_381_G2_COMPRESSED_LEN
    } else {
        BLS12_381_G2_UNCOMPRESSED_LEN
    };
    let pb = match aead_common::fixed_input(point, point_len, plen, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let sb = match aead_common::fixed_input(
        scalar,
        scalar_len,
        BLS12_381_SCALAR_LEN,
        RUSTCRYPTO_ERR_INVALID_PARAMETER,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut sa = [0u8; BLS12_381_SCALAR_LEN];
    sa.copy_from_slice(sb);
    let s = match read_scalar(&sa) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let out = match aead_common::output_buffer(output, output_len, plen) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let scalar_le = write_scalar_le(&s);
    if is_g1 {
        let p = match g1_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut r = blst_p1::default();
        unsafe {
            blst_p1_mult(
                &mut r,
                &g1_affine_to_projective(&p),
                scalar_le.as_ptr(),
                BLS12_381_SCALAR_LEN * 8,
            );
        }
        let aff = g1_projective_to_affine(&r);
        if g1_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    } else {
        let p = match g2_decode(pb, compressed) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut r = blst_p2::default();
        unsafe {
            blst_p2_mult(
                &mut r,
                &g2_affine_to_projective(&p),
                scalar_le.as_ptr(),
                BLS12_381_SCALAR_LEN * 8,
            );
        }
        let aff = g2_projective_to_affine(&r);
        if g2_encode_affine(&aff, compressed, out).is_err() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
    }
    RUSTCRYPTO_OK
}

// --- pairing ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_pairing_eq(
    g1_lhs: *const u8,
    g1_lhs_len: usize,
    g2_lhs: *const u8,
    g2_lhs_len: usize,
    g1_rhs: *const u8,
    g1_rhs_len: usize,
    g2_rhs: *const u8,
    g2_rhs_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| pairing_eq_impl(
        g1_lhs, g1_lhs_len, g2_lhs, g2_lhs_len, g1_rhs, g1_rhs_len, g2_rhs, g2_rhs_len,
    )))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn pairing_eq_impl(
    g1_lhs: *const u8,
    g1_lhs_len: usize,
    g2_lhs: *const u8,
    g2_lhs_len: usize,
    g1_rhs: *const u8,
    g1_rhs_len: usize,
    g2_rhs: *const u8,
    g2_rhs_len: usize,
) -> c_int {
    let a1 = match aead_common::fixed_input(
        g1_lhs,
        g1_lhs_len,
        BLS12_381_G1_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let a2 = match aead_common::fixed_input(
        g2_lhs,
        g2_lhs_len,
        BLS12_381_G2_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let b1 = match aead_common::fixed_input(
        g1_rhs,
        g1_rhs_len,
        BLS12_381_G1_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let b2 = match aead_common::fixed_input(
        g2_rhs,
        g2_rhs_len,
        BLS12_381_G2_COMPRESSED_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let a1a = match g1_decode(a1, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let a2a = match g2_decode(a2, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let b1a = match g1_decode(b1, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let b2a = match g2_decode(b2, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let p1 = blst_fp12::miller_loop(&a2a, &a1a).final_exp();
    let p2 = blst_fp12::miller_loop(&b2a, &b1a).final_exp();
    if blst_fp12::finalverify(&p1, &p2) {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_pairing_product_is_identity(
    g1_points: *const u8,
    g1_points_len: usize,
    g2_points: *const u8,
    g2_points_len: usize,
    pair_count: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| pairing_product_identity_impl(
        g1_points,
        g1_points_len,
        g2_points,
        g2_points_len,
        pair_count,
    )))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn pairing_product_identity_impl(
    g1_points: *const u8,
    g1_points_len: usize,
    g2_points: *const u8,
    g2_points_len: usize,
    pair_count: usize,
) -> c_int {
    if pair_count == 0 {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    let expect_g1 = match pair_count.checked_mul(BLS12_381_G1_COMPRESSED_LEN) {
        Some(v) => v,
        None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
    };
    let expect_g2 = match pair_count.checked_mul(BLS12_381_G2_COMPRESSED_LEN) {
        Some(v) => v,
        None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
    };
    if g1_points_len != expect_g1 || g2_points_len != expect_g2 {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    if g1_points.is_null() || g2_points.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }
    let g1s = unsafe { core::slice::from_raw_parts(g1_points, g1_points_len) };
    let g2s = unsafe { core::slice::from_raw_parts(g2_points, g2_points_len) };
    let mut acc = blst_fp12::default();
    for i in 0..pair_count {
        let g1b = &g1s[i * BLS12_381_G1_COMPRESSED_LEN..(i + 1) * BLS12_381_G1_COMPRESSED_LEN];
        let g2b = &g2s[i * BLS12_381_G2_COMPRESSED_LEN..(i + 1) * BLS12_381_G2_COMPRESSED_LEN];
        let g1a = match g1_decode(g1b, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let g2a = match g2_decode(g2b, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        fp12_mul_assign(&mut acc, &blst_fp12::miller_loop(&g2a, &g1a));
    }
    let fe = acc.final_exp();
    if fp12_is_identity(&fe) {
        RUSTCRYPTO_OK
    } else {
        RUSTCRYPTO_ERR_VERIFICATION_FAILED
    }
}

// --- BLS signatures (minimal-pk-size) ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_private_key_from_seed(
    seed: *const u8,
    seed_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let seed_sl = match aead_common::optional_input(seed, seed_len) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sk = match key_gen_from_ikm(seed_sl) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&write_scalar_le(&sk));
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_private_key_generate(output: *mut u8, output_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (output, output_len);
            return RUSTCRYPTO_ERR_RANDOM_FAILED;
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut ikm = [0u8; 32];
            if OsRng.try_fill_bytes(&mut ikm).is_err() {
                return RUSTCRYPTO_ERR_RANDOM_FAILED;
            }
            let sk = match key_gen_from_ikm(&ikm) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
                Ok(o) => o,
                Err(e) => return e,
            };
            out.copy_from_slice(&write_scalar_le(&sk));
            RUSTCRYPTO_OK
        }
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_private_key_from_decimal_string(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let bytes = match aead_common::optional_input(input, input_len) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let s = match core::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
        };
        let mut sk = blst_scalar::default();
        unsafe {
            blst_scalar_from_hexascii(&mut sk, s.as_ptr());
            if !blst_sk_check(&sk) {
                return RUSTCRYPTO_ERR_INVALID_PARAMETER;
            }
        }
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_SCALAR_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&write_scalar_le(&sk));
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_public_key(
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let kb = match aead_common::fixed_input(
            private_key,
            private_key_len,
            BLS12_381_SCALAR_LEN,
            RUSTCRYPTO_ERR_INVALID_PARAMETER,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let mut arr = [0u8; BLS12_381_SCALAR_LEN];
        arr.copy_from_slice(kb);
        let sk = match min_pk_secret_from_le(&arr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let pk = sk.sk_to_pk();
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G1_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&pk.compress());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_hash(
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let msg = match aead_common::optional_input(message, message_len) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let h = g2_projective_to_affine(&hash_to_g2(msg));
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G2_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let mut buf = [0u8; BLS12_381_G2_COMPRESSED_LEN];
        unsafe {
            blst_p2_affine_compress(buf.as_mut_ptr(), &h);
        }
        out.copy_from_slice(&buf);
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_sign(
    message: *const u8,
    message_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let msg = match aead_common::optional_input(message, message_len) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let kb = match aead_common::fixed_input(
            private_key,
            private_key_len,
            BLS12_381_SCALAR_LEN,
            RUSTCRYPTO_ERR_INVALID_PARAMETER,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let mut arr = [0u8; BLS12_381_SCALAR_LEN];
        arr.copy_from_slice(kb);
        let sk = match min_pk_secret_from_le(&arr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let sig = sk.sign(msg, CSUITE, &[]);
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G2_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        out.copy_from_slice(&sig.compress());
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_aggregate(
    signatures: *const u8,
    signatures_len: usize,
    signature_count: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if signature_count == 0 {
            return RUSTCRYPTO_ERR_INVALID_LENGTH;
        }
        let need = match signature_count.checked_mul(BLS12_381_G2_COMPRESSED_LEN) {
            Some(v) => v,
            None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
        };
        if signatures_len != need {
            return RUSTCRYPTO_ERR_INVALID_LENGTH;
        }
        if signatures.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        let slab = unsafe { core::slice::from_raw_parts(signatures, signatures_len) };
        let mut acc = blst_p2::default();
        let mut first = true;
        for i in 0..signature_count {
            let chunk = &slab[i * BLS12_381_G2_COMPRESSED_LEN..(i + 1) * BLS12_381_G2_COMPRESSED_LEN];
            let p = match g2_decode(chunk, true) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if first {
                acc = g2_affine_to_projective(&p);
                first = false;
            } else {
                unsafe {
                    blst_p2_add_or_double_affine(&mut acc, &acc, &p);
                }
            }
        }
        let aff = g2_projective_to_affine(&acc);
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G2_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        unsafe {
            blst_p2_affine_compress(out.as_mut_ptr(), &aff);
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_verify(
    signature: *const u8,
    signature_len: usize,
    hashes: *const u8,
    hashes_len: usize,
    public_keys: *const u8,
    public_keys_len: usize,
    pair_count: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if pair_count == 0 {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        let sigb = match aead_common::fixed_input(
            signature,
            signature_len,
            BLS12_381_G2_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let need_h = pair_count * BLS12_381_G2_COMPRESSED_LEN;
        let need_pk = pair_count * BLS12_381_G1_COMPRESSED_LEN;
        if hashes_len != need_h || public_keys_len != need_pk {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        if hashes.is_null() || public_keys.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        let sig_a = match g2_decode(sigb, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let hslab = unsafe { core::slice::from_raw_parts(hashes, hashes_len) };
        let pkslab = unsafe { core::slice::from_raw_parts(public_keys, public_keys_len) };
        let mut hashes_a: Vec<blst_p2_affine> = Vec::with_capacity(pair_count);
        let mut pks: Vec<blst_p1_affine> = Vec::with_capacity(pair_count);
        for i in 0..pair_count {
            let hb = &hslab[i * BLS12_381_G2_COMPRESSED_LEN..(i + 1) * BLS12_381_G2_COMPRESSED_LEN];
            let pk = &pkslab[i * BLS12_381_G1_COMPRESSED_LEN..(i + 1) * BLS12_381_G1_COMPRESSED_LEN];
            hashes_a.push(match g2_decode(hb, true) {
                Ok(v) => v,
                Err(e) => return e,
            });
            pks.push(match g1_decode(pk, true) {
                Ok(v) => v,
                Err(e) => return e,
            });
        }
        verify_aggregate_impl(&sig_a, &hashes_a, &pks)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_verify_messages(
    signature: *const u8,
    signature_len: usize,
    messages: *const *const u8,
    message_lens: *const usize,
    message_count: usize,
    public_keys: *const u8,
    public_keys_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if message_count == 0 {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        if public_keys_len != message_count * BLS12_381_G1_COMPRESSED_LEN {
            return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
        }
        if messages.is_null() || message_lens.is_null() || public_keys.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        let sigb = match aead_common::fixed_input(
            signature,
            signature_len,
            BLS12_381_G2_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let sig = match min_pk::Signature::from_bytes(sigb) {
            Ok(v) => v,
            Err(e) => return blst_err_to_cint(e),
        };
        let mptrs = unsafe { core::slice::from_raw_parts(messages, message_count) };
        let mlens = unsafe { core::slice::from_raw_parts(message_lens, message_count) };
        let pkslab = unsafe { core::slice::from_raw_parts(public_keys, public_keys_len) };

        let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(message_count);
        let mut pks: Vec<min_pk::PublicKey> = Vec::with_capacity(message_count);
        for i in 0..message_count {
            let msg = match aead_common::optional_input(mptrs[i], mlens[i]) {
                Ok(m) => m,
                Err(e) => return e,
            };
            msgs.push(msg.to_vec());
            let pk_bytes =
                &pkslab[i * BLS12_381_G1_COMPRESSED_LEN..(i + 1) * BLS12_381_G1_COMPRESSED_LEN];
            let pk = match min_pk::PublicKey::from_bytes(pk_bytes) {
                Ok(v) => v,
                Err(e) => return blst_err_to_cint(e),
            };
            pks.push(pk);
        }

        for i in 0..message_count {
            for j in (i + 1)..message_count {
                if msgs[i] == msgs[j] {
                    return RUSTCRYPTO_ERR_VERIFICATION_FAILED;
                }
            }
        }

        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let pk_refs: Vec<&min_pk::PublicKey> = pks.iter().collect();
        blst_err_to_cint(sig.aggregate_verify(true, &msg_refs, CSUITE, &pk_refs, true))
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

// --- BLS minimal-signature-size + message augmentation (G2 pk / G1 sig / G1 hash) ---

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_hash_g1_aug(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let pkb = match aead_common::fixed_input(
            public_key,
            public_key_len,
            BLS12_381_G2_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let msg = match aead_common::optional_input(message, message_len) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let h = match hash_to_g1_aug(pkb, msg) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let aff = g1_projective_to_affine(&h);
        let out = match aead_common::output_buffer(output, output_len, BLS12_381_G1_COMPRESSED_LEN) {
            Ok(o) => o,
            Err(e) => return e,
        };
        unsafe {
            blst_p1_affine_compress(out.as_mut_ptr(), &aff);
        }
        RUSTCRYPTO_OK
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_verify_g1_aug_hash(
    signature: *const u8,
    signature_len: usize,
    message_hash: *const u8,
    message_hash_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let sigb = match aead_common::fixed_input(
            signature,
            signature_len,
            BLS12_381_G1_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let hb = match aead_common::fixed_input(
            message_hash,
            message_hash_len,
            BLS12_381_G1_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let pkb = match aead_common::fixed_input(
            public_key,
            public_key_len,
            BLS12_381_G2_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let mut sig_arr = [0u8; BLS12_381_G1_COMPRESSED_LEN];
        sig_arr.copy_from_slice(sigb);
        if !g1_is_canonical_compressed(&sig_arr) {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        let mut hash_arr = [0u8; BLS12_381_G1_COMPRESSED_LEN];
        hash_arr.copy_from_slice(hb);
        if !g1_is_canonical_compressed(&hash_arr) {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        let mut pk_arr = [0u8; BLS12_381_G2_COMPRESSED_LEN];
        pk_arr.copy_from_slice(pkb);
        if !g2_is_canonical_compressed(&pk_arr) {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        let sig_a = match g1_decode(sigb, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let hash_a = match g1_decode(hb, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let pk_a = match g2_decode(pkb, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        verify_g1_aug_hash_impl(&sig_a, &hash_a, &pk_a)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bls12_381_signature_verify_g1_aug_message(
    signature: *const u8,
    signature_len: usize,
    message: *const u8,
    message_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let sigb = match aead_common::fixed_input(
            signature,
            signature_len,
            BLS12_381_G1_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let pkb = match aead_common::fixed_input(
            public_key,
            public_key_len,
            BLS12_381_G2_COMPRESSED_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let msg = match aead_common::optional_input(message, message_len) {
            Ok(m) => m,
            Err(e) => return e,
        };
        let mut sig_arr = [0u8; BLS12_381_G1_COMPRESSED_LEN];
        sig_arr.copy_from_slice(sigb);
        if !g1_is_canonical_compressed(&sig_arr) {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        let mut pk_arr = [0u8; BLS12_381_G2_COMPRESSED_LEN];
        pk_arr.copy_from_slice(pkb);
        if !g2_is_canonical_compressed(&pk_arr) {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        let sig = match min_sig::Signature::from_bytes(sigb) {
            Ok(v) => v,
            Err(e) => return blst_err_to_cint(e),
        };
        let pk = match min_sig::PublicKey::from_bytes(pkb) {
            Ok(v) => v,
            Err(e) => return blst_err_to_cint(e),
        };
        blst_err_to_cint(sig.verify(true, msg, AUG_G1_CSUITE, pkb, &pk, true))
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls_signatures::{
        aggregate as bs_agg, hash as bs_hash, verify as bs_verify, PrivateKey, Serialize, Signature,
    };

    #[test]
    fn key_gen_matches_bls_signatures() {
        let material = b"hello world (it's a secret!) very secret stuff";
        let mut out = [0u8; 32];
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_signature_private_key_from_seed(
                material.as_ptr(),
                material.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        );
        let sk = PrivateKey::new(material);
        assert_eq!(out.as_slice(), sk.as_bytes().as_slice());
    }

    #[test]
    fn sign_verify_roundtrip_matches() {
        let msg = b"this is the message";
        let seed = b"this is the key and it is very secret";
        let mut sk = [0u8; 32];
        rustcrypto_bls12_381_signature_private_key_from_seed(seed.as_ptr(), seed.len(), sk.as_mut_ptr(), 32);
        let mut pk = [0u8; 48];
        rustcrypto_bls12_381_signature_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 48);
        let mut sig = [0u8; 96];
        rustcrypto_bls12_381_signature_sign(msg.as_ptr(), msg.len(), sk.as_ptr(), 32, sig.as_mut_ptr(), 96);
        let bs_sk = PrivateKey::new(seed);
        let bs_sig = bs_sk.sign(msg);
        assert_eq!(sig.as_slice(), bs_sig.as_bytes());
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_signature_verify_messages(
                sig.as_ptr(),
                96,
                [msg.as_ptr()].as_ptr(),
                [msg.len()].as_ptr(),
                1,
                pk.as_ptr(),
                48,
            )
        );
        let ref_pk = bls_signatures::PublicKey::from_bytes(&pk).unwrap();
        assert!(ref_pk.verify(bs_sig, msg));
        assert!(bs_verify(&bs_sig, &[bs_hash(msg)], &[ref_pk]));
    }

    #[test]
    fn pairing_bilinearity_smoke() {
        let mut g = [0u8; 48];
        rustcrypto_bls12_381_g1_generator(g.as_mut_ptr(), 48, 1);
        let s = read_scalar(&{
            let mut tmp = [0u8; 32];
            tmp[0] = 2;
            tmp
        })
        .unwrap();
        let s_bytes = write_scalar_le(&s);
        let mut g2 = [0u8; 48];
        rustcrypto_bls12_381_g1_mul(g.as_ptr(), 48, s_bytes.as_ptr(), 32, g2.as_mut_ptr(), 48, 1);
        let mut h = [0u8; 96];
        rustcrypto_bls12_381_g2_generator(h.as_mut_ptr(), 96, 1);
        let mut inv = blst_scalar::default();
        unsafe {
            blst_sk_inverse(&mut inv, &s);
        }
        let s_inv = write_scalar_le(&inv);
        let mut h2 = [0u8; 96];
        rustcrypto_bls12_381_g2_mul(h.as_ptr(), 96, s_inv.as_ptr(), 32, h2.as_mut_ptr(), 96, 1);
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_pairing_eq(g.as_ptr(), 48, h.as_ptr(), 96, g2.as_ptr(), 48, h2.as_ptr(), 96)
        );
    }

    #[test]
    fn duplicate_message_fails() {
        let seed = [7u8; 40];
        let mut sk = [0u8; 32];
        rustcrypto_bls12_381_signature_private_key_from_seed(seed.as_ptr(), seed.len(), sk.as_mut_ptr(), 32);
        let mut pk = [0u8; 48];
        rustcrypto_bls12_381_signature_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 48);
        let msg = b"same";
        let mut sk2 = [0u8; 32];
        rustcrypto_bls12_381_signature_private_key_from_seed([8u8; 40].as_ptr(), 40, sk2.as_mut_ptr(), 32);
        let mut pk2 = [0u8; 48];
        rustcrypto_bls12_381_signature_public_key(sk2.as_ptr(), 32, pk2.as_mut_ptr(), 48);
        let mut s1 = [0u8; 96];
        let mut s2 = [0u8; 96];
        rustcrypto_bls12_381_signature_sign(msg.as_ptr(), msg.len(), sk.as_ptr(), 32, s1.as_mut_ptr(), 96);
        rustcrypto_bls12_381_signature_sign(msg.as_ptr(), msg.len(), sk2.as_ptr(), 32, s2.as_mut_ptr(), 96);
        let mut agg = [0u8; 96];
        let slab: Vec<u8> = s1.iter().chain(s2.iter()).copied().collect();
        let sig1 = Signature::from_bytes(&s1).unwrap();
        let sig2 = Signature::from_bytes(&s2).unwrap();
        let agg_bs = bs_agg(&[sig1, sig2]).unwrap();
        rustcrypto_bls12_381_signature_aggregate(slab.as_ptr(), slab.len(), 2, agg.as_mut_ptr(), 96);
        assert_eq!(agg.as_slice(), agg_bs.as_bytes().as_slice());
        let msgs = [msg.as_ptr(), msg.as_ptr()];
        let lens = [msg.len(), msg.len()];
        let mut pkb = [0u8; 96];
        pkb[..48].copy_from_slice(&pk);
        pkb[48..].copy_from_slice(&pk2);
        assert_eq!(
            RUSTCRYPTO_ERR_VERIFICATION_FAILED,
            rustcrypto_bls12_381_signature_verify_messages(
                agg.as_ptr(),
                96,
                msgs.as_ptr(),
                lens.as_ptr(),
                2,
                pkb.as_ptr(),
                96,
            )
        );
    }

    fn aug_g1_test_vectors() -> ([u8; 96], [u8; 48], [u8; 48], &'static [u8]) {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[..8].copy_from_slice(&0x4242_4242_4242_4242u64.to_le_bytes());
        let sk = read_scalar(&sk_bytes).expect("scalar");
        let sk_le = write_scalar_le(&sk);
        let mut pk = [0u8; 96];
        rustcrypto_bls12_381_g2_generator(pk.as_mut_ptr(), 96, 1);
        rustcrypto_bls12_381_g2_mul(pk.as_ptr(), 96, sk_le.as_ptr(), 32, pk.as_mut_ptr(), 96, 1);
        let message: &'static [u8] = b"aug g1 test message";
        let mut hash = [0u8; 48];
        rustcrypto_bls12_381_signature_hash_g1_aug(
            pk.as_ptr(),
            pk.len(),
            message.as_ptr(),
            message.len(),
            hash.as_mut_ptr(),
            hash.len(),
        );
        let mut sig = [0u8; 48];
        rustcrypto_bls12_381_g1_mul(hash.as_ptr(), 48, sk_le.as_ptr(), 32, sig.as_mut_ptr(), 48, 1);
        (pk, sig, hash, message)
    }

    #[test]
    fn aug_g1_hash_verify_roundtrip() {
        let (pk, sig, hash, message) = aug_g1_test_vectors();
        let mut out_hash = [0u8; 48];
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_signature_hash_g1_aug(
                pk.as_ptr(),
                pk.len(),
                message.as_ptr(),
                message.len(),
                out_hash.as_mut_ptr(),
                out_hash.len(),
            )
        );
        assert_eq!(out_hash.as_slice(), hash.as_slice());
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_signature_verify_g1_aug_hash(
                sig.as_ptr(),
                sig.len(),
                hash.as_ptr(),
                hash.len(),
                pk.as_ptr(),
                pk.len(),
            )
        );
        assert_eq!(
            RUSTCRYPTO_OK,
            rustcrypto_bls12_381_signature_verify_g1_aug_message(
                sig.as_ptr(),
                sig.len(),
                message.as_ptr(),
                message.len(),
                pk.as_ptr(),
                pk.len(),
            )
        );
    }

    #[test]
    fn aug_g1_verify_rejects_tampering() {
        let (pk, sig, hash, message) = aug_g1_test_vectors();
        let mut bad_msg = message.to_vec();
        bad_msg.push(b'!');
        assert_eq!(
            RUSTCRYPTO_ERR_VERIFICATION_FAILED,
            rustcrypto_bls12_381_signature_verify_g1_aug_message(
                sig.as_ptr(),
                sig.len(),
                bad_msg.as_ptr(),
                bad_msg.len(),
                pk.as_ptr(),
                pk.len(),
            )
        );
        let mut bad_pk = pk;
        bad_pk[0] ^= 0x01;
        assert_eq!(
            RUSTCRYPTO_ERR_INVALID_PARAMETER,
            rustcrypto_bls12_381_signature_verify_g1_aug_message(
                sig.as_ptr(),
                sig.len(),
                message.as_ptr(),
                message.len(),
                bad_pk.as_ptr(),
                bad_pk.len(),
            )
        );
        let mut bad_sig = sig;
        bad_sig[0] ^= 0x01;
        assert_eq!(
            RUSTCRYPTO_ERR_INVALID_PARAMETER,
            rustcrypto_bls12_381_signature_verify_g1_aug_hash(
                bad_sig.as_ptr(),
                bad_sig.len(),
                hash.as_ptr(),
                hash.len(),
                pk.as_ptr(),
                pk.len(),
            )
        );
        let mut sk_wrong = [0u8; 32];
        sk_wrong[..8].copy_from_slice(&0xdead_beef_cafe_babeu64.to_le_bytes());
        let sk_wrong_le = write_scalar_le(&read_scalar(&sk_wrong).unwrap());
        let mut wrong_sig = [0u8; 48];
        rustcrypto_bls12_381_g1_mul(hash.as_ptr(), 48, sk_wrong_le.as_ptr(), 32, wrong_sig.as_mut_ptr(), 48, 1);
        assert_eq!(
            RUSTCRYPTO_ERR_VERIFICATION_FAILED,
            rustcrypto_bls12_381_signature_verify_g1_aug_hash(
                wrong_sig.as_ptr(),
                wrong_sig.len(),
                hash.as_ptr(),
                hash.len(),
                pk.as_ptr(),
                pk.len(),
            )
        );
        let mut sk2_bytes = [0u8; 32];
        sk2_bytes[..8].copy_from_slice(&0x1337_1337_1337_1337u64.to_le_bytes());
        let sk2_le = write_scalar_le(&read_scalar(&sk2_bytes).unwrap());
        let mut pk2 = [0u8; 96];
        rustcrypto_bls12_381_g2_generator(pk2.as_mut_ptr(), 96, 1);
        rustcrypto_bls12_381_g2_mul(pk2.as_ptr(), 96, sk2_le.as_ptr(), 32, pk2.as_mut_ptr(), 96, 1);
        assert_eq!(
            RUSTCRYPTO_ERR_VERIFICATION_FAILED,
            rustcrypto_bls12_381_signature_verify_g1_aug_hash(
                sig.as_ptr(),
                sig.len(),
                hash.as_ptr(),
                hash.len(),
                pk2.as_ptr(),
                pk2.len(),
            )
        );
    }

    #[test]
    fn aug_g1_identity_public_key_fails() {
        let (_, sig, hash, _) = aug_g1_test_vectors();
        let mut id_pk = [0u8; 96];
        id_pk[0] = 0xc0;
        assert_eq!(
            RUSTCRYPTO_ERR_VERIFICATION_FAILED,
            rustcrypto_bls12_381_signature_verify_g1_aug_hash(
                sig.as_ptr(),
                sig.len(),
                hash.as_ptr(),
                hash.len(),
                id_pk.as_ptr(),
                id_pk.len(),
            )
        );
    }

    #[test]
    fn aug_g1_invalid_lengths_are_input_errors() {
        let (pk, sig, hash, message) = aug_g1_test_vectors();
        let mut out = [0u8; 48];
        assert_eq!(
            RUSTCRYPTO_ERR_INVALID_LENGTH,
            rustcrypto_bls12_381_signature_hash_g1_aug(
                pk.as_ptr(),
                pk.len() - 1,
                message.as_ptr(),
                message.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        );
        assert_eq!(
            RUSTCRYPTO_ERR_INVALID_LENGTH,
            rustcrypto_bls12_381_signature_verify_g1_aug_hash(
                sig.as_ptr(),
                sig.len() - 1,
                hash.as_ptr(),
                hash.len(),
                pk.as_ptr(),
                pk.len(),
            )
        );
        assert_eq!(
            RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
            rustcrypto_bls12_381_signature_hash_g1_aug(
                pk.as_ptr(),
                pk.len(),
                message.as_ptr(),
                message.len(),
                out.as_mut_ptr(),
                out.len() - 1,
            )
        );
    }
}
