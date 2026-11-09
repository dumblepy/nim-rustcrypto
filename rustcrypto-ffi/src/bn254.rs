//! BN254 finite-field and curve point encoding helpers (C ABI).
//!
//! # Wire format v1
//!
//! All integers are encoded **big-endian** and must be canonical.
//!
//! - `Fr` / `Fq`: exactly 32 bytes. Values greater than or equal to the modulus are rejected;
//!   inputs are never silently reduced modulo the field modulus.
//! - `G1`: exactly 64 bytes: `x (32) || y (32)`.
//! - `G2`: exactly 128 bytes: `x.c0 (32) || x.c1 (32) || y.c0 (32) || y.c1 (32)`.
//!   `c0` is the constant coefficient and `c1` is the coefficient of `u` in `Fq2 = Fq[u]/(u^2 + 1)`.
//! - The point at infinity is encoded as an all-zero byte string of the point length.
//!   Any other all-zero coordinate pair is rejected as an invalid curve point.
//! - Non-infinity points must be on the curve and in the prime-order subgroup.
//!
//! This module deliberately exposes only validation. Higher-level APIs (Poseidon, Groth16)
//! build on these primitives.

use crate::{
    RUSTCRYPTO_ERR_INVALID_CURVE_POINT, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_OK,
};
use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use core::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub const BN254_FR_LEN: usize = 32;
pub const BN254_G1_LEN: usize = 64;
pub const BN254_G2_LEN: usize = 128;

fn canonical_bytes<F: PrimeField>(value: &F, len: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = value.into_bigint().to_bytes_be();
    debug_assert!(bytes.len() <= 32);
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    debug_assert_eq!(len, 32);
    out
}

fn is_canonical<F: PrimeField>(value: &F, bytes: &[u8]) -> bool {
    let canonical = canonical_bytes(value, bytes.len());
    canonical[..] == bytes[..]
}

pub(crate) fn fr_from_be(bytes: &[u8]) -> Result<Fr, c_int> {
    if bytes.len() != BN254_FR_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let value = Fr::from_be_bytes_mod_order(bytes);
    if !is_canonical(&value, bytes) {
        return Err(RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT);
    }
    Ok(value)
}

pub(crate) fn fr_to_be(value: &Fr) -> [u8; BN254_FR_LEN] {
    canonical_bytes(value, BN254_FR_LEN)
}

pub(crate) fn fq_from_be(bytes: &[u8]) -> Result<Fq, c_int> {
    if bytes.len() != 32 {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let value = Fq::from_be_bytes_mod_order(bytes);
    if !is_canonical(&value, bytes) {
        return Err(RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT);
    }
    Ok(value)
}

fn fq_to_be(value: &Fq) -> [u8; 32] {
    canonical_bytes(value, 32)
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

pub(crate) fn g1_from_bytes(bytes: &[u8], allow_infinity: bool) -> Result<G1Affine, c_int> {
    if bytes.len() != BN254_G1_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if is_all_zero(bytes) {
        return if allow_infinity {
            Ok(G1Affine::identity())
        } else {
            Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT)
        };
    }
    let x = fq_from_be(&bytes[..32])?;
    let y = fq_from_be(&bytes[32..])?;
    let point = G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT);
    }
    Ok(point)
}

pub(crate) fn g2_from_bytes(bytes: &[u8], allow_infinity: bool) -> Result<G2Affine, c_int> {
    if bytes.len() != BN254_G2_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if is_all_zero(bytes) {
        return if allow_infinity {
            Ok(G2Affine::identity())
        } else {
            Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT)
        };
    }
    let x = Fq2::new(fq_from_be(&bytes[..32])?, fq_from_be(&bytes[32..64])?);
    let y = Fq2::new(fq_from_be(&bytes[64..96])?, fq_from_be(&bytes[96..128])?);
    let point = G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT);
    }
    Ok(point)
}

pub(crate) fn g1_to_bytes(point: &G1Affine) -> [u8; BN254_G1_LEN] {
    let mut out = [0u8; BN254_G1_LEN];
    if let Some((x, y)) = point.xy() {
        out[..32].copy_from_slice(&fq_to_be(&x));
        out[32..].copy_from_slice(&fq_to_be(&y));
    }
    out
}

pub(crate) fn g2_to_bytes(point: &G2Affine) -> [u8; BN254_G2_LEN] {
    let mut out = [0u8; BN254_G2_LEN];
    if let Some((x, y)) = point.xy() {
        out[..32].copy_from_slice(&fq_to_be(&x.c0));
        out[32..64].copy_from_slice(&fq_to_be(&x.c1));
        out[64..96].copy_from_slice(&fq_to_be(&y.c0));
        out[96..128].copy_from_slice(&fq_to_be(&y.c1));
    }
    out
}

fn input_slice<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], c_int> {
    if input_len == 0 {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if input.is_null() {
        return Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }
    Ok(unsafe { core::slice::from_raw_parts(input, input_len) })
}

fn fr_validate_impl(input: *const u8, input_len: usize) -> c_int {
    let bytes = match input_slice(input, input_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match fr_from_be(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

/// Validates that `input` is a canonical 32-byte big-endian BN254 `Fr` element.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bn254_fr_validate(input: *const u8, input_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| fr_validate_impl(input, input_len))).unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g1_validate_impl(point: *const u8, point_len: usize) -> c_int {
    let bytes = match input_slice(point, point_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match g1_from_bytes(bytes, true) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

/// Validates a canonical 64-byte big-endian BN254 G1 point (infinity allowed).
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bn254_g1_validate(point: *const u8, point_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g1_validate_impl(point, point_len))).unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn g2_validate_impl(point: *const u8, point_len: usize) -> c_int {
    let bytes = match input_slice(point, point_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match g2_from_bytes(bytes, true) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

/// Validates a canonical 128-byte big-endian BN254 G2 point (infinity allowed).
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_bn254_g2_validate(point: *const u8, point_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| g2_validate_impl(point, point_len))).unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::Zero;

    #[test]
    fn fr_rejects_non_canonical_values() {
        let mut modulus = [0u8; 32];
        modulus[..].copy_from_slice(&Fr::MODULUS.to_bytes_be());
        assert_eq!(fr_from_be(&modulus), Err(RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT));

        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(fr_from_be(&one), Ok(Fr::from(1u64)));

        let zero = [0u8; 32];
        assert_eq!(fr_from_be(&zero), Ok(Fr::zero()));
    }

    #[test]
    fn g1_round_trip_and_infinity() {
        let generator = G1Affine::generator();
        let encoded = g1_to_bytes(&generator);
        assert_eq!(g1_from_bytes(&encoded, false), Ok(generator));

        let infinity = [0u8; BN254_G1_LEN];
        assert_eq!(g1_from_bytes(&infinity, true), Ok(G1Affine::identity()));
        assert_eq!(g1_from_bytes(&infinity, false), Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT));
    }

    #[test]
    fn g1_rejects_off_curve_points() {
        let mut encoded = g1_to_bytes(&G1Affine::generator());
        encoded[63] ^= 1;
        assert_eq!(g1_from_bytes(&encoded, false), Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT));
    }

    #[test]
    fn g2_round_trip() {
        let generator = G2Affine::generator();
        let encoded = g2_to_bytes(&generator);
        assert_eq!(g2_from_bytes(&encoded, false), Ok(generator));
    }

    #[test]
    fn g2_rejects_off_curve_points() {
        let mut encoded = g2_to_bytes(&G2Affine::generator());
        encoded[127] ^= 1;
        assert_eq!(g2_from_bytes(&encoded, false), Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT));
    }
}
