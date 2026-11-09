//! Halo2 (PSE/Axiom KZG/BN254, SHPLONK, Blake2b transcript) verification (C ABI).
//!
//! # Fixed profile (v1)
//!
//! - Implementation: `snark-verifier` 0.2.7 over `halo2-axiom` 0.5.3
//!   (PSE-halo2 derivative), pinned through `Cargo.lock`.
//! - Curve / field: BN254, scalar field `Fr`.
//! - Polynomial commitment: KZG over BN254 with a universal SRS.
//! - Multi-open scheme: **SHPLONK** (`snark_verifier::pcs::kzg::Bdfg21`).
//! - Fiat-Shamir: halo2 `Blake2bRead`/`Blake2bWrite`
//!   (`b"Halo2-Transcript"`, 64-byte challenges). The Poseidon transcript and the
//!   EVM/Keccak transcript are **different profiles** and are not accepted.
//! - Protocol encoding: `bincode` 1.3 of `snark_verifier`'s `PlonkProtocol<G1Affine>`.
//!
//! This is **not** Zcash `halo2_proofs` IPA/Pasta and not gnark PLONK.
//!
//! # Wire format v1
//!
//! ## params (328 bytes)
//!
//! ```text
//! magic   8 bytes  "RCH2P1\0\0"
//! [1]_1   G1  (64)  SRS G1 generator
//! [1]_2   G2 (128)
//! [tau]_2 G2 (128)
//! ```
//!
//! ## verifying key
//!
//! ```text
//! magic        8 bytes "RCH2V1\0\0"
//! protocol_len u32 BE
//! protocol     bincode(PlonkProtocol<G1Affine>)
//! ```
//!
//! ## public instances
//!
//! ```text
//! magic          8 bytes "RCH2I1\0\0"
//! column_count   u32 BE (<= 64)
//! for each column:
//!   value_count  u32 BE
//!   values       value_count * Fr (32-byte big-endian, canonical)
//! ```
//!
//! ## proof
//!
//! The raw bytes written by halo2's `Blake2bWrite` transcript for the SHPLONK prover.
//! Trailing bytes are rejected.
//!
//! # Security notes
//!
//! The caller is responsible for trusting the params/SRS and the verifying key
//! (circuit). This library checks structural validity and the pairing equation only.

use crate::{
    RUSTCRYPTO_ERR_INVALID_CURVE_POINT, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT, RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_OK, aead_common,
};
use bincode::Options;
use core::cell::Cell;
use core::ffi::c_int;
use snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fq2, Fr, G1Affine, G2Affine};
use snark_verifier::halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use snark_verifier::halo2_base::halo2_proofs::halo2curves::group::cofactor::CofactorGroup;
use snark_verifier::halo2_base::halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;
use snark_verifier::halo2_base::halo2_proofs::halo2curves::CurveAffine;
use snark_verifier::halo2_base::halo2_proofs::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
use snark_verifier::pcs::kzg::{Bdfg21, KzgAs, KzgDecidingKey};
use snark_verifier::verifier::plonk::{PlonkProtocol, PlonkVerifier};
use snark_verifier::verifier::SnarkVerifier;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

pub const HALO2_KZG_BN254_PARAMS_V1_MAGIC: &[u8; 8] = b"RCH2P1\0\0";
pub const HALO2_KZG_BN254_VK_V1_MAGIC: &[u8; 8] = b"RCH2V1\0\0";
pub const HALO2_KZG_BN254_INSTANCES_V1_MAGIC: &[u8; 8] = b"RCH2I1\0\0";
pub const HALO2_KZG_BN254_PARAMS_V1_LEN: usize = 8 + 64 + 128 + 128;
pub const HALO2_KZG_BN254_VK_V1_HEADER_LEN: usize = 12;
pub const HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN: usize = 12;
pub const HALO2_KZG_BN254_MAX_PROTOCOL_LEN: usize = 2 * 1024 * 1024;
pub const HALO2_KZG_BN254_MAX_PROOF_LEN: usize = 16 * 1024 * 1024;
pub const HALO2_KZG_BN254_MAX_INSTANCE_COLUMNS: usize = 64;
pub const HALO2_KZG_BN254_MAX_INSTANCE_VALUES: usize = 1 << 20;

fn halo_fq_from_be(bytes: &[u8]) -> Result<Fq, c_int> {
    if bytes.len() != 32 {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut le = [0u8; 32];
    for (i, byte) in bytes.iter().enumerate() {
        le[31 - i] = *byte;
    }
    Option::<Fq>::from(Fq::from_repr(le)).ok_or(RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT)
}

fn halo_fr_from_be(bytes: &[u8]) -> Result<Fr, c_int> {
    if bytes.len() != 32 {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut le = [0u8; 32];
    for (i, byte) in bytes.iter().enumerate() {
        le[31 - i] = *byte;
    }
    Option::<Fr>::from(Fr::from_repr(le)).ok_or(RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT)
}

fn halo_g1_from_be(bytes: &[u8]) -> Result<G1Affine, c_int> {
    // Reuse the arkworks canonical/on-curve/subgroup validation first.
    let _ = crate::bn254::g1_from_bytes(bytes, true)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(G1Affine::identity());
    }
    let x = halo_fq_from_be(&bytes[..32])?;
    let y = halo_fq_from_be(&bytes[32..64])?;
    let point = Option::<G1Affine>::from(G1Affine::from_xy(x, y)).ok_or(RUSTCRYPTO_ERR_INVALID_CURVE_POINT)?;
    if bool::from(point.to_curve().is_torsion_free()) {
        Ok(point)
    } else {
        Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT)
    }
}

fn halo_g2_from_be(bytes: &[u8]) -> Result<G2Affine, c_int> {
    let _ = crate::bn254::g2_from_bytes(bytes, true)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(G2Affine::identity());
    }
    let x = Fq2 {
        c0: halo_fq_from_be(&bytes[..32])?,
        c1: halo_fq_from_be(&bytes[32..64])?,
    };
    let y = Fq2 {
        c0: halo_fq_from_be(&bytes[64..96])?,
        c1: halo_fq_from_be(&bytes[96..128])?,
    };
    let point = Option::<G2Affine>::from(G2Affine::from_xy(x, y)).ok_or(RUSTCRYPTO_ERR_INVALID_CURVE_POINT)?;
    if bool::from(point.to_curve().is_torsion_free()) {
        Ok(point)
    } else {
        Err(RUSTCRYPTO_ERR_INVALID_CURVE_POINT)
    }
}

fn parse_params(bytes: &[u8]) -> Result<KzgDecidingKey<Bn256>, c_int> {
    if bytes.len() != HALO2_KZG_BN254_PARAMS_V1_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if &bytes[..8] != HALO2_KZG_BN254_PARAMS_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let g1 = halo_g1_from_be(&bytes[8..72]).map_err(|_| RUSTCRYPTO_ERR_INVALID_CURVE_POINT)?;
    let g2 = halo_g2_from_be(&bytes[72..200]).map_err(|_| RUSTCRYPTO_ERR_INVALID_CURVE_POINT)?;
    let s_g2 = halo_g2_from_be(&bytes[200..328]).map_err(|_| RUSTCRYPTO_ERR_INVALID_CURVE_POINT)?;
    Ok(KzgDecidingKey::<Bn256>::new(g1, g2, s_g2))
}

fn parse_protocol(bytes: &[u8]) -> Result<PlonkProtocol<G1Affine>, c_int> {
    if bytes.len() < HALO2_KZG_BN254_VK_V1_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    if &bytes[..8] != HALO2_KZG_BN254_VK_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let protocol_len = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?,
    ) as usize;
    if protocol_len == 0
        || protocol_len > HALO2_KZG_BN254_MAX_PROTOCOL_LEN
        || bytes.len() != HALO2_KZG_BN254_VK_V1_HEADER_LEN + protocol_len
    {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let protocol: PlonkProtocol<G1Affine> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(HALO2_KZG_BN254_MAX_PROTOCOL_LEN as u64)
        .reject_trailing_bytes()
        .deserialize(&bytes[HALO2_KZG_BN254_VK_V1_HEADER_LEN..])
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;

    if protocol.num_instance.len() > HALO2_KZG_BN254_MAX_INSTANCE_COLUMNS
        || protocol.num_instance.iter().sum::<usize>() > HALO2_KZG_BN254_MAX_INSTANCE_VALUES
        || protocol.num_witness.len() > HALO2_KZG_BN254_MAX_INSTANCE_COLUMNS
        || protocol.preprocessed.len() > 4096
    {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let valid_point = |point: &G1Affine| {
        bool::from(point.is_on_curve()) && bool::from(point.to_curve().is_torsion_free())
    };
    for point in &protocol.preprocessed {
        if !valid_point(point) {
            return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
        }
    }
    if let Some(key) = &protocol.instance_committing_key {
        if key.bases.len() > 4096 {
            return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
        }
        for point in &key.bases {
            if !valid_point(point) {
                return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
            }
        }
        if let Some(point) = &key.constant {
            if !valid_point(point) {
                return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
            }
        }
    }
    Ok(protocol)
}

fn parse_instances(bytes: &[u8]) -> Result<Vec<Vec<Fr>>, c_int> {
    if bytes.len() < HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if &bytes[..8] != HALO2_KZG_BN254_INSTANCES_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let column_count = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?,
    ) as usize;
    if column_count > HALO2_KZG_BN254_MAX_INSTANCE_COLUMNS {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
    }

    let mut offset = HALO2_KZG_BN254_INSTANCES_V1_HEADER_LEN;
    let mut total_values = 0usize;
    let mut columns = Vec::with_capacity(column_count);
    for _ in 0..column_count {
        if offset + 4 > bytes.len() {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let value_count = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?,
        ) as usize;
        offset += 4;
        total_values = match total_values.checked_add(value_count) {
            Some(total) if total <= HALO2_KZG_BN254_MAX_INSTANCE_VALUES => total,
            _ => return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT),
        };
        let value_bytes = match value_count.checked_mul(32) {
            Some(len) => len,
            None => return Err(RUSTCRYPTO_ERR_INVALID_LENGTH),
        };
        if offset + value_bytes > bytes.len() {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let mut column = Vec::with_capacity(value_count);
        for chunk in bytes[offset..offset + value_bytes].chunks_exact(32) {
            column.push(halo_fr_from_be(chunk)?);
        }
        offset += value_bytes;
        columns.push(column);
    }
    if offset != bytes.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    Ok(columns)
}

struct CountingReader<'a> {
    data: &'a [u8],
    position: Rc<Cell<usize>>,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let position = self.position.get();
        let remaining = &self.data[position..];
        let count = remaining.len().min(buf.len());
        buf[..count].copy_from_slice(&remaining[..count]);
        self.position.set(position + count);
        Ok(count)
    }
}

fn read_blob<'a>(ptr: *const u8, len: usize, error: c_int) -> Result<&'a [u8], c_int> {
    if len == 0 || len > HALO2_KZG_BN254_MAX_PROOF_LEN {
        return Err(error);
    }
    if ptr.is_null() {
        return Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

fn verify_impl(
    params_ptr: *const u8,
    params_len: usize,
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    if params_len != HALO2_KZG_BN254_PARAMS_V1_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    if vk_len < HALO2_KZG_BN254_VK_V1_HEADER_LEN || vk_len > HALO2_KZG_BN254_VK_V1_HEADER_LEN + HALO2_KZG_BN254_MAX_PROTOCOL_LEN {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    if proof_len == 0 || proof_len > HALO2_KZG_BN254_MAX_PROOF_LEN {
        return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT;
    }
    let params_bytes = match aead_common::optional_input(params_ptr, params_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let vk_bytes = match aead_common::optional_input(vk_ptr, vk_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let proof_bytes = match aead_common::optional_input(proof_ptr, proof_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    let instances_bytes = match read_blob(instances_ptr, instances_len, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };

    let dk = match parse_params(params_bytes) {
        Ok(dk) => dk,
        Err(err) => return err,
    };
    let protocol = match parse_protocol(vk_bytes) {
        Ok(protocol) => protocol,
        Err(err) => return err,
    };
    let instances = match parse_instances(instances_bytes) {
        Ok(instances) => instances,
        Err(err) => return err,
    };
    if instances.len() != protocol.num_instance.len()
        || instances
            .iter()
            .zip(protocol.num_instance.iter())
            .any(|(column, expected)| column.len() != *expected)
    {
        return RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT;
    }

    let position = Rc::new(Cell::new(0usize));
    let reader = CountingReader {
        data: proof_bytes,
        position: position.clone(),
    };
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(reader);
    let proof = match PlonkVerifier::<KzgAs<Bn256, Bdfg21>>::read_proof(
        &dk,
        &protocol,
        &instances,
        &mut transcript,
    ) {
        Ok(proof) => proof,
        Err(_) => return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    };
    if position.get() != proof_bytes.len() {
        return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT;
    }
    match PlonkVerifier::<KzgAs<Bn256, Bdfg21>>::verify(&dk, &protocol, &instances, &proof) {
        Ok(()) => RUSTCRYPTO_OK,
        Err(_) => RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    }
}

fn validate_params_impl(params_ptr: *const u8, params_len: usize) -> c_int {
    if params_len != HALO2_KZG_BN254_PARAMS_V1_LEN {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    let bytes = match aead_common::optional_input(params_ptr, params_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match parse_params(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

fn validate_vk_impl(vk_ptr: *const u8, vk_len: usize) -> c_int {
    if vk_len < HALO2_KZG_BN254_VK_V1_HEADER_LEN
        || vk_len > HALO2_KZG_BN254_VK_V1_HEADER_LEN + HALO2_KZG_BN254_MAX_PROTOCOL_LEN
    {
        return RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY;
    }
    let bytes = match aead_common::optional_input(vk_ptr, vk_len) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match parse_protocol(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

fn validate_instances_impl(instances_ptr: *const u8, instances_len: usize) -> c_int {
    let bytes = match read_blob(instances_ptr, instances_len, RUSTCRYPTO_ERR_INVALID_LENGTH) {
        Ok(bytes) => bytes,
        Err(err) => return err,
    };
    match parse_instances(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(err) => err,
    }
}

/// Verifies a Halo2 PSE/Axiom KZG/BN254 SHPLONK proof (Blake2b transcript).
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_kzg_bn254_verify(
    params_ptr: *const u8,
    params_len: usize,
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        verify_impl(
            params_ptr,
            params_len,
            vk_ptr,
            vk_len,
            proof_ptr,
            proof_len,
            instances_ptr,
            instances_len,
        )
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates the v1 Halo2 KZG/BN254 params (SRS subset).
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_kzg_bn254_params_validate(
    params_ptr: *const u8,
    params_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_params_impl(params_ptr, params_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates the v1 Halo2 KZG/BN254 verifying key (protocol).
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_kzg_bn254_vk_validate(vk_ptr: *const u8, vk_len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_vk_impl(vk_ptr, vk_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

/// Validates the v1 Halo2 KZG/BN254 public instances encoding.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_kzg_bn254_instances_validate(
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| validate_instances_impl(instances_ptr, instances_len)))
        .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_blobs_without_panicking() {
        assert!(matches!(parse_params(&[]), Err(RUSTCRYPTO_ERR_INVALID_LENGTH)));
        assert!(matches!(
            parse_params(&vec![0u8; HALO2_KZG_BN254_PARAMS_V1_LEN]),
            Err(RUSTCRYPTO_ERR_INVALID_LENGTH)
        ));
        assert!(matches!(
            parse_protocol(&[]),
            Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)
        ));
        assert!(matches!(
            parse_instances(&[]),
            Err(RUSTCRYPTO_ERR_INVALID_LENGTH)
        ));
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixture_value(fixture: &str, name: &str) -> Vec<u8> {
        fixture
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .map(unhex)
            .unwrap_or_else(|| panic!("missing fixture value {name}"))
    }

    #[test]
    fn verifies_repository_fixture() {
        const FIXTURE: &str = include_str!("../../tests/fixtures/halo2_kzg_bn254_v1.hex");
        let params = fixture_value(FIXTURE, "PARAMS");
        let vk = fixture_value(FIXTURE, "VK");
        let proof = fixture_value(FIXTURE, "PROOF");
        let instances = fixture_value(FIXTURE, "INSTANCES");

        assert_eq!(
            verify_impl(
                params.as_ptr(),
                params.len(),
                vk.as_ptr(),
                vk.len(),
                proof.as_ptr(),
                proof.len(),
                instances.as_ptr(),
                instances.len(),
            ),
            RUSTCRYPTO_OK
        );

        let mut wrong = instances.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        assert_eq!(
            verify_impl(
                params.as_ptr(),
                params.len(),
                vk.as_ptr(),
                vk.len(),
                proof.as_ptr(),
                proof.len(),
                wrong.as_ptr(),
                wrong.len(),
            ),
            RUSTCRYPTO_ERR_VERIFICATION_FAILED
        );

        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            verify_impl(
                params.as_ptr(),
                params.len(),
                vk.as_ptr(),
                vk.len(),
                trailing.as_ptr(),
                trailing.len(),
                instances.as_ptr(),
                instances.len(),
            ),
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
        );
    }
}
