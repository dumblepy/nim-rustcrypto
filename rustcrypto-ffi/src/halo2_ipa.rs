//! Halo2 IPA / BN254 transparent proving and verification (C ABI).
//!
//! # Profile (v1)
//!
//! - Implementation: `halo2-axiom` 0.5.3 (the same vendored copy used by the
//!   KZG profile), BN254 G1 with scalar field `Fr`.
//! - Polynomial commitment: IPA (`ParamsIPA`, `IPACommitmentScheme`).
//! - Multi-open: BGH19 (`ProverIPA` / `VerifierIPA`).
//! - Fiat-Shamir: halo2 `Blake2bRead` / `Blake2bWrite`.
//! - **No trusted setup**: `ParamsIPA::new(k)` derives the generator set
//!   deterministically with halo2's `hash_to_curve("Halo2-Parameters")` from
//!   `k` alone. There is no SRS ceremony and no caller-supplied generators, so
//!   the params are regenerated from `k` and are not part of the wire format.
//!
//! # Circuit registry
//!
//! `VerifyingKey::read` / `ProvingKey::read` need a concrete `Circuit` type, so
//! this module owns a small registry of **approved** circuits keyed by `u32`.
//! Only [`HALO2_IPA_BN254_CIRCUIT_CUBIC_V1`] (id `1`) is implemented:
//!
//! - one advice column, one instance column, one selector;
//! - gate `x^3 + x + 5 - y == 0`, where `y` is queried from the instance
//!   column and `x` is the witness;
//! - public instance: one column with exactly one value `y`.
//!
//! Adding a circuit requires a Rust source change and review. Arbitrary circuit
//! code is never loaded from bytes.
//!
//! # Verifying-key pinning
//!
//! This module validates structure only. The caller is responsible for pinning
//! an approved verifying key (for example by hash) and for trusting the
//! circuit identified by `circuit_id`.
//!
//! # Wire formats v1
//!
//! ```text
//! VK:        "RCH2IPV1" | circuit_id u32 BE | k u32 BE | vk_len u32 BE | vk
//! PK:        "RCH2IPP1" | circuit_id u32 BE | k u32 BE | pk_len u32 BE | pk
//! proof:     "RCH2IPF1" | proof_len u32 BE | transcript bytes
//! instances: "RCH2IPI1" | column_count u32 BE |
//!            column_count * (value_count u32 BE | value_count * Fr(32 BE))
//! ```
//!
//! Trailing bytes are rejected. Field elements must be canonical big-endian
//! BN254 `Fr` values. Lengths are bounded: VK ≤ 4 MiB, PK ≤ 64 MiB, proof
//! ≤ 4 MiB, at most 8 instance columns and 4096 instance values total, and
//! `4 <= k <= 16`.
//!
//! # Security notes
//!
//! - The verifier needs no entropy, filesystem, clock, or network access; it
//!   only regenerates `ParamsIPA::new(k)` from the VK header.
//! - Proving uses `rand_core::OsRng` (the OS CSPRNG) for IPA blinding.
//! - Verifying keys and proving keys are caller-supplied and must be pinned /
//!   trusted by the application.
//! - Panics never cross the C ABI: every entry point is wrapped in
//!   `catch_unwind` and returns [`crate::RUSTCRYPTO_ERR_PANIC`] on failure.

use crate::{
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT, RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT,
    RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY, RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA,
    RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_ERR_PANIC,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
};
use core::cell::Cell;
use core::ffi::c_int;
use halo2_axiom::SerdeFormat;
use halo2_axiom::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_axiom::halo2curves::bn256::{Fr, G1Affine};
use halo2_axiom::halo2curves::ff::PrimeField;
use halo2_axiom::plonk::{
    Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Expression, ProvingKey, Selector,
    VerifyingKey, create_proof, keygen_pk, keygen_vk, verify_proof,
};
use halo2_axiom::poly::Rotation;
use halo2_axiom::poly::VerificationStrategy;
use halo2_axiom::poly::commitment::ParamsProver;
use halo2_axiom::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_axiom::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
use halo2_axiom::poly::ipa::strategy::SingleStrategy;
use halo2_axiom::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use rand_core::{OsRng, RngCore};
use std::io::{Cursor, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

pub const HALO2_IPA_BN254_VK_V1_MAGIC: &[u8; 8] = b"RCH2IPV1";
pub const HALO2_IPA_BN254_PK_V1_MAGIC: &[u8; 8] = b"RCH2IPP1";
pub const HALO2_IPA_BN254_PROOF_V1_MAGIC: &[u8; 8] = b"RCH2IPF1";
pub const HALO2_IPA_BN254_INSTANCES_V1_MAGIC: &[u8; 8] = b"RCH2IPI1";

/// Built-in approved circuit: public `y = x^3 + x + 5`, witness `x`.
pub const HALO2_IPA_BN254_CIRCUIT_CUBIC_V1: u32 = 1;

pub const HALO2_IPA_BN254_MIN_K: u32 = 4;
pub const HALO2_IPA_BN254_MAX_K: u32 = 16;
pub const HALO2_IPA_BN254_MAX_VK_LEN: usize = 4 * 1024 * 1024;
pub const HALO2_IPA_BN254_MAX_PK_LEN: usize = 64 * 1024 * 1024;
pub const HALO2_IPA_BN254_MAX_PROOF_LEN: usize = 4 * 1024 * 1024;
pub const HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS: usize = 8;
pub const HALO2_IPA_BN254_MAX_INSTANCE_VALUES: usize = 4096;

const VK_HEADER_LEN: usize = 8 + 4 + 4 + 4;
const PK_HEADER_LEN: usize = 8 + 4 + 4 + 4;
const PROOF_HEADER_LEN: usize = 8 + 4;
const INSTANCES_HEADER_LEN: usize = 8 + 4;
const MAX_INSTANCES_BLOB_LEN: usize = INSTANCES_HEADER_LEN
    + HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS * 4
    + HALO2_IPA_BN254_MAX_INSTANCE_VALUES * 32;

const FR_BYTES: usize = 32;
const MAX_FIXED_COMMITMENTS: u32 = 256;
const MAX_PK_POLY_VECTOR_LEN: usize = 64;

/// The only approved circuit. Mirrors the native prototype exactly.
#[derive(Clone, Default)]
struct CubicCircuitV1 {
    x: Value<Fr>,
}

#[derive(Clone)]
struct CubicConfigV1 {
    advice: Column<Advice>,
    selector: Selector,
}

impl Circuit<Fr> for CubicCircuitV1 {
    type Config = CubicConfigV1;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> CubicConfigV1 {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();
        meta.enable_equality(advice);
        meta.enable_equality(instance);
        meta.create_gate("x^3 + x + 5 = y", |meta| {
            let x = meta.query_advice(advice, Rotation::cur());
            let y = meta.query_instance(instance, Rotation::cur());
            let enabled = meta.query_selector(selector);
            vec![
                enabled
                    * (x.clone() * x.clone() * x.clone()
                        + x
                        + Expression::Constant(Fr::from(5u64))
                        - y),
            ]
        });
        CubicConfigV1 { advice, selector }
    }

    fn synthesize(
        &self,
        config: CubicConfigV1,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "witness",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(config.advice, 0, self.x.map(Assigned::from));
                Ok(())
            },
        )?;
        Ok(())
    }
}

fn valid_circuit_id(circuit_id: u32) -> bool {
    circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1
}

fn valid_k(k: u32) -> bool {
    (HALO2_IPA_BN254_MIN_K..=HALO2_IPA_BN254_MAX_K).contains(&k)
}

fn circuit_without_witnesses(circuit_id: u32) -> Result<CubicCircuitV1, c_int> {
    match circuit_id {
        HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 => Ok(CubicCircuitV1::default()),
        _ => Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
    }
}

// ---------------------------------------------------------------------------
// Field / byte helpers
// ---------------------------------------------------------------------------

fn fr_from_be(bytes: &[u8]) -> Result<Fr, c_int> {
    if bytes.len() != FR_BYTES {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut le = [0u8; FR_BYTES];
    for (index, byte) in bytes.iter().enumerate() {
        le[FR_BYTES - 1 - index] = *byte;
    }
    Option::<Fr>::from(Fr::from_repr(le)).ok_or(RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT)
}

/// Encodes a canonical big-endian `Fr` the same way the wire format does.
#[doc(hidden)]
pub fn encode_fr_be(value: Fr) -> [u8; FR_BYTES] {
    let le = value.to_repr();
    let mut be = [0u8; FR_BYTES];
    for index in 0..FR_BYTES {
        be[index] = le[FR_BYTES - 1 - index];
    }
    be
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32, c_int> {
    let end = offset.checked_add(4).ok_or(RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    slice
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)
}

fn push_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

// ---------------------------------------------------------------------------
// v1 encoders (also used by the fixture example)
// ---------------------------------------------------------------------------

fn encode_vk_blob(circuit_id: u32, k: u32, vk_bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    if !valid_circuit_id(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    if !valid_k(k) || vk_bytes.is_empty() || vk_bytes.len() > HALO2_IPA_BN254_MAX_VK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let vk_len = u32::try_from(vk_bytes.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let mut out = Vec::with_capacity(VK_HEADER_LEN + vk_bytes.len());
    out.extend_from_slice(HALO2_IPA_BN254_VK_V1_MAGIC);
    push_u32_be(&mut out, circuit_id);
    push_u32_be(&mut out, k);
    push_u32_be(&mut out, vk_len);
    out.extend_from_slice(vk_bytes);
    Ok(out)
}

fn encode_pk_blob(circuit_id: u32, k: u32, pk_bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    if !valid_circuit_id(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    if !valid_k(k) || pk_bytes.is_empty() || pk_bytes.len() > HALO2_IPA_BN254_MAX_PK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let pk_len = u32::try_from(pk_bytes.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let mut out = Vec::with_capacity(PK_HEADER_LEN + pk_bytes.len());
    out.extend_from_slice(HALO2_IPA_BN254_PK_V1_MAGIC);
    push_u32_be(&mut out, circuit_id);
    push_u32_be(&mut out, k);
    push_u32_be(&mut out, pk_len);
    out.extend_from_slice(pk_bytes);
    Ok(out)
}

/// Encodes a transcript byte string as a v1 proof envelope.
#[doc(hidden)]
pub fn encode_proof_v1(transcript_bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    if transcript_bytes.is_empty() || transcript_bytes.len() > HALO2_IPA_BN254_MAX_PROOF_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    let proof_len =
        u32::try_from(transcript_bytes.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT)?;
    let mut out = Vec::with_capacity(PROOF_HEADER_LEN + transcript_bytes.len());
    out.extend_from_slice(HALO2_IPA_BN254_PROOF_V1_MAGIC);
    push_u32_be(&mut out, proof_len);
    out.extend_from_slice(transcript_bytes);
    Ok(out)
}

/// Encodes public instance columns as the v1 instances wire format.
#[doc(hidden)]
pub fn encode_instances_v1(columns: &[Vec<Fr>]) -> Result<Vec<u8>, c_int> {
    if columns.is_empty() || columns.len() > HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
    }
    let total_values = columns
        .iter()
        .try_fold(0usize, |total, column| total.checked_add(column.len()))
        .ok_or(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT)?;
    if total_values > HALO2_IPA_BN254_MAX_INSTANCE_VALUES {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
    }
    let column_count =
        u32::try_from(columns.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT)?;
    let mut out =
        Vec::with_capacity(INSTANCES_HEADER_LEN + total_values * FR_BYTES + columns.len() * 4);
    out.extend_from_slice(HALO2_IPA_BN254_INSTANCES_V1_MAGIC);
    push_u32_be(&mut out, column_count);
    for column in columns {
        let value_count =
            u32::try_from(column.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT)?;
        push_u32_be(&mut out, value_count);
        for value in column {
            out.extend_from_slice(&encode_fr_be(*value));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parsers (all return Result, never unwrap attacker input)
// ---------------------------------------------------------------------------

fn read_input<'a>(
    ptr: *const u8,
    len: usize,
    max: usize,
    length_error: c_int,
) -> Result<&'a [u8], c_int> {
    if len == 0 || len > max {
        return Err(length_error);
    }
    if ptr.is_null() {
        return Err(RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA);
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Rejects a key whose embedded version/k/selector shape could make
/// `VerifyingKey::read` allocate or index out of bounds before it has consumed
/// the caller-bounded payload.
fn check_serialized_vk_prefix(payload: &[u8], header_k: u32, error: c_int) -> Result<(), c_int> {
    if payload.len() < 10 {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if payload[0] != 0x02 {
        return Err(error);
    }
    let inner_k = u32::from_le_bytes(payload[1..5].try_into().map_err(|_| error)?);
    if inner_k != header_k || !valid_k(inner_k) {
        return Err(error);
    }
    if payload[5] > 1 {
        return Err(error);
    }
    let num_fixed = u32::from_le_bytes(payload[6..10].try_into().map_err(|_| error)?);
    if num_fixed > MAX_FIXED_COMMITMENTS {
        return Err(error);
    }
    Ok(())
}

fn read_vk_payload<C>(payload: &[u8], error: c_int) -> Result<VerifyingKey<G1Affine>, c_int>
where
    C: Circuit<Fr, Params = ()>,
{
    let mut cursor = Cursor::new(payload);
    let result =
        match VerifyingKey::<G1Affine>::read::<_, C>(&mut cursor, SerdeFormat::Processed, ()) {
            Ok(vk) => vk,
            Err(_) => return Err(error),
        };
    if cursor.position() as usize != payload.len() {
        return Err(error);
    }
    Ok(result)
}

fn parse_vk(bytes: &[u8]) -> Result<(u32, VerifyingKey<G1Affine>), c_int> {
    if bytes.len() < VK_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if &bytes[..8] != HALO2_IPA_BN254_VK_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let circuit_id = read_u32_be(bytes, 8).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let k = read_u32_be(bytes, 12).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let vk_len = read_u32_be(bytes, 16).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)? as usize;
    if vk_len == 0 || vk_len > HALO2_IPA_BN254_MAX_VK_LEN || bytes.len() != VK_HEADER_LEN + vk_len {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if !valid_circuit_id(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    if !valid_k(k) {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let payload = &bytes[VK_HEADER_LEN..];
    check_serialized_vk_prefix(payload, k, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;
    let vk = match circuit_id {
        HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 => catch_unwind(AssertUnwindSafe(|| {
            read_vk_payload::<CubicCircuitV1>(payload, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)
        }))
        .unwrap_or(Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY))?,
        _ => return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA),
    };
    Ok((k, vk))
}

/// Walks the canonical `ProvingKey` serialization *without* allocating, so a
/// hostile polynomial length cannot reach `Polynomial::read`'s `Vec` reserve.
fn skip_pk_polynomial(
    bytes: &[u8],
    offset: usize,
    max_len: usize,
    error: c_int,
) -> Result<usize, c_int> {
    let len = read_u32_be(bytes, offset).map_err(|_| error)? as usize;
    if len > max_len {
        return Err(error);
    }
    let value_bytes = len.checked_mul(FR_BYTES).ok_or(error)?;
    let end = offset
        .checked_add(4)
        .and_then(|value| value.checked_add(value_bytes))
        .ok_or(error)?;
    if end > bytes.len() {
        return Err(error);
    }
    Ok(end)
}

fn skip_pk_polynomial_vector(
    bytes: &[u8],
    offset: usize,
    max_len: usize,
    max_count: usize,
    error: c_int,
) -> Result<usize, c_int> {
    let count = read_u32_be(bytes, offset).map_err(|_| error)? as usize;
    if count > max_count {
        return Err(error);
    }
    let mut offset = offset + 4;
    for _ in 0..count {
        offset = skip_pk_polynomial(bytes, offset, max_len, error)?;
    }
    Ok(offset)
}

fn validate_pk_layout(bytes: &[u8], vk_end: usize, k: u32) -> Result<(), c_int> {
    let max_poly_len = 1usize << k; // k <= 16, checked before this call
    let mut offset = vk_end;
    for _ in 0..3 {
        offset = skip_pk_polynomial(
            bytes,
            offset,
            max_poly_len,
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
        )?;
    }
    for _ in 0..2 {
        offset = skip_pk_polynomial_vector(
            bytes,
            offset,
            max_poly_len,
            MAX_PK_POLY_VECTOR_LEN,
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
        )?;
    }
    for _ in 0..2 {
        offset = skip_pk_polynomial_vector(
            bytes,
            offset,
            max_poly_len,
            MAX_PK_POLY_VECTOR_LEN,
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
        )?;
    }
    if offset != bytes.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    Ok(())
}

fn parse_pk(bytes: &[u8]) -> Result<(u32, ProvingKey<G1Affine>), c_int> {
    if bytes.len() < PK_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if &bytes[..8] != HALO2_IPA_BN254_PK_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    let circuit_id = read_u32_be(bytes, 8).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let k = read_u32_be(bytes, 12).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let pk_len = read_u32_be(bytes, 16).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)? as usize;
    if pk_len == 0 || pk_len > HALO2_IPA_BN254_MAX_PK_LEN || bytes.len() != PK_HEADER_LEN + pk_len {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if !valid_circuit_id(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    if !valid_k(k) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    let payload = &bytes[PK_HEADER_LEN..];

    // The PK starts with the serialized VK. Use a counting cursor to learn its
    // exact extent, then walk the remaining polynomial layout without
    // allocating.
    const VK_READ_ERROR: c_int = RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA;
    check_serialized_vk_prefix(payload, k, VK_READ_ERROR)?;
    let mut cursor = Cursor::new(payload);
    let vk_end = match catch_unwind(AssertUnwindSafe(|| {
        VerifyingKey::<G1Affine>::read::<_, CubicCircuitV1>(&mut cursor, SerdeFormat::Processed, ())
    })) {
        Ok(Ok(_)) => cursor.position() as usize,
        _ => return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA),
    };
    if vk_end == 0 || vk_end > payload.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    validate_pk_layout(payload, vk_end, k)?;

    let mut cursor = Cursor::new(payload);
    let pk = match catch_unwind(AssertUnwindSafe(|| {
        ProvingKey::<G1Affine>::read::<_, CubicCircuitV1>(&mut cursor, SerdeFormat::Processed, ())
    })) {
        Ok(Ok(pk)) => pk,
        _ => return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA),
    };
    if cursor.position() as usize != payload.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    Ok((k, pk))
}

fn parse_proof(bytes: &[u8]) -> Result<&[u8], c_int> {
    if bytes.len() < PROOF_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    if &bytes[..8] != HALO2_IPA_BN254_PROOF_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    let proof_len =
        read_u32_be(bytes, 8).map_err(|_| RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT)? as usize;
    if proof_len == 0
        || proof_len > HALO2_IPA_BN254_MAX_PROOF_LEN
        || bytes.len() != PROOF_HEADER_LEN + proof_len
    {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    Ok(&bytes[PROOF_HEADER_LEN..])
}

fn parse_instances(bytes: &[u8]) -> Result<Vec<Vec<Fr>>, c_int> {
    if bytes.len() < INSTANCES_HEADER_LEN || bytes.len() > MAX_INSTANCES_BLOB_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if &bytes[..8] != HALO2_IPA_BN254_INSTANCES_V1_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let column_count = read_u32_be(bytes, 8).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)? as usize;
    if column_count == 0 || column_count > HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
    }

    let mut offset = INSTANCES_HEADER_LEN;
    let mut total_values = 0usize;
    let mut columns = Vec::with_capacity(column_count);
    for _ in 0..column_count {
        if offset + 4 > bytes.len() {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let value_count =
            read_u32_be(bytes, offset).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)? as usize;
        offset += 4;
        total_values = match total_values.checked_add(value_count) {
            Some(total) if total <= HALO2_IPA_BN254_MAX_INSTANCE_VALUES => total,
            _ => return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT),
        };
        let value_bytes = match value_count.checked_mul(FR_BYTES) {
            Some(len) => len,
            None => return Err(RUSTCRYPTO_ERR_INVALID_LENGTH),
        };
        let end = offset
            .checked_add(value_bytes)
            .ok_or(RUSTCRYPTO_ERR_INVALID_LENGTH)?;
        if end > bytes.len() {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let mut column = Vec::with_capacity(value_count);
        for chunk in bytes[offset..end].chunks_exact(FR_BYTES) {
            column.push(fr_from_be(chunk)?);
        }
        offset = end;
        columns.push(column);
    }
    if offset != bytes.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    Ok(columns)
}

/// The registered cubic circuit takes exactly one public instance column with
/// exactly one value.
fn parse_single_instance(bytes: &[u8]) -> Result<Fr, c_int> {
    let mut columns = parse_instances(bytes)?;
    if columns.len() != 1 || columns[0].len() != 1 {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
    }
    columns
        .pop()
        .and_then(|mut column| column.pop())
        .ok_or(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT)
}

// ---------------------------------------------------------------------------
// Key generation / proving helpers
// ---------------------------------------------------------------------------

fn key_material(circuit_id: u32, k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    if !valid_circuit_id(circuit_id) || !valid_k(k) {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    let params = ParamsIPA::<G1Affine>::new(k);
    let circuit = circuit_without_witnesses(circuit_id)?;
    let vk = keygen_vk(&params, &circuit).map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;
    let pk = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;

    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::Processed)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::Processed)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;

    Ok((
        encode_vk_blob(circuit_id, k, &vk_bytes)?,
        encode_pk_blob(circuit_id, k, &pk_bytes)?,
    ))
}

/// Generates v1 VK/PK blobs for an approved circuit. Fixture/test support.
#[doc(hidden)]
pub fn generate_key_material_v1(circuit_id: u32, k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    key_material(circuit_id, k)
}

fn expected_instance(x: Fr) -> Fr {
    x * x * x + x + Fr::from(5u64)
}

fn prove_with_rng_impl<R: RngCore>(
    pk_blob: &[u8],
    witness: Fr,
    instance: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let (k, pk) = parse_pk(pk_blob)?;
    if expected_instance(witness) != instance {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }

    let params = ParamsIPA::<G1Affine>::new(k);
    let circuit = CubicCircuitV1 {
        x: Value::known(witness),
    };

    let instance_values = [instance];
    let instance_columns: [&[Fr]; 1] = [&instance_values];
    let instances: [&[&[Fr]]; 1] = [&instance_columns];

    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<IPACommitmentScheme<G1Affine>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &instances,
        rng,
        &mut transcript,
    )
    .map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;
    let transcript_bytes = transcript.finalize();
    encode_proof_v1(&transcript_bytes)
}

/// Proves the registered cubic circuit with a caller-supplied RNG. Used by the
/// deterministic fixture generator; the C ABI uses `OsRng`.
#[doc(hidden)]
pub fn prove_with_rng_v1<R: RngCore>(
    pk_blob: &[u8],
    witness: Fr,
    instance: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    prove_with_rng_impl(pk_blob, witness, instance, rng)
}

// ---------------------------------------------------------------------------
// C ABI implementation
// ---------------------------------------------------------------------------

fn write_output(out: *mut u8, cap: usize, data: &[u8], out_len: *mut usize) -> c_int {
    if out_len.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    let required = data.len();
    unsafe {
        *out_len = required;
    }
    if out.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if cap < required {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), out, required);
    }
    RUSTCRYPTO_OK
}

fn prepare_impl(
    circuit_id: u32,
    k: u32,
    vk_out: *mut u8,
    vk_cap: usize,
    vk_len: *mut usize,
    pk_out: *mut u8,
    pk_cap: usize,
    pk_len: *mut usize,
) -> c_int {
    if !valid_circuit_id(circuit_id) || !valid_k(k) {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    if vk_len.is_null() || pk_len.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    let (vk_bytes, pk_bytes) = match key_material(circuit_id, k) {
        Ok(material) => material,
        Err(error) => return error,
    };
    unsafe {
        *vk_len = vk_bytes.len();
        *pk_len = pk_bytes.len();
    }
    if vk_out.is_null() || pk_out.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if vk_cap < vk_bytes.len() || pk_cap < pk_bytes.len() {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(vk_bytes.as_ptr(), vk_out, vk_bytes.len());
        core::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), pk_out, pk_bytes.len());
    }
    RUSTCRYPTO_OK
}

fn prove_impl(
    pk_ptr: *const u8,
    pk_len: usize,
    witness_ptr: *const u8,
    witness_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
    proof_out: *mut u8,
    proof_cap: usize,
    proof_len: *mut usize,
) -> c_int {
    if proof_len.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    let pk_bytes = match read_input(
        pk_ptr,
        pk_len,
        HALO2_IPA_BN254_MAX_PK_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let witness_bytes = match read_input(
        witness_ptr,
        witness_len,
        FR_BYTES,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    if witness_bytes.len() != FR_BYTES {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    let witness = match fr_from_be(witness_bytes) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let instances_bytes = match read_input(
        instances_ptr,
        instances_len,
        MAX_INSTANCES_BLOB_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let instance = match parse_single_instance(instances_bytes) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if expected_instance(witness) != instance {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }

    let proof = match prove_with_rng_impl(pk_bytes, witness, instance, OsRng) {
        Ok(proof) => proof,
        Err(error) => return error,
    };
    write_output(proof_out, proof_cap, &proof, proof_len)
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

fn verify_impl(
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    let vk_bytes = match read_input(
        vk_ptr,
        vk_len,
        HALO2_IPA_BN254_MAX_VK_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let proof_bytes = match read_input(
        proof_ptr,
        proof_len,
        HALO2_IPA_BN254_MAX_PROOF_LEN,
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let instances_bytes = match read_input(
        instances_ptr,
        instances_len,
        MAX_INSTANCES_BLOB_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    let (k, vk) = match parse_vk(vk_bytes) {
        Ok(vk) => vk,
        Err(error) => return error,
    };
    let instance = match parse_single_instance(instances_bytes) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let transcript_bytes = match parse_proof(proof_bytes) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    let params = ParamsIPA::<G1Affine>::new(k);
    let verifier_params = params.verifier_params();

    let position = Rc::new(Cell::new(0usize));
    let reader = CountingReader {
        data: transcript_bytes,
        position: position.clone(),
    };
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(reader);

    let instance_values = [instance];
    let instance_columns: [&[Fr]; 1] = [&instance_values];
    let instances: [&[&[Fr]]; 1] = [&instance_columns];

    match verify_proof::<IPACommitmentScheme<G1Affine>, VerifierIPA<_>, _, _, SingleStrategy<_>>(
        verifier_params,
        &vk,
        SingleStrategy::new(verifier_params),
        &instances,
        &mut transcript,
    ) {
        Ok(()) => {}
        Err(_) => return RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    };

    if position.get() != transcript_bytes.len() {
        return RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT;
    }
    RUSTCRYPTO_OK
}

fn validate_vk_impl(vk_ptr: *const u8, vk_len: usize) -> c_int {
    let bytes = match read_input(
        vk_ptr,
        vk_len,
        HALO2_IPA_BN254_MAX_VK_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    match parse_vk(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

fn validate_pk_impl(pk_ptr: *const u8, pk_len: usize) -> c_int {
    let bytes = match read_input(
        pk_ptr,
        pk_len,
        HALO2_IPA_BN254_MAX_PK_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    match parse_pk(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

fn validate_proof_impl(proof_ptr: *const u8, proof_len: usize) -> c_int {
    let bytes = match read_input(
        proof_ptr,
        proof_len,
        HALO2_IPA_BN254_MAX_PROOF_LEN,
        RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    match parse_proof(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

fn validate_instances_impl(instances_ptr: *const u8, instances_len: usize) -> c_int {
    let bytes = match read_input(
        instances_ptr,
        instances_len,
        MAX_INSTANCES_BLOB_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    match parse_instances(bytes) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

fn guard(f: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

/// Prepares the deterministic IPA params for `k`, keygens the approved circuit,
/// and writes the v1 VK and PK encodings. Neither step uses randomness.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_ipa_bn254_prepare(
    circuit_id: u32,
    k: u32,
    vk_out: *mut u8,
    vk_cap: usize,
    vk_len: *mut usize,
    pk_out: *mut u8,
    pk_cap: usize,
    pk_len: *mut usize,
) -> c_int {
    guard(|| {
        prepare_impl(
            circuit_id, k, vk_out, vk_cap, vk_len, pk_out, pk_cap, pk_len,
        )
    })
}

/// Proves the approved circuit in `pk` and writes the v1 proof encoding.
/// Uses the operating system CSPRNG for blinding.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_ipa_bn254_prove(
    pk_ptr: *const u8,
    pk_len: usize,
    witness_ptr: *const u8,
    witness_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
    proof_out: *mut u8,
    proof_cap: usize,
    proof_len: *mut usize,
) -> c_int {
    guard(|| {
        prove_impl(
            pk_ptr,
            pk_len,
            witness_ptr,
            witness_len,
            instances_ptr,
            instances_len,
            proof_out,
            proof_cap,
            proof_len,
        )
    })
}

/// Verifies a v1 proof against a v1 VK and the expected public instances.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_ipa_bn254_verify(
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    guard(|| {
        verify_impl(
            vk_ptr,
            vk_len,
            proof_ptr,
            proof_len,
            instances_ptr,
            instances_len,
        )
    })
}

/// Structurally validates a v1 verifying key, including the embedded
/// `halo2_axiom` key for the registered circuit.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_ipa_bn254_vk_validate(
    vk_ptr: *const u8,
    vk_len: usize,
) -> c_int {
    guard(|| validate_vk_impl(vk_ptr, vk_len))
}

/// Structurally validates a v1 proving key, including the embedded
/// `halo2_axiom` key for the registered circuit.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_ipa_bn254_pk_validate(
    pk_ptr: *const u8,
    pk_len: usize,
) -> c_int {
    guard(|| validate_pk_impl(pk_ptr, pk_len))
}

/// Validates the v1 proof envelope.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_ipa_bn254_proof_validate(
    proof_ptr: *const u8,
    proof_len: usize,
) -> c_int {
    guard(|| validate_proof_impl(proof_ptr, proof_len))
}

/// Validates the v1 instances encoding (magic, counts, canonical `Fr`, trailing
/// bytes).
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_halo2_ipa_bn254_instances_validate(
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    guard(|| validate_instances_impl(instances_ptr, instances_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/halo2_ipa_bn254_v1.hex");

    fn unhex(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0, "odd-length hex");
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    fn fixture_value(fixture: &str, name: &str) -> Vec<u8> {
        fixture
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .map(unhex)
            .unwrap_or_else(|| panic!("missing fixture value {name}"))
    }

    fn fixture_parts() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            fixture_value(FIXTURE, "VK"),
            fixture_value(FIXTURE, "PROOF"),
            fixture_value(FIXTURE, "INSTANCES"),
            fixture_value(FIXTURE, "WITNESS"),
        )
    }

    fn verify(vk: &[u8], proof: &[u8], instances: &[u8]) -> c_int {
        rustcrypto_halo2_ipa_bn254_verify(
            vk.as_ptr(),
            vk.len(),
            proof.as_ptr(),
            proof.len(),
            instances.as_ptr(),
            instances.len(),
        )
    }

    fn validate_vk(vk: &[u8]) -> c_int {
        rustcrypto_halo2_ipa_bn254_vk_validate(vk.as_ptr(), vk.len())
    }

    fn validate_pk(pk: &[u8]) -> c_int {
        rustcrypto_halo2_ipa_bn254_pk_validate(pk.as_ptr(), pk.len())
    }

    fn validate_proof(proof: &[u8]) -> c_int {
        rustcrypto_halo2_ipa_bn254_proof_validate(proof.as_ptr(), proof.len())
    }

    fn validate_instances(instances: &[u8]) -> c_int {
        rustcrypto_halo2_ipa_bn254_instances_validate(instances.as_ptr(), instances.len())
    }

    #[test]
    fn committed_fixture_verifies_through_c_abi() {
        let (vk, proof, instances, witness) = fixture_parts();
        assert_eq!(witness.len(), FR_BYTES);
        assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
        assert_eq!(validate_proof(&proof), RUSTCRYPTO_OK);
        assert_eq!(validate_instances(&instances), RUSTCRYPTO_OK);
        assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);
        // Repeated calls must be side-effect free.
        assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);
    }

    #[test]
    fn prepare_prove_verify_roundtrip() {
        let circuit_id = HALO2_IPA_BN254_CIRCUIT_CUBIC_V1;
        let k = 8u32;

        let mut vk_len = 0usize;
        let mut pk_len = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prepare(
                circuit_id,
                k,
                core::ptr::null_mut(),
                0,
                &mut vk_len,
                core::ptr::null_mut(),
                0,
                &mut pk_len,
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT
        );
        assert!(vk_len > 0 && pk_len > 0);

        let mut vk = vec![0u8; vk_len];
        let mut pk = vec![0u8; pk_len];
        let mut vk_len2 = 0usize;
        let mut pk_len2 = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prepare(
                circuit_id,
                k,
                vk.as_mut_ptr(),
                vk.len(),
                &mut vk_len2,
                pk.as_mut_ptr(),
                pk.len(),
                &mut pk_len2,
            ),
            RUSTCRYPTO_OK
        );
        vk.truncate(vk_len2);
        pk.truncate(pk_len2);
        assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
        assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);

        // A too-small output buffer is reported without partial writes.
        let mut short_vk = [0u8; 1];
        let mut short_vk_len = 0usize;
        let mut ignored_pk_len = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prepare(
                circuit_id,
                k,
                short_vk.as_mut_ptr(),
                short_vk.len(),
                &mut short_vk_len,
                pk.as_mut_ptr(),
                pk.len(),
                &mut ignored_pk_len,
            ),
            RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT
        );
        assert_eq!(short_vk_len, vk.len());
        assert_eq!(short_vk, [0u8]);

        let x = Fr::from(3u64);
        let y = Fr::from(35u64);
        let witness = encode_fr_be(x);
        let instances = encode_instances_v1(&[vec![y]]).expect("instances");

        let mut proof = vec![0u8; 4096];
        let mut proof_len = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                witness.as_ptr(),
                witness.len(),
                instances.as_ptr(),
                instances.len(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut proof_len,
            ),
            RUSTCRYPTO_OK
        );
        proof.truncate(proof_len);
        assert_eq!(validate_proof(&proof), RUSTCRYPTO_OK);
        assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);

        // Short output buffer reports the required length.
        let mut required = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                witness.as_ptr(),
                witness.len(),
                instances.as_ptr(),
                instances.len(),
                core::ptr::null_mut(),
                0,
                &mut required,
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT
        );
        assert_eq!(required, proof.len());
    }

    #[test]
    fn wrong_instance_is_rejected() {
        let (vk, proof, _, _) = fixture_parts();
        let wrong = encode_instances_v1(&[vec![Fr::from(36u64)]]).expect("instances");
        assert_eq!(
            verify(&vk, &proof, &wrong),
            RUSTCRYPTO_ERR_VERIFICATION_FAILED
        );
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (vk, mut proof, instances, _) = fixture_parts();
        let last = proof.len() - 1;
        proof[last] ^= 0x01;
        let status = verify(&vk, &proof, &instances);
        assert_ne!(status, RUSTCRYPTO_OK, "tampered proof accepted");
        assert_ne!(status, RUSTCRYPTO_ERR_PANIC, "tampered proof panicked");
    }

    #[test]
    fn truncated_and_trailing_blobs_are_rejected() {
        let (vk, proof, instances, _) = fixture_parts();
        let (_, pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");

        let mut vk_short = vk.clone();
        vk_short.pop();
        assert_eq!(validate_vk(&vk_short), RUSTCRYPTO_ERR_INVALID_LENGTH);

        let mut vk_trailing = vk.clone();
        vk_trailing.push(0);
        assert_eq!(validate_vk(&vk_trailing), RUSTCRYPTO_ERR_INVALID_LENGTH);

        let mut proof_short = proof.clone();
        proof_short.pop();
        assert_eq!(
            validate_proof(&proof_short),
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
        );

        let mut proof_trailing = proof.clone();
        proof_trailing.push(0);
        assert_eq!(
            validate_proof(&proof_trailing),
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
        );

        let mut instances_short = instances.clone();
        instances_short.pop();
        assert_eq!(
            validate_instances(&instances_short),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );

        let mut instances_trailing = instances.clone();
        instances_trailing.push(0);
        assert_eq!(
            validate_instances(&instances_trailing),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );

        let mut pk_short = pk.clone();
        pk_short.pop();
        assert_eq!(validate_pk(&pk_short), RUSTCRYPTO_ERR_INVALID_LENGTH);

        let mut pk_trailing = pk.clone();
        pk_trailing.push(0);
        assert_eq!(validate_pk(&pk_trailing), RUSTCRYPTO_ERR_INVALID_LENGTH);
    }

    #[test]
    fn hostile_pk_polynomial_length_is_rejected_without_allocation() {
        let (_, mut pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
        // Inner VK payload length: outer header + VK payload.
        let vk_payload_len = {
            let (vk, _) =
                generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
            u32::from_be_bytes(vk[16..20].try_into().unwrap()) as usize
        };
        let l0_len_offset = PK_HEADER_LEN + vk_payload_len;
        // Claim a 1 Mi-domain polynomial (32 MiB) inside a ~74 KiB PK.
        pk[l0_len_offset..l0_len_offset + 4].copy_from_slice(&(1u32 << 20).to_be_bytes());
        assert_eq!(validate_pk(&pk), RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }

    #[test]
    fn noncanonical_field_and_shape_errors_are_rejected() {
        let (_, _, instances, _) = fixture_parts();

        let mut noncanonical = instances.clone();
        let value_start = noncanonical.len() - FR_BYTES;
        noncanonical[value_start..].fill(0xff);
        assert_eq!(
            validate_instances(&noncanonical),
            RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );

        assert_eq!(validate_instances(&[]), RUSTCRYPTO_ERR_INVALID_LENGTH);

        let mut wrong_magic = instances.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            validate_instances(&wrong_magic),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );

        let two_columns = encode_instances_v1(&[vec![Fr::from(35u64)], vec![Fr::from(35u64)]])
            .expect("instances");
        let (vk, proof, _, _) = fixture_parts();
        assert_eq!(
            verify(&vk, &proof, &two_columns),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
        );

        let two_values =
            encode_instances_v1(&[vec![Fr::from(35u64), Fr::from(36u64)]]).expect("instances");
        assert_eq!(
            verify(&vk, &proof, &two_values),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
        );
    }

    #[test]
    fn bad_magic_circuit_id_and_k_are_rejected() {
        let (vk, proof, instances, _) = fixture_parts();
        let (_, pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");

        let mut kzg_vk = vk.clone();
        kzg_vk[..8].copy_from_slice(b"RCH2V1\0\0");
        assert_eq!(validate_vk(&kzg_vk), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
        assert_eq!(
            verify(&kzg_vk, &proof, &instances),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
        );

        let mut kzg_params_as_pk = pk.clone();
        kzg_params_as_pk[..8].copy_from_slice(b"RCH2P1\0\0");
        assert_eq!(
            validate_pk(&kzg_params_as_pk),
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
        );

        let mut kzg_proof = proof.clone();
        kzg_proof[..8].copy_from_slice(b"RCH2P1\0\0");
        assert_eq!(
            validate_proof(&kzg_proof),
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT
        );

        let mut unknown_circuit = vk.clone();
        unknown_circuit[8..12].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            validate_vk(&unknown_circuit),
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
        );

        let mut unknown_circuit_pk = pk.clone();
        unknown_circuit_pk[8..12].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            validate_pk(&unknown_circuit_pk),
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
        );

        for &bad_k in &[3u32, 17u32] {
            let mut bad = vk.clone();
            bad[12..16].copy_from_slice(&bad_k.to_be_bytes());
            assert_eq!(validate_vk(&bad), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);

            let mut bad_pk = pk.clone();
            bad_pk[12..16].copy_from_slice(&bad_k.to_be_bytes());
            assert_eq!(validate_pk(&bad_pk), RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
        }

        // Header k must match the k baked into the serialized VK.
        let mut mismatched_inner_k = vk.clone();
        mismatched_inner_k[VK_HEADER_LEN + 1..VK_HEADER_LEN + 5]
            .copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(
            validate_vk(&mismatched_inner_k),
            RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
        );
    }

    #[test]
    fn prepare_parameter_and_pointer_errors() {
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prepare(
                2,
                8,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut()
            ),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prepare(
                1,
                3,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut()
            ),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prepare(
                1,
                17,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut()
            ),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prepare(
                1,
                8,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut()
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT
        );
    }

    #[test]
    fn null_and_short_buffers_are_rejected() {
        let (vk, proof, instances, witness) = fixture_parts();
        let (_, pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
        let mut out_len = 0usize;

        assert_eq!(validate_vk(&[]), RUSTCRYPTO_ERR_INVALID_LENGTH);
        assert_eq!(validate_pk(&[]), RUSTCRYPTO_ERR_INVALID_LENGTH);
        assert_eq!(validate_proof(&[]), RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
        assert_eq!(validate_instances(&[]), RUSTCRYPTO_ERR_INVALID_LENGTH);
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_vk_validate(core::ptr::null(), 10),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_pk_validate(core::ptr::null(), 10),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_proof_validate(core::ptr::null(), 10),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_instances_validate(core::ptr::null(), 10),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );

        assert_eq!(
            rustcrypto_halo2_ipa_bn254_verify(
                core::ptr::null(),
                10,
                proof.as_ptr(),
                proof.len(),
                instances.as_ptr(),
                instances.len(),
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_verify(
                vk.as_ptr(),
                vk.len(),
                core::ptr::null(),
                10,
                instances.as_ptr(),
                instances.len(),
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_verify(
                vk.as_ptr(),
                vk.len(),
                proof.as_ptr(),
                proof.len(),
                core::ptr::null(),
                10,
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );

        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                core::ptr::null(),
                10,
                witness.as_ptr(),
                witness.len(),
                instances.as_ptr(),
                instances.len(),
                core::ptr::null_mut(),
                0,
                &mut out_len,
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                core::ptr::null(),
                10,
                instances.as_ptr(),
                instances.len(),
                core::ptr::null_mut(),
                0,
                &mut out_len,
            ),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                witness.as_ptr(),
                witness.len(),
                instances.as_ptr(),
                instances.len(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT
        );

        // Too-short output buffer: reports required size.
        let mut required = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                witness.as_ptr(),
                witness.len(),
                instances.as_ptr(),
                instances.len(),
                core::ptr::null_mut(),
                0,
                &mut required,
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT
        );
        assert!(required > 0);
    }

    #[test]
    fn wrong_witness_instance_pair_is_rejected_before_proving() {
        let (_, pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
        let witness = encode_fr_be(Fr::from(3u64));
        let wrong = encode_instances_v1(&[vec![Fr::from(36u64)]]).expect("instances");
        let mut out = [0u8; 4096];
        let mut out_len = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                witness.as_ptr(),
                witness.len(),
                wrong.as_ptr(),
                wrong.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
        assert_eq!(out_len, 0);
    }
}
