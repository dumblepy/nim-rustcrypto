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
//!
//! - [`HALO2_IPA_BN254_CIRCUIT_CUBIC_V1`] (id `1`), `4 <= k <= 16`:
//!   one advice column, one instance column, one selector; gate
//!   `x^3 + x + 5 - y == 0`; witness is one canonical 32-byte BE `Fr` `x`;
//!   public instance is one column with exactly one value `y`.
//! - [`HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1`] (id `2`), `7 <= k <= 16`:
//!   the [`Poseidon2HashCircuit`] fixed 3-input Noir/Barretenberg sponge;
//!   witness is exactly three canonical 32-byte BE `Fr` inputs (96 bytes);
//!   public instance is one column `[digest, input0, input1, input2]`.
//!   Keys use the **V2** artifact revision (see below).
//! - [`HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE`] `+ n` for `n` in
//!   `0..=12`: the same [`Poseidon2HashCircuit`], fixed to `n` inputs. Witness
//!   is `n` canonical 32-byte BE `Fr` inputs (`32 * n` bytes; zero bytes for
//!   `n = 0`); public instance is one column with `n + 1` values
//!   `[digest, input0, .., input_{n-1}]`. Circuit id `2` remains the legacy
//!   three-input encoding. The minimum `k` satisfies
//!   `2^k - 6 >= hash_circuit_rows(n)`, i.e. `7` for `n` in `0..=3`, `8` for
//!   `4..=9`, and `9` for `10..=12`. Keys use the **V2** artifact revision.
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
//! # Wire formats and artifact revisions
//!
//! ```text
//! VK:        "RCH2IPV1" | circuit_id u32 BE | k u32 BE | vk_len u32 BE | vk
//! PK:        "RCH2IPP1" | circuit_id u32 BE | k u32 BE | pk_len u32 BE | pk
//! proof:     "RCH2IPF1" | proof_len u32 BE | transcript bytes
//! instances: "RCH2IPI1" | column_count u32 BE |
//!            column_count * (value_count u32 BE | value_count * Fr(32 BE))
//! ```
//!
//! The envelope **layout** above is shared by both artifact revisions; only
//! the 8-byte key magic differs.
//!
//! - **V1** (`"RCH2IPV1"` / `"RCH2IPP1"`): circuit id `1` (cubic v1) only. Its
//!   semantics are unchanged.
//! - **V2** (`"RCH2IPV2"` / `"RCH2IPP2"`): the Poseidon2 hash circuit family
//!   (ids `2` and `BASE + n`). The other agent's soundness fix to the sponge's
//!   unused absorb lanes changes every VK/PK, so old V1-magic Poseidon2
//!   artifacts are **not** accepted as the new circuit. The proof transcript
//!   format is unchanged, so proofs/instances stay `RCH2IPF1` / `RCH2IPI1`.
//!
//! The revision is bound to the circuit id: a V2 magic on the cubic circuit or
//! a V1 magic on a Poseidon2 circuit is rejected (`INVALID_VERIFYING_KEY` for
//! VKs, `INVALID_CIRCUIT_DATA` for PKs). External circuits registered through
//! [`crate::halo2_ipa_registry`] always use the V2 envelope.
//!
//! Trailing bytes are rejected. Field elements must be canonical big-endian
//! BN254 `Fr` values. Lengths are bounded: VK ≤ 4 MiB, PK ≤ 64 MiB, proof
//! ≤ 4 MiB, at most 8 instance columns and 4096 instance values total, and
//! `4 <= k <= 16`. The legacy Poseidon2 circuit id `2` requires `k >= 7` (the
//! 65-row permutation layout's minimum). The arbitrary-arity family
//! `BASE + n` requires the smallest `k` with
//! `2^k - 6 >= hash_circuit_rows(n)` (`7` for `n = 0..=3`, `8` for `4..=9`,
//! `9` for `10..=12`).
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
//! - With the optional `halo2-ipa-params-cache` feature, `ParamsIPA` is cached
//!   in one thread-local slot per `k`. This is heap memory owned by the current
//!   canister instance, is lost on upgrade, and is **not** a trusted-SRS cache:
//!   the params remain deterministically derived from `k` alone.
//! - `prepare` and `prove` keep a **one-shot** thread-local staging entry so the
//!   sizing call and the immediately following body call share one keygen or
//!   one proof instead of running it twice. The entry is discarded after a
//!   successful write (or when the statement changes). It is ordinary heap
//!   memory, not a persistent proof cache, and **not** a trusted SRS.

#[cfg(not(feature = "halo2-ipa-verify-only"))]
use crate::poseidon2_halo2::hash_output as poseidon2_hash_output;
use crate::poseidon2_halo2::{Poseidon2HashCircuit, hash_circuit_rows};
use crate::{
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA, RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT,
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_PANIC, RUSTCRYPTO_ERR_VERIFICATION_FAILED,
    RUSTCRYPTO_OK,
};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use crate::{
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT,
};
use core::cell::Cell;
#[cfg(any(
    feature = "halo2-ipa-params-cache",
    not(feature = "halo2-ipa-verify-only")
))]
use core::cell::RefCell;
use core::ffi::c_int;
use halo2_axiom::SerdeFormat;
use halo2_axiom::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_axiom::halo2curves::bn256::{Fr, G1Affine};
use halo2_axiom::halo2curves::ff::PrimeField;
use halo2_axiom::plonk::{
    Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Expression, Selector, VerifyingKey,
    verify_proof,
};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use halo2_axiom::plonk::{ProvingKey, create_proof, keygen_pk, keygen_vk};
use halo2_axiom::poly::Rotation;
use halo2_axiom::poly::VerificationStrategy;
use halo2_axiom::poly::commitment::ParamsProver;
use halo2_axiom::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use halo2_axiom::poly::ipa::multiopen::ProverIPA;
use halo2_axiom::poly::ipa::multiopen::VerifierIPA;
use halo2_axiom::poly::ipa::strategy::SingleStrategy;
use halo2_axiom::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use halo2_axiom::transcript::{Blake2bWrite, TranscriptWriterBuffer};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use rand_core::{OsRng, RngCore};
use std::io::{Cursor, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

pub const HALO2_IPA_BN254_VK_V1_MAGIC: &[u8; 8] = b"RCH2IPV1";
pub const HALO2_IPA_BN254_PK_V1_MAGIC: &[u8; 8] = b"RCH2IPP1";
/// V2 verifying-key magic: sound Poseidon2 hash revision and external circuits.
///
/// The header layout is identical to V1; only the magic and the meaning of the
/// payload (a different, sound circuit) differ.
pub const HALO2_IPA_BN254_VK_V2_MAGIC: &[u8; 8] = b"RCH2IPV2";
/// V2 proving-key magic: sound Poseidon2 hash revision and external circuits.
pub const HALO2_IPA_BN254_PK_V2_MAGIC: &[u8; 8] = b"RCH2IPP2";
/// Proof transcripts are revision-independent: the transcript format did not
/// change between V1 and V2.
pub const HALO2_IPA_BN254_PROOF_V1_MAGIC: &[u8; 8] = b"RCH2IPF1";
/// Public-instance blobs are revision-independent.
pub const HALO2_IPA_BN254_INSTANCES_V1_MAGIC: &[u8; 8] = b"RCH2IPI1";

/// Built-in approved circuit: public `y = x^3 + x + 5`, witness `x`.
pub const HALO2_IPA_BN254_CIRCUIT_CUBIC_V1: u32 = 1;

/// Built-in approved circuit: 3-input Poseidon2 hash.
///
/// Witness: three canonical 32-byte BE `Fr` inputs (96 bytes). Public
/// instance: one column `[digest, input0, input1, input2]`.
pub const HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1: u32 = 2;

/// Number of Poseidon2 hash inputs fixed by circuit id `2`.
pub const HALO2_IPA_BN254_POSEIDON2_HASH3_INPUTS: usize = 3;

/// Base of the arbitrary-arity Poseidon2 hash circuit id family.
///
/// `HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE + n` (`n` in `0..=12`) is
/// the fixed `n`-input Poseidon2 hash circuit. Circuit id `2` remains the
/// legacy three-input encoding and is **not** part of this range (`0x100`).
pub const HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE: u32 = 0x100;

/// Maximum arity of the arbitrary-arity Poseidon2 hash circuit family.
pub const HALO2_IPA_BN254_POSEIDON2_MAX_ARITY: usize = 12;

/// Rows reserved by halo2 for blinding (`blinding_factors + 1`).
const POSEIDON2_RESERVED_ROWS: usize = 6;

/// Returns the Poseidon2 input count encoded by `circuit_id`.
///
/// - circuit id `2` -> `3` (legacy fixed three-input circuit),
/// - `BASE + n` for `n` in `0..=12` -> `n`,
/// - anything else -> `None`.
pub fn poseidon2_arity(circuit_id: u32) -> Option<usize> {
    if circuit_id == HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1 {
        return Some(HALO2_IPA_BN254_POSEIDON2_HASH3_INPUTS);
    }
    let offset = circuit_id.checked_sub(HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE)?;
    let arity = usize::try_from(offset).ok()?;
    (arity <= HALO2_IPA_BN254_POSEIDON2_MAX_ARITY).then_some(arity)
}

/// Minimum `k` for the fixed `arity`-input Poseidon2 hash circuit.
///
/// Halo2 reserves `blinding_factors + 1` rows, so the smallest valid `k`
/// satisfies `2^k - 6 >= hash_circuit_rows(arity)`. Computed from the sponge
/// layout rather than hardcoded. Returns `None` above the maximum arity.
pub fn poseidon2_arity_min_k(arity: usize) -> Option<u32> {
    if arity > HALO2_IPA_BN254_POSEIDON2_MAX_ARITY {
        return None;
    }
    let rows = hash_circuit_rows(arity);
    (HALO2_IPA_BN254_MIN_K..=HALO2_IPA_BN254_MAX_K)
        .find(|k| (1usize << *k) - POSEIDON2_RESERVED_ROWS >= rows)
}

pub const HALO2_IPA_BN254_MIN_K: u32 = 4;
/// The Poseidon2 circuit uses 65 rows per permutation, so `k >= 7`.
pub const HALO2_IPA_BN254_POSEIDON2_HASH3_MIN_K: u32 = 7;
pub const HALO2_IPA_BN254_MAX_K: u32 = 16;
pub const HALO2_IPA_BN254_MAX_VK_LEN: usize = 4 * 1024 * 1024;
pub const HALO2_IPA_BN254_MAX_PK_LEN: usize = 64 * 1024 * 1024;
pub const HALO2_IPA_BN254_MAX_PROOF_LEN: usize = 4 * 1024 * 1024;
pub const HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS: usize = 8;
pub const HALO2_IPA_BN254_MAX_INSTANCE_VALUES: usize = 4096;

pub(crate) const VK_HEADER_LEN: usize = 8 + 4 + 4 + 4;
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub(crate) const PK_HEADER_LEN: usize = 8 + 4 + 4 + 4;
pub(crate) const PROOF_HEADER_LEN: usize = 8 + 4;
pub(crate) const INSTANCES_HEADER_LEN: usize = 8 + 4;
pub(crate) const MAX_INSTANCES_BLOB_LEN: usize = INSTANCES_HEADER_LEN
    + HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS * 4
    + HALO2_IPA_BN254_MAX_INSTANCE_VALUES * 32;

pub(crate) const FR_BYTES: usize = 32;
const MAX_FIXED_COMMITMENTS: u32 = 256;
#[cfg(not(feature = "halo2-ipa-verify-only"))]
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
    circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 || poseidon2_arity(circuit_id).is_some()
}

/// Returns the key-envelope magic required by `circuit_id`.
///
/// - cubic v1 -> V1 (`RCH2IPV1` / `RCH2IPP1`);
/// - Poseidon2 hash family (id `2`, `BASE + n`) -> V2 (`RCH2IPV2` /
///   `RCH2IPP2`).
///
/// Unknown circuit ids return the V1 magic and are rejected by
/// [`valid_circuit_id`] before this is used for encoding.
fn vk_magic_for_circuit(circuit_id: u32) -> &'static [u8; 8] {
    if circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        HALO2_IPA_BN254_VK_V1_MAGIC
    } else {
        HALO2_IPA_BN254_VK_V2_MAGIC
    }
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn pk_magic_for_circuit(circuit_id: u32) -> &'static [u8; 8] {
    if circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        HALO2_IPA_BN254_PK_V1_MAGIC
    } else {
        HALO2_IPA_BN254_PK_V2_MAGIC
    }
}

/// Envelope-wide `k` bound. Per-circuit bounds are enforced by
/// [`valid_k_for_circuit`].
fn valid_k(k: u32) -> bool {
    (HALO2_IPA_BN254_MIN_K..=HALO2_IPA_BN254_MAX_K).contains(&k)
}

/// Registered circuits have different row counts and therefore different
/// minimum `k`.
fn valid_k_for_circuit(circuit_id: u32, k: u32) -> bool {
    match circuit_id {
        HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 => valid_k(k),
        HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1 => {
            (HALO2_IPA_BN254_POSEIDON2_HASH3_MIN_K..=HALO2_IPA_BN254_MAX_K).contains(&k)
        }
        _ => match poseidon2_arity(circuit_id) {
            Some(arity) => poseidon2_arity_min_k(arity)
                .is_some_and(|min_k| (min_k..=HALO2_IPA_BN254_MAX_K).contains(&k)),
            None => false,
        },
    }
}

// ---------------------------------------------------------------------------
// Field / byte helpers
// ---------------------------------------------------------------------------

pub(crate) fn fr_from_be(bytes: &[u8]) -> Result<Fr, c_int> {
    if bytes.len() != FR_BYTES {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut le = [0u8; FR_BYTES];
    for (index, byte) in bytes.iter().enumerate() {
        le[FR_BYTES - 1 - index] = *byte;
    }
    Option::<Fr>::from(Fr::from_repr(le)).ok_or(RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT)
}

/// Parses `arity` canonical BE `Fr` values from a Poseidon2 witness.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn poseidon2_inputs_from_be(bytes: &[u8], arity: usize) -> Result<Vec<Fr>, c_int> {
    if arity > HALO2_IPA_BN254_POSEIDON2_MAX_ARITY || bytes.len() != arity * FR_BYTES {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let mut inputs = Vec::with_capacity(arity);
    for chunk in bytes.chunks_exact(FR_BYTES) {
        inputs.push(fr_from_be(chunk)?);
    }
    Ok(inputs)
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

pub(crate) fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32, c_int> {
    let end = offset.checked_add(4).ok_or(RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    slice
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)
}

pub(crate) fn push_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

// ---------------------------------------------------------------------------
// v1 encoders (also used by the fixture example)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn encode_vk_blob(circuit_id: u32, k: u32, vk_bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    if !valid_circuit_id(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    if !valid_k(k) || vk_bytes.is_empty() || vk_bytes.len() > HALO2_IPA_BN254_MAX_VK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let vk_len = u32::try_from(vk_bytes.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let mut out = Vec::with_capacity(VK_HEADER_LEN + vk_bytes.len());
    out.extend_from_slice(vk_magic_for_circuit(circuit_id));
    push_u32_be(&mut out, circuit_id);
    push_u32_be(&mut out, k);
    push_u32_be(&mut out, vk_len);
    out.extend_from_slice(vk_bytes);
    Ok(out)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn encode_pk_blob(circuit_id: u32, k: u32, pk_bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    if !valid_circuit_id(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    if !valid_k(k) || pk_bytes.is_empty() || pk_bytes.len() > HALO2_IPA_BN254_MAX_PK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let pk_len = u32::try_from(pk_bytes.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let mut out = Vec::with_capacity(PK_HEADER_LEN + pk_bytes.len());
    out.extend_from_slice(pk_magic_for_circuit(circuit_id));
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

pub(crate) fn read_input<'a>(
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
pub(crate) fn check_serialized_vk_prefix(payload: &[u8], header_k: u32, error: c_int) -> Result<(), c_int> {
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

pub(crate) fn read_vk_payload<C>(payload: &[u8], error: c_int) -> Result<VerifyingKey<G1Affine>, c_int>
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

/// Parses a VK envelope of either artifact revision and returns
/// `(circuit_id, k, vk)`.
///
/// The magic must match the circuit id's revision: cubic is V1, Poseidon2 is
/// V2. A revision/id mismatch is rejected before decoding the payload.
fn parse_vk(bytes: &[u8]) -> Result<(u32, u32, VerifyingKey<G1Affine>), c_int> {
    if bytes.len() < VK_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let magic: &[u8; 8] = bytes[..8]
        .try_into()
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    if magic != HALO2_IPA_BN254_VK_V1_MAGIC && magic != HALO2_IPA_BN254_VK_V2_MAGIC {
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
    if magic != vk_magic_for_circuit(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    if !valid_k_for_circuit(circuit_id, k) {
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let payload = &bytes[VK_HEADER_LEN..];
    check_serialized_vk_prefix(payload, k, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;
    let vk = if circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        catch_unwind(AssertUnwindSafe(|| {
            read_vk_payload::<CubicCircuitV1>(payload, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)
        }))
        .unwrap_or(Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY))?
    } else if poseidon2_arity(circuit_id).is_some() {
        catch_unwind(AssertUnwindSafe(|| {
            read_vk_payload::<Poseidon2HashCircuit>(payload, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)
        }))
        .unwrap_or(Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY))?
    } else {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    };
    Ok((circuit_id, k, vk))
}

/// Walks the canonical `ProvingKey` serialization *without* allocating, so a
/// hostile polynomial length cannot reach `Polynomial::read`'s `Vec` reserve.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
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

#[cfg(not(feature = "halo2-ipa-verify-only"))]
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

#[cfg(not(feature = "halo2-ipa-verify-only"))]
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

/// Reads one `ProvingKey` after validating the non-allocating layout scan.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub(crate) fn parse_pk_with_circuit<C>(payload: &[u8], k: u32) -> Result<ProvingKey<G1Affine>, c_int>
where
    C: Circuit<Fr, Params = ()>,
{
    const VK_READ_ERROR: c_int = RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA;
    check_serialized_vk_prefix(payload, k, VK_READ_ERROR)?;

    // The PK starts with the serialized VK. Use a counting cursor to learn its
    // exact extent, then walk the remaining polynomial layout without
    // allocating.
    let mut cursor = Cursor::new(payload);
    let vk_end = match catch_unwind(AssertUnwindSafe(|| {
        VerifyingKey::<G1Affine>::read::<_, C>(&mut cursor, SerdeFormat::Processed, ())
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
        ProvingKey::<G1Affine>::read::<_, C>(&mut cursor, SerdeFormat::Processed, ())
    })) {
        Ok(Ok(pk)) => pk,
        _ => return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA),
    };
    if cursor.position() as usize != payload.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    Ok(pk)
}

/// Parses a PK envelope of either artifact revision and returns
/// `(circuit_id, k, pk)`.
///
/// The magic must match the circuit id's revision (cubic V1, Poseidon2 V2).
#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn parse_pk(bytes: &[u8]) -> Result<(u32, u32, ProvingKey<G1Affine>), c_int> {
    if bytes.len() < PK_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let magic: &[u8; 8] = bytes[..8]
        .try_into()
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    if magic != HALO2_IPA_BN254_PK_V1_MAGIC && magic != HALO2_IPA_BN254_PK_V2_MAGIC {
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
    if magic != pk_magic_for_circuit(circuit_id) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    if !valid_k_for_circuit(circuit_id, k) {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    let payload = &bytes[PK_HEADER_LEN..];

    let pk = if circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        parse_pk_with_circuit::<CubicCircuitV1>(payload, k)?
    } else if poseidon2_arity(circuit_id).is_some() {
        parse_pk_with_circuit::<Poseidon2HashCircuit>(payload, k)?
    } else {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    };
    Ok((circuit_id, k, pk))
}

pub(crate) fn parse_proof(bytes: &[u8]) -> Result<&[u8], c_int> {
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

pub(crate) fn parse_instances(bytes: &[u8]) -> Result<Vec<Vec<Fr>>, c_int> {
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

/// Parses the instances blob and enforces the registered shape of
/// `circuit_id`, returning its single instance column.
///
/// - cubic (id `1`): one column, one value.
/// - Poseidon2 hash (id `2` and `BASE + n`): one column with `arity + 1` values
///   `[digest, input0, .., input_{arity-1}]`.
fn parse_instances_for(circuit_id: u32, bytes: &[u8]) -> Result<Vec<Fr>, c_int> {
    let expected_values = if circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        1
    } else {
        match poseidon2_arity(circuit_id) {
            Some(arity) => arity + 1,
            None => return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA),
        }
    };
    let mut columns = parse_instances(bytes)?;
    if columns.len() != 1 || columns[0].len() != expected_values {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
    }
    columns
        .pop()
        .ok_or(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT)
}

// ---------------------------------------------------------------------------
// Deterministic params (optionally cached)
// ---------------------------------------------------------------------------

/// Returns the deterministic IPA params for `k`.
///
/// Without the `halo2-ipa-params-cache` feature this regenerates the generator
/// set from `k` on every call. With the feature, a single-entry thread-local
/// cache holds one `(k, params)` pair; a hit clones it. The cache is ordinary
/// heap memory owned by the current canister instance, is lost on upgrade, and
/// is **not** a trusted-SRS cache: the params are still derived from `k` alone.
#[cfg(not(feature = "halo2-ipa-params-cache"))]
pub(crate) fn params_for(k: u32) -> ParamsIPA<G1Affine> {
    ParamsIPA::<G1Affine>::new(k)
}

#[cfg(feature = "halo2-ipa-params-cache")]
pub(crate) fn params_for(k: u32) -> ParamsIPA<G1Affine> {
    std::thread_local! {
        static PARAMS_CACHE: RefCell<Option<(u32, ParamsIPA<G1Affine>)>> =
            const { RefCell::new(None) };
    }
    PARAMS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((cached_k, params)) = cache.as_ref() {
            if *cached_k == k {
                return params.clone();
            }
        }
        let params = ParamsIPA::<G1Affine>::new(k);
        *cache = Some((k, params.clone()));
        params
    })
}

/// Builds a v1 VK/PK blob pair for an approved circuit.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn keygen_blobs<C>(circuit: &C, circuit_id: u32, k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int>
where
    C: Circuit<Fr, Params = ()>,
{
    let params = params_for(k);
    let vk = keygen_vk(&params, circuit).map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;
    let pk =
        keygen_pk(&params, vk.clone(), circuit).map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;

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

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn key_material(circuit_id: u32, k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    if !valid_circuit_id(circuit_id) || !valid_k_for_circuit(circuit_id, k) {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    #[cfg(test)]
    note_keygen_call();
    match circuit_id {
        HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 => keygen_blobs(&CubicCircuitV1::default(), circuit_id, k),
        _ => match poseidon2_arity(circuit_id) {
            // The fixed columns depend on the sponge layout, so keygen with the
            // registered arity instead of `Default` (0 inputs).
            Some(arity) => {
                let circuit = Poseidon2HashCircuit::new(&vec![Fr::from(0u64); arity]);
                keygen_blobs(&circuit, circuit_id, k)
            }
            None => Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
        },
    }
}

/// Generates VK/PK blobs for an approved circuit. Fixture/test support.
///
/// The key envelope uses the circuit's artifact revision: V1 for cubic,
/// V2 (`RCH2IPV2` / `RCH2IPP2`) for the Poseidon2 hash family.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[doc(hidden)]
pub fn generate_key_material_v1(circuit_id: u32, k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    key_material(circuit_id, k)
}

/// Generates key material for the registered 3-input Poseidon2 hash circuit.
///
/// The envelope magic is V2 even though the function name retains `_v1` for
/// API compatibility.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[doc(hidden)]
pub fn generate_poseidon2_key_material_v1(k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    key_material(HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1, k)
}

/// Generates key material for the fixed `arity`-input Poseidon2 hash circuit
/// (`HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE + arity`) with V2 magic.
///
/// `arity` must be in `0..=12` and `k` at least [`poseidon2_arity_min_k`].
#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[doc(hidden)]
pub fn generate_poseidon2_arity_key_material_v1(
    arity: usize,
    k: u32,
) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    let circuit_id = poseidon2_arity_circuit_id(arity)?;
    key_material(circuit_id, k)
}

/// Returns the arbitrary-arity circuit id `BASE + arity` for `arity in 0..=12`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn poseidon2_arity_circuit_id(arity: usize) -> Result<u32, c_int> {
    if arity > HALO2_IPA_BN254_POSEIDON2_MAX_ARITY {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    let offset = u32::try_from(arity).map_err(|_| RUSTCRYPTO_ERR_INVALID_PARAMETER)?;
    HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE
        .checked_add(offset)
        .ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn expected_instance(x: Fr) -> Fr {
    x * x * x + x + Fr::from(5u64)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_circuit_with_pk<R: RngCore, C: Circuit<Fr>>(
    k: u32,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instance_values: &[Fr],
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let params = params_for(k);
    let instance_columns: [&[Fr]; 1] = [instance_values];
    let instances: [&[&[Fr]]; 1] = [&instance_columns];

    #[cfg(test)]
    note_proof_call();
    let mut transcript =
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    create_proof::<IPACommitmentScheme<G1Affine>, ProverIPA<_>, _, _, _, _>(
        &params,
        pk,
        &[circuit],
        &instances,
        rng,
        &mut transcript,
    )
    .map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;
    let transcript_bytes = transcript.finalize();
    encode_proof_v1(&transcript_bytes)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_cubic_with_pk<R: RngCore>(
    k: u32,
    pk: &ProvingKey<G1Affine>,
    witness: Fr,
    instance: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let circuit = CubicCircuitV1 {
        x: Value::known(witness),
    };
    prove_circuit_with_pk(k, pk, circuit, &[instance], rng)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_poseidon2_with_pk<R: RngCore>(
    k: u32,
    pk: &ProvingKey<G1Affine>,
    inputs: [Fr; HALO2_IPA_BN254_POSEIDON2_HASH3_INPUTS],
    digest: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    prove_poseidon2_arity_with_pk(k, pk, &inputs, digest, rng)
}

/// Proves the fixed `arity`-input Poseidon2 hash circuit, binding
/// `[digest, inputs...]` as the single public instance column.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_poseidon2_arity_with_pk<R: RngCore>(
    k: u32,
    pk: &ProvingKey<G1Affine>,
    inputs: &[Fr],
    digest: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let circuit = Poseidon2HashCircuit::new(inputs);
    let mut instances = Vec::with_capacity(inputs.len() + 1);
    instances.push(digest);
    instances.extend_from_slice(inputs);
    prove_circuit_with_pk(k, pk, circuit, &instances, rng)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_with_rng_impl<R: RngCore>(
    pk_blob: &[u8],
    witness: Fr,
    instance: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let (circuit_id, k, pk) = parse_pk(pk_blob)?;
    if circuit_id != HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    if expected_instance(witness) != instance {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    prove_cubic_with_pk(k, &pk, witness, instance, rng)
}

/// Proves the registered cubic circuit with a caller-supplied RNG. Used by the
/// deterministic fixture generator; the C ABI uses `OsRng`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[doc(hidden)]
pub fn prove_with_rng_v1<R: RngCore>(
    pk_blob: &[u8],
    witness: Fr,
    instance: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    prove_with_rng_impl(pk_blob, witness, instance, rng)
}

/// Proves the registered 3-input Poseidon2 hash circuit with a caller-supplied
/// RNG. Used by the deterministic fixture generator; the C ABI uses `OsRng`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[doc(hidden)]
pub fn prove_poseidon2_with_rng_v1<R: RngCore>(
    pk_blob: &[u8],
    inputs: [Fr; HALO2_IPA_BN254_POSEIDON2_HASH3_INPUTS],
    digest: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let (circuit_id, k, pk) = parse_pk(pk_blob)?;
    if circuit_id != HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1 {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    if poseidon2_hash_output(&inputs) != digest {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    prove_poseidon2_with_pk(k, &pk, inputs, digest, rng)
}

/// Proves the arbitrary-arity Poseidon2 hash circuit in `pk_blob` with a
/// caller-supplied RNG. Used by the deterministic fixture generator and tests;
/// the C ABI uses `OsRng`.
///
/// `inputs.len()` must equal the arity encoded by the PK circuit id and
/// `digest` must equal `hash_output(inputs)`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
#[doc(hidden)]
pub fn prove_poseidon2_arity_with_rng_v1<R: RngCore>(
    pk_blob: &[u8],
    inputs: &[Fr],
    digest: Fr,
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let (circuit_id, k, pk) = parse_pk(pk_blob)?;
    let arity = poseidon2_arity(circuit_id).ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)?;
    if inputs.len() != arity || poseidon2_hash_output(inputs) != digest {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    prove_poseidon2_arity_with_pk(k, &pk, inputs, digest, rng)
}

// ---------------------------------------------------------------------------
// One-shot prepare / prove caches (C ABI only)
// ---------------------------------------------------------------------------

/// Key material generated by a sizing `prepare` call.
///
/// The Nim wrapper always calls `prepare` twice (first with null outputs to
/// learn the sizes, then with caller-owned buffers). Without this cache the
/// second call would repeat `keygen_vk` / `keygen_pk`. The entry is a
/// **one-shot** thread-local staging buffer for exactly that handshake: it is
/// ordinary heap memory, is not persisted, and is **not** a trusted SRS. The
/// keys are still derived deterministically from `(circuit_id, k)`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
struct PreparedKeyMaterial {
    circuit_id: u32,
    k: u32,
    vk_bytes: Vec<u8>,
    pk_bytes: Vec<u8>,
}

/// Proof generated by a sizing `prove` call, keyed by the exact statement
/// bytes.
///
/// An entry is only reused when the proving key, witness, and instances bytes
/// all match, so a different statement never receives a stale proof. Like
/// [`PreparedKeyMaterial`], this is a one-shot thread-local staging buffer, not
/// a trusted SRS and not a persistent proof cache.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
struct CachedProof {
    circuit_id: u32,
    k: u32,
    pk_bytes: Vec<u8>,
    witness_bytes: Vec<u8>,
    instances_bytes: Vec<u8>,
    proof: Vec<u8>,
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
std::thread_local! {
    static PREPARED_KEY_MATERIAL: RefCell<Option<PreparedKeyMaterial>> =
        const { RefCell::new(None) };
    static CACHED_PROOF: RefCell<Option<CachedProof>> = const { RefCell::new(None) };
}

#[cfg(all(test, not(feature = "halo2-ipa-verify-only")))]
std::thread_local! {
    static KEYGEN_CALLS: Cell<usize> = const { Cell::new(0) };
    static PROOF_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(all(test, not(feature = "halo2-ipa-verify-only")))]
fn note_keygen_call() {
    KEYGEN_CALLS.with(|calls| calls.set(calls.get() + 1));
}

#[cfg(all(test, not(feature = "halo2-ipa-verify-only")))]
fn note_proof_call() {
    PROOF_CALLS.with(|calls| calls.set(calls.get() + 1));
}

#[cfg(all(test, not(feature = "halo2-ipa-verify-only")))]
fn reset_ipa_state_for_test() {
    PREPARED_KEY_MATERIAL.with(|slot| *slot.borrow_mut() = None);
    CACHED_PROOF.with(|slot| *slot.borrow_mut() = None);
    KEYGEN_CALLS.with(|calls| calls.set(0));
    PROOF_CALLS.with(|calls| calls.set(0));
}

#[cfg(all(test, not(feature = "halo2-ipa-verify-only")))]
fn keygen_calls_for_test() -> usize {
    KEYGEN_CALLS.with(|calls| calls.get())
}

#[cfg(all(test, not(feature = "halo2-ipa-verify-only")))]
fn proof_calls_for_test() -> usize {
    PROOF_CALLS.with(|calls| calls.get())
}

// ---------------------------------------------------------------------------
// C ABI implementation
// ---------------------------------------------------------------------------

#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub(crate) fn write_output(out: *mut u8, cap: usize, data: &[u8], out_len: *mut usize) -> c_int {
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

#[cfg(not(feature = "halo2-ipa-verify-only"))]
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
    if !valid_circuit_id(circuit_id) || !valid_k_for_circuit(circuit_id, k) {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    if vk_len.is_null() || pk_len.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    PREPARED_KEY_MATERIAL.with(|slot| {
        let mut slot = slot.borrow_mut();
        let reuse = slot
            .as_ref()
            .is_some_and(|cached| cached.circuit_id == circuit_id && cached.k == k);
        if !reuse {
            // Replace any stale entry so a failed keygen never leaves key
            // material for a different `(circuit_id, k)` behind.
            *slot = None;
            let (vk_bytes, pk_bytes) = match key_material(circuit_id, k) {
                Ok(material) => material,
                Err(error) => return error,
            };
            *slot = Some(PreparedKeyMaterial {
                circuit_id,
                k,
                vk_bytes,
                pk_bytes,
            });
        }
        let cached = match slot.as_ref() {
            Some(cached) => cached,
            None => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
        };
        unsafe {
            *vk_len = cached.vk_bytes.len();
            *pk_len = cached.pk_bytes.len();
        }
        if vk_out.is_null() || pk_out.is_null() {
            return RUSTCRYPTO_ERR_NULL_OUTPUT;
        }
        if vk_cap < cached.vk_bytes.len() || pk_cap < cached.pk_bytes.len() {
            return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                cached.vk_bytes.as_ptr(),
                vk_out,
                cached.vk_bytes.len(),
            );
            core::ptr::copy_nonoverlapping(
                cached.pk_bytes.as_ptr(),
                pk_out,
                cached.pk_bytes.len(),
            );
        }
        *slot = None;
        RUSTCRYPTO_OK
    })
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
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
    // The circuit id comes from the PK header and selects the witness length.
    let (circuit_id, k, pk) = match parse_pk(pk_bytes) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let arity = poseidon2_arity(circuit_id);
    let witness_expected = if circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        FR_BYTES
    } else if let Some(arity) = arity {
        arity * FR_BYTES
    } else {
        return RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA;
    };
    // Arity 0 has a zero-byte witness; accept a null pointer for it while still
    // rejecting a non-empty buffer.
    let witness_bytes: &[u8] = if witness_expected == 0 {
        if witness_len != 0 {
            return RUSTCRYPTO_ERR_INVALID_LENGTH;
        }
        &[]
    } else {
        match read_input(
            witness_ptr,
            witness_len,
            witness_expected,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(bytes) => bytes,
            Err(error) => return error,
        }
    };
    if witness_bytes.len() != witness_expected {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    let instances_bytes = match read_input(
        instances_ptr,
        instances_len,
        MAX_INSTANCES_BLOB_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let instance_column = match parse_instances_for(circuit_id, instances_bytes) {
        Ok(column) => column,
        Err(error) => return error,
    };

    // Check the public relation before proving so a mismatched statement never
    // yields a knowingly invalid proof. Parsing happens on every call, so the
    // existing error codes and validation order are unchanged.
    enum Statement {
        Cubic { witness: Fr, instance: Fr },
        Poseidon2 { inputs: Vec<Fr>, digest: Fr },
    }
    let statement = if circuit_id == HALO2_IPA_BN254_CIRCUIT_CUBIC_V1 {
        let witness = match fr_from_be(witness_bytes) {
            Ok(value) => value,
            Err(error) => return error,
        };
        let instance = instance_column[0];
        if expected_instance(witness) != instance {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        Statement::Cubic { witness, instance }
    } else if let Some(arity) = arity {
        let inputs = match poseidon2_inputs_from_be(witness_bytes, arity) {
            Ok(value) => value,
            Err(error) => return error,
        };
        let digest = instance_column[0];
        if instance_column[1..] != inputs[..] || digest != poseidon2_hash_output(&inputs) {
            return RUSTCRYPTO_ERR_INVALID_PARAMETER;
        }
        Statement::Poseidon2 { inputs, digest }
    } else {
        return RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA;
    };

    CACHED_PROOF.with(|slot| {
        let mut slot = slot.borrow_mut();
        // Reuse only for the exact same statement bytes. A different witness,
        // instances blob, or proving key must never receive the old proof.
        let reuse = slot.as_ref().is_some_and(|cached| {
            cached.circuit_id == circuit_id
                && cached.k == k
                && cached.pk_bytes.as_slice() == pk_bytes
                && cached.witness_bytes.as_slice() == witness_bytes
                && cached.instances_bytes.as_slice() == instances_bytes
        });
        if !reuse {
            let proof = match &statement {
                Statement::Cubic { witness, instance } => {
                    prove_cubic_with_pk(k, &pk, *witness, *instance, OsRng)
                }
                Statement::Poseidon2 { inputs, digest } => {
                    prove_poseidon2_arity_with_pk(k, &pk, inputs, *digest, OsRng)
                }
            };
            let proof = match proof {
                Ok(proof) => proof,
                Err(error) => return error,
            };
            *slot = Some(CachedProof {
                circuit_id,
                k,
                pk_bytes: pk_bytes.to_vec(),
                witness_bytes: witness_bytes.to_vec(),
                instances_bytes: instances_bytes.to_vec(),
                proof,
            });
        }
        let status = {
            let cached = match slot.as_ref() {
                Some(cached) => cached,
                None => return RUSTCRYPTO_ERR_INVALID_PARAMETER,
            };
            write_output(proof_out, proof_cap, &cached.proof, proof_len)
        };
        // A short/null output keeps the entry so the retry can reuse it.
        if status == RUSTCRYPTO_OK {
            *slot = None;
        }
        status
    })
}

pub(crate) struct CountingReader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) position: Rc<Cell<usize>>,
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

    let (circuit_id, k, vk) = match parse_vk(vk_bytes) {
        Ok(vk) => vk,
        Err(error) => return error,
    };
    let instance_column = match parse_instances_for(circuit_id, instances_bytes) {
        Ok(column) => column,
        Err(error) => return error,
    };
    let transcript_bytes = match parse_proof(proof_bytes) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    let params = params_for(k);
    let verifier_params = params.verifier_params();

    let position = Rc::new(Cell::new(0usize));
    let reader = CountingReader {
        data: transcript_bytes,
        position: position.clone(),
    };
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(reader);

    let instance_columns: [&[Fr]; 1] = [&instance_column];
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

#[cfg(not(feature = "halo2-ipa-verify-only"))]
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

/// Validates the instances envelope and accepts any registered single-column
/// shape: cubic (1 value), legacy Poseidon2 hash3 (4 values), or an
/// arbitrary-arity Poseidon2 hash (`arity + 1` values for `arity in 0..=12`,
/// i.e. 1..=13 values). The validator does not receive a circuit id, so it
/// accepts any valid single-column shape in that range without weakening the
/// magic/count/canonical/trailing checks.
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
    let columns = match parse_instances(bytes) {
        Ok(columns) => columns,
        Err(error) => return error,
    };
    if columns.len() != 1
        || columns[0].is_empty()
        || columns[0].len() > HALO2_IPA_BN254_POSEIDON2_MAX_ARITY + 1
    {
        return RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT;
    }
    RUSTCRYPTO_OK
}

pub(crate) fn guard(f: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(RUSTCRYPTO_ERR_PANIC)
}

/// Prepares the deterministic IPA params for `k`, keygens the approved circuit,
/// and writes the v1 VK and PK encodings. Neither step uses randomness.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
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
#[cfg(not(feature = "halo2-ipa-verify-only"))]
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
#[cfg(not(feature = "halo2-ipa-verify-only"))]
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

#[cfg(all(test, not(feature = "halo2-ipa-verify-only")))]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/halo2_ipa_bn254_v1.hex");
    const POSEIDON2_FIXTURE: &str = include_str!("../../tests/fixtures/halo2_ipa_poseidon2_v1.hex");
    /// Pre-soundness-fix Poseidon2 fixture (V1 magic). Kept only to prove that
    /// the vulnerable artifact is rejected by the current registry.
    const POSEIDON2_LEGACY_FIXTURE: &str =
        include_str!("../../tests/fixtures/halo2_ipa_poseidon2_legacy_v1.hex");
    const POSEIDON2_ARITY12_LEGACY_FIXTURE: &str =
        include_str!("../../tests/fixtures/halo2_ipa_poseidon2_arity12_legacy_v1.hex");

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

    fn poseidon2_fixture_parts() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            fixture_value(POSEIDON2_FIXTURE, "VK"),
            fixture_value(POSEIDON2_FIXTURE, "PROOF"),
            fixture_value(POSEIDON2_FIXTURE, "INSTANCES"),
            fixture_value(POSEIDON2_FIXTURE, "WITNESS"),
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
        unknown_circuit[8..12].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(
            validate_vk(&unknown_circuit),
            RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA
        );

        let mut unknown_circuit_pk = pk.clone();
        unknown_circuit_pk[8..12].copy_from_slice(&3u32.to_be_bytes());
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
                3,
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
        // Circuit id 2 requires k >= 7.
        for &too_small in &[4u32, 6u32] {
            assert_eq!(
                rustcrypto_halo2_ipa_bn254_prepare(
                    2,
                    too_small,
                    core::ptr::null_mut(),
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    0,
                    core::ptr::null_mut()
                ),
                RUSTCRYPTO_ERR_INVALID_PARAMETER
            );
        }
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

    // ------------------------------------------------------------------
    // Circuit id 2: 3-input Poseidon2 hash
    // ------------------------------------------------------------------

    const POSEIDON2_DIGEST_HEX: &str =
        "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8";

    fn poseidon2_inputs() -> [Fr; HALO2_IPA_BN254_POSEIDON2_HASH3_INPUTS] {
        [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]
    }

    fn poseidon2_digest() -> Fr {
        fr_from_be(&unhex(POSEIDON2_DIGEST_HEX)).expect("digest")
    }

    fn poseidon2_witness(inputs: [Fr; HALO2_IPA_BN254_POSEIDON2_HASH3_INPUTS]) -> Vec<u8> {
        inputs
            .iter()
            .flat_map(|value| encode_fr_be(*value))
            .collect()
    }

    /// The committed Poseidon2 fixture predates the soundness fix to the
    /// sponge's unused absorb lanes. Its V1-magic VK/PK must no longer be
    /// accepted as the new (V2) circuit. If the fixture is regenerated with the
    /// new revision, the full round-trip is checked instead.
    #[test]
    fn poseidon2_fixture_is_revision_checked() {
        let (vk, proof, instances, witness) = poseidon2_fixture_parts();
        assert_eq!(
            witness.len(),
            HALO2_IPA_BN254_POSEIDON2_HASH3_INPUTS * FR_BYTES
        );
        assert_eq!(&witness[..], &poseidon2_witness(poseidon2_inputs())[..]);
        // Circuit id / k / proof+instance formats are unchanged.
        assert_eq!(
            read_u32_be(&vk, 8).unwrap(),
            HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1
        );
        assert_eq!(read_u32_be(&vk, 12).unwrap(), 8);
        assert_eq!(validate_proof(&proof), RUSTCRYPTO_OK);
        assert_eq!(validate_instances(&instances), RUSTCRYPTO_OK);

        if &vk[..8] == HALO2_IPA_BN254_VK_V1_MAGIC {
            // Stale, vulnerable revision: reject the key rather than treating
            // it as the sound circuit.
            assert_eq!(validate_vk(&vk), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
            assert_eq!(
                verify(&vk, &proof, &instances),
                RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY
            );
        } else {
            assert_eq!(&vk[..8], HALO2_IPA_BN254_VK_V2_MAGIC);
            assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
            assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);
            assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);
            let expected_instances = encode_instances_v1(&[{
                let [i0, i1, i2] = poseidon2_inputs();
                vec![poseidon2_digest(), i0, i1, i2]
            }])
            .expect("instances");
            assert_eq!(instances, expected_instances);
        }
    }

    /// Old (V1) Poseidon2 artifacts must never be accepted as the sound
    /// (V2) hash circuit. The fixture is the exact pre-fix artifact.
    #[test]
    fn legacy_poseidon2_artifacts_are_rejected() {
        for fixture in [POSEIDON2_LEGACY_FIXTURE, POSEIDON2_ARITY12_LEGACY_FIXTURE] {
            let vk = fixture_value(fixture, "VK");
            let proof = fixture_value(fixture, "PROOF");
            let instances = fixture_value(fixture, "INSTANCES");
            assert_eq!(&vk[..8], HALO2_IPA_BN254_VK_V1_MAGIC);
            assert_eq!(
                validate_vk(&vk),
                RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
                "legacy V1 Poseidon2 VK was accepted"
            );
            assert_eq!(
                verify(&vk, &proof, &instances),
                RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
                "legacy V1 Poseidon2 proof was verified"
            );
            assert_eq!(validate_proof(&proof), RUSTCRYPTO_OK);
            assert_eq!(validate_instances(&instances), RUSTCRYPTO_OK);
        }
    }

    #[test]
    fn poseidon2_prepare_prove_verify_roundtrip() {
        let circuit_id = HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1;
        let k = 8u32;
        let (vk, pk) = generate_poseidon2_key_material_v1(k).expect("keygen");
        assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
        assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);
        assert_eq!(read_u32_be(&vk, 8).unwrap(), circuit_id);

        let [i0, i1, i2] = poseidon2_inputs();
        let instances =
            encode_instances_v1(&[vec![poseidon2_digest(), i0, i1, i2]]).expect("instances");
        let witness = poseidon2_witness(poseidon2_inputs());

        let mut proof = vec![0u8; 16384];
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

        // A different digest is a valid envelope but an invalid proof.
        let wrong_instances =
            encode_instances_v1(&[vec![poseidon2_digest() + Fr::from(1u64), i0, i1, i2]])
                .expect("instances");
        assert_eq!(
            verify(&vk, &proof, &wrong_instances),
            RUSTCRYPTO_ERR_VERIFICATION_FAILED
        );

        // A witness that disagrees with the public inputs is rejected before
        // proving.
        let wrong_witness = poseidon2_witness([Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)]);
        let mut out = [0u8; 16384];
        let mut out_len = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                wrong_witness.as_ptr(),
                wrong_witness.len(),
                instances.as_ptr(),
                instances.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
        assert_eq!(out_len, 0);

        // The cubic witness length (32 bytes) is not a Poseidon2 witness.
        let short_witness = encode_fr_be(Fr::from(1u64));
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                short_witness.as_ptr(),
                short_witness.len(),
                instances.as_ptr(),
                instances.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
    }

    #[test]
    fn poseidon2_wrong_shape_and_noncanonical_are_rejected() {
        let (vk, pk) = generate_poseidon2_key_material_v1(8).expect("keygen");
        let witness = poseidon2_witness(poseidon2_inputs());
        let instances = encode_instances_v1(&[{
            let [i0, i1, i2] = poseidon2_inputs();
            vec![poseidon2_digest(), i0, i1, i2]
        }])
        .expect("instances");
        let mut proof = vec![0u8; 16384];
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
        assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);

        // One value is the cubic shape, not the Poseidon2 shape.
        let one_value = encode_instances_v1(&[vec![poseidon2_digest()]]).expect("instances");
        assert_eq!(
            verify(&vk, &proof, &one_value),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
        );

        // Two values are not the id-2 shape.
        let two_values =
            encode_instances_v1(&[vec![poseidon2_digest(), Fr::from(1u64)]]).expect("instances");
        assert_eq!(
            verify(&vk, &proof, &two_values),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
        );
        // The circuit-agnostic envelope validator cannot tell circuits apart, so
        // it accepts any single-column shape with 1..=13 values (arity 0..=12)
        // and leaves the circuit-specific check to `verify`.
        assert_eq!(validate_instances(&two_values), RUSTCRYPTO_OK);
        assert_eq!(validate_instances(&instances), RUSTCRYPTO_OK);

        // The cubic 1x1 shape is still accepted by the circuit-agnostic
        // envelope validator.
        assert_eq!(validate_instances(&one_value), RUSTCRYPTO_OK);

        let mut noncanonical = instances.clone();
        let input_start = INSTANCES_HEADER_LEN + 4 + FR_BYTES;
        noncanonical[input_start..input_start + FR_BYTES].fill(0xff);
        assert_eq!(
            validate_instances(&noncanonical),
            RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );
        assert_eq!(
            verify(&vk, &proof, &noncanonical),
            RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );

        // A non-canonical witness is rejected before proving.
        let mut bad_witness = witness;
        bad_witness[..FR_BYTES].fill(0xff);
        let mut out = [0u8; 16384];
        let mut out_len = 0usize;
        assert_eq!(
            rustcrypto_halo2_ipa_bn254_prove(
                pk.as_ptr(),
                pk.len(),
                bad_witness.as_ptr(),
                bad_witness.len(),
                instances.as_ptr(),
                instances.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );
    }

    #[test]
    fn poseidon2_tampered_proof_is_rejected() {
        let (vk, mut proof, instances, _) = poseidon2_fixture_parts();
        let last = proof.len() - 1;
        proof[last] ^= 0x01;
        let status = verify(&vk, &proof, &instances);
        assert_ne!(status, RUSTCRYPTO_OK, "tampered proof accepted");
        assert_ne!(status, RUSTCRYPTO_ERR_PANIC, "tampered proof panicked");
    }

    // ------------------------------------------------------------------
    // Arbitrary arity: circuit ids BASE + 0..=12
    // ------------------------------------------------------------------

    fn arity_circuit_id(arity: usize) -> u32 {
        HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE + arity as u32
    }

    fn arity_inputs(arity: usize) -> Vec<Fr> {
        (1..=arity as u64).map(Fr::from).collect()
    }

    fn arity_witness(inputs: &[Fr]) -> Vec<u8> {
        inputs
            .iter()
            .flat_map(|value| encode_fr_be(*value))
            .collect()
    }

    fn arity_instances(inputs: &[Fr]) -> Vec<u8> {
        encode_instances_v1(&[crate::poseidon2_halo2::hash_public_inputs(inputs)])
            .expect("instances")
    }

    /// Runs the C ABI prove entry point with a caller-supplied witness pointer
    /// and returns `(status, proof, out_len)`. The proof is empty unless the
    /// status is OK.
    fn prove_request(
        pk: &[u8],
        witness_ptr: *const u8,
        witness_len: usize,
        instances: &[u8],
    ) -> (c_int, Vec<u8>, usize) {
        let mut out = vec![0u8; 65536];
        let mut out_len = 0usize;
        let status = rustcrypto_halo2_ipa_bn254_prove(
            pk.as_ptr(),
            pk.len(),
            witness_ptr,
            witness_len,
            instances.as_ptr(),
            instances.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        if status == RUSTCRYPTO_OK {
            out.truncate(out_len);
        }
        (status, out, out_len)
    }

    #[test]
    fn arbitrary_arity_min_k_is_derived_from_rows() {
        assert_eq!(poseidon2_arity(2), Some(3));
        assert_eq!(poseidon2_arity(1), None);
        for arity in 0..=HALO2_IPA_BN254_POSEIDON2_MAX_ARITY {
            assert_eq!(poseidon2_arity(arity_circuit_id(arity)), Some(arity));
            let expected = match arity {
                0..=3 => 7,
                4..=9 => 8,
                _ => 9,
            };
            assert_eq!(
                poseidon2_arity_min_k(arity),
                Some(expected),
                "arity {arity}"
            );
            assert!(valid_k_for_circuit(arity_circuit_id(arity), expected));
            assert!(!valid_k_for_circuit(arity_circuit_id(arity), expected - 1));
            assert!(valid_k_for_circuit(arity_circuit_id(arity), 16));
            assert!(!valid_k_for_circuit(arity_circuit_id(arity), 17));
        }
        assert_eq!(poseidon2_arity_min_k(13), None);
        assert_eq!(poseidon2_arity(arity_circuit_id(13)), None);
        assert_eq!(
            poseidon2_arity(HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE.wrapping_sub(1)),
            None
        );
        assert!(!valid_circuit_id(3));
        assert!(!valid_circuit_id(arity_circuit_id(13)));
    }

    #[test]
    fn arbitrary_arity_prepare_prove_verify_roundtrip() {
        for arity in [0usize, 1, 2, 3, 4, 6, 8, 9, 12] {
            let k = poseidon2_arity_min_k(arity).expect("min k");
            let (vk, pk) = generate_poseidon2_arity_key_material_v1(arity, k).expect("keygen");
            assert_eq!(read_u32_be(&vk, 8).unwrap(), arity_circuit_id(arity));
            assert_eq!(read_u32_be(&vk, 12).unwrap(), k);
            assert_eq!(read_u32_be(&pk, 8).unwrap(), arity_circuit_id(arity));
            assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
            assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);

            let inputs = arity_inputs(arity);
            let instances = arity_instances(&inputs);
            assert_eq!(validate_instances(&instances), RUSTCRYPTO_OK);
            let witness = arity_witness(&inputs);
            assert_eq!(witness.len(), arity * FR_BYTES);

            // Arity 0 has a zero-byte witness: a null pointer must be accepted.
            let (witness_ptr, witness_len): (*const u8, usize) = if arity == 0 {
                (core::ptr::null(), 0)
            } else {
                (witness.as_ptr(), witness.len())
            };
            let (status, proof, _) = prove_request(&pk, witness_ptr, witness_len, &instances);
            assert_eq!(status, RUSTCRYPTO_OK, "arity {arity} prove");
            assert_eq!(validate_proof(&proof), RUSTCRYPTO_OK);
            assert_eq!(
                verify(&vk, &proof, &instances),
                RUSTCRYPTO_OK,
                "arity {arity} verify"
            );

            // A wrong digest is a structurally valid envelope but an invalid
            // proof.
            let mut wrong_values = crate::poseidon2_halo2::hash_public_inputs(&inputs);
            wrong_values[0] += Fr::from(1u64);
            let wrong_instances = encode_instances_v1(&[wrong_values]).expect("instances");
            assert_eq!(validate_instances(&wrong_instances), RUSTCRYPTO_OK);
            assert_eq!(
                verify(&vk, &proof, &wrong_instances),
                RUSTCRYPTO_ERR_VERIFICATION_FAILED,
                "arity {arity} wrong digest"
            );

            // A witness that disagrees with the public inputs is rejected before
            // proving. For arity 0 the empty witness is paired with a different
            // expected digest; for larger arities one input is changed.
            let mismatch_witness = if arity == 0 {
                Vec::new()
            } else {
                let mut wrong_inputs = inputs.clone();
                wrong_inputs[arity - 1] += Fr::from(1u64);
                arity_witness(&wrong_inputs)
            };
            let (mismatch_ptr, mismatch_len, mismatch_instances) = if arity == 0 {
                (core::ptr::null(), 0, wrong_instances.clone())
            } else {
                (
                    mismatch_witness.as_ptr(),
                    mismatch_witness.len(),
                    instances.clone(),
                )
            };
            let (status, _, out_len) =
                prove_request(&pk, mismatch_ptr, mismatch_len, &mismatch_instances);
            assert_eq!(
                status, RUSTCRYPTO_ERR_INVALID_PARAMETER,
                "arity {arity} witness/instance mismatch"
            );
            assert_eq!(out_len, 0);
        }
    }

    #[test]
    fn arbitrary_arity_rejects_wrong_shapes() {
        let arity = 4usize;
        let k = poseidon2_arity_min_k(arity).expect("min k");
        let (vk, pk) = generate_poseidon2_arity_key_material_v1(arity, k).expect("keygen");
        let inputs = arity_inputs(arity);
        let instances = arity_instances(&inputs);
        let witness = arity_witness(&inputs);

        // The legacy 4-value (id 2) shape is not the 5-value arity-4 shape.
        let legacy_shape =
            encode_instances_v1(&[crate::poseidon2_halo2::hash_public_inputs(&inputs[..3])])
                .expect("instances");
        assert_eq!(
            verify(&vk, &proof_placeholder(), &legacy_shape),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
        );

        // A truncated witness is rejected before proving.
        let (status, _, _) =
            prove_request(&pk, witness.as_ptr(), witness.len() - FR_BYTES, &instances);
        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_LENGTH);

        // `BASE + 13` is not a registered circuit id.
        let mut unknown = vk.clone();
        unknown[8..12].copy_from_slice(&arity_circuit_id(13).to_be_bytes());
        assert_eq!(validate_vk(&unknown), RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }

    /// A non-empty well-formed proof envelope used only where the shape check
    /// fires before the transcript is inspected.
    fn proof_placeholder() -> Vec<u8> {
        fixture_value(POSEIDON2_FIXTURE, "PROOF")
    }

    #[test]
    fn instances_validate_accepts_arity_shapes_up_to_thirteen_values() {
        for values in 1..=HALO2_IPA_BN254_POSEIDON2_MAX_ARITY + 1 {
            let mut column = Vec::with_capacity(values);
            for index in 0..values {
                column.push(Fr::from(index as u64));
            }
            let encoded = encode_instances_v1(&[column]).expect("instances");
            assert_eq!(
                validate_instances(&encoded),
                RUSTCRYPTO_OK,
                "values {values}"
            );
        }
        let too_many = encode_instances_v1(&[vec![Fr::from(0u64); 14]]).expect("instances");
        assert_eq!(
            validate_instances(&too_many),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
        );
        let empty_column = encode_instances_v1(&[vec![]]).expect("instances");
        assert_eq!(
            validate_instances(&empty_column),
            RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT
        );
    }

    // ------------------------------------------------------------------
    // Artifact revisions (V1 cubic / V2 Poseidon2)
    // ------------------------------------------------------------------

    #[test]
    fn cubic_keeps_v1_magic_and_rejects_v2() {
        let (vk, pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
        assert_eq!(&vk[..8], HALO2_IPA_BN254_VK_V1_MAGIC);
        assert_eq!(&pk[..8], HALO2_IPA_BN254_PK_V1_MAGIC);
        assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
        assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);

        let mut v2_vk = vk;
        v2_vk[..8].copy_from_slice(HALO2_IPA_BN254_VK_V2_MAGIC);
        assert_eq!(validate_vk(&v2_vk), RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);

        let mut v2_pk = pk;
        v2_pk[..8].copy_from_slice(HALO2_IPA_BN254_PK_V2_MAGIC);
        assert_eq!(validate_pk(&v2_pk), RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }

    #[test]
    fn poseidon2_uses_v2_magic_and_rejects_v1_relabel() {
        for circuit_id in [
            HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1,
            HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE,
            HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE + 12,
        ] {
            let k = if circuit_id == HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1 {
                8
            } else if circuit_id == HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE + 12 {
                9
            } else {
                7
            };
            let (vk, pk) = generate_key_material_v1(circuit_id, k).expect("keygen");
            assert_eq!(&vk[..8], HALO2_IPA_BN254_VK_V2_MAGIC, "id {circuit_id} VK");
            assert_eq!(&pk[..8], HALO2_IPA_BN254_PK_V2_MAGIC, "id {circuit_id} PK");
            assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
            assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);
            assert_eq!(read_u32_be(&vk, 8).unwrap(), circuit_id);
            assert_eq!(read_u32_be(&pk, 8).unwrap(), circuit_id);

            // The same payload re-labelled with the vulnerable V1 magic is not
            // accepted as the sound circuit.
            let mut v1_vk = vk;
            v1_vk[..8].copy_from_slice(HALO2_IPA_BN254_VK_V1_MAGIC);
            assert_eq!(
                validate_vk(&v1_vk),
                RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
                "id {circuit_id} V1-relabelled VK"
            );

            let mut v1_pk = pk;
            v1_pk[..8].copy_from_slice(HALO2_IPA_BN254_PK_V1_MAGIC);
            assert_eq!(
                validate_pk(&v1_pk),
                RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA,
                "id {circuit_id} V1-relabelled PK"
            );
        }
    }

    #[test]
    fn proof_and_instance_formats_are_revision_independent() {
        let values = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let instances = encode_instances_v1(&[values.clone()]).expect("instances");
        assert_eq!(&instances[..8], HALO2_IPA_BN254_INSTANCES_V1_MAGIC);
        assert_eq!(
            parse_instances(&instances).expect("parse"),
            vec![values.clone()]
        );

        let proof = encode_proof_v1(&[0xaa, 0xbb, 0xcc]).expect("proof");
        assert_eq!(&proof[..8], HALO2_IPA_BN254_PROOF_V1_MAGIC);
        assert_eq!(parse_proof(&proof).expect("parse"), &[0xaa, 0xbb, 0xcc]);

        // Trailing bytes and unknown ids are still rejected under V2.
        let mut trailing = instances.clone();
        trailing.push(0);
        assert_eq!(
            validate_instances(&trailing),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
        let (mut vk, _) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1, 8)
                .expect("keygen");
        vk[8..12].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(validate_vk(&vk), RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }

    // ------------------------------------------------------------------
    // One-shot sizing/body caches
    // ------------------------------------------------------------------

    fn prepare_sizing(circuit_id: u32, k: u32) -> (c_int, usize, usize) {
        let mut vk_len = 0usize;
        let mut pk_len = 0usize;
        let status = rustcrypto_halo2_ipa_bn254_prepare(
            circuit_id,
            k,
            core::ptr::null_mut(),
            0,
            &mut vk_len,
            core::ptr::null_mut(),
            0,
            &mut pk_len,
        );
        (status, vk_len, pk_len)
    }

    fn prepare_into(
        circuit_id: u32,
        k: u32,
        vk: &mut [u8],
        pk: &mut [u8],
    ) -> (c_int, usize, usize) {
        let mut vk_len = 0usize;
        let mut pk_len = 0usize;
        let status = rustcrypto_halo2_ipa_bn254_prepare(
            circuit_id,
            k,
            vk.as_mut_ptr(),
            vk.len(),
            &mut vk_len,
            pk.as_mut_ptr(),
            pk.len(),
            &mut pk_len,
        );
        (status, vk_len, pk_len)
    }

    fn prove_raw(
        pk: &[u8],
        witness: &[u8],
        instances: &[u8],
        proof_out: *mut u8,
        proof_cap: usize,
    ) -> (c_int, usize) {
        let mut proof_len = 0usize;
        let status = rustcrypto_halo2_ipa_bn254_prove(
            pk.as_ptr(),
            pk.len(),
            witness.as_ptr(),
            witness.len(),
            instances.as_ptr(),
            instances.len(),
            proof_out,
            proof_cap,
            &mut proof_len,
        );
        (status, proof_len)
    }

    fn cubic_statement(x: u64) -> (Vec<u8>, Vec<u8>) {
        let witness = encode_fr_be(Fr::from(x)).to_vec();
        let y = expected_instance(Fr::from(x));
        let instances = encode_instances_v1(&[vec![y]]).expect("instances");
        (witness, instances)
    }

    #[test]
    fn prepare_sizing_and_body_share_one_keygen() {
        reset_ipa_state_for_test();
        let circuit_id = HALO2_IPA_BN254_CIRCUIT_CUBIC_V1;
        let k = 8u32;

        let (sizing, vk_len, pk_len) = prepare_sizing(circuit_id, k);
        assert_eq!(sizing, RUSTCRYPTO_ERR_NULL_OUTPUT);
        assert!(vk_len > 0 && pk_len > 0);
        assert_eq!(
            keygen_calls_for_test(),
            1,
            "sizing prepare must keygen once"
        );

        let mut vk = vec![0u8; vk_len];
        let mut pk = vec![0u8; pk_len];
        let (status, vk_len2, pk_len2) = prepare_into(circuit_id, k, &mut vk, &mut pk);
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(vk_len2, vk_len);
        assert_eq!(pk_len2, pk_len);
        assert_eq!(
            keygen_calls_for_test(),
            1,
            "body prepare must reuse the sizing keygen"
        );
        assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
        assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);
    }

    #[test]
    fn prepare_short_output_retry_reuses_cached_keys() {
        reset_ipa_state_for_test();
        let circuit_id = HALO2_IPA_BN254_CIRCUIT_CUBIC_V1;
        let k = 8u32;

        // First call is a real body call with too-small buffers. It generates
        // once and reports the required sizes.
        let mut short_vk = [0u8; 1];
        let mut short_pk = [0u8; 1];
        let (status, vk_len, pk_len) = prepare_into(circuit_id, k, &mut short_vk, &mut short_pk);
        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        assert!(vk_len > 1 && pk_len > 1);
        assert_eq!(short_vk, [0u8], "no partial write on short output");
        assert_eq!(short_pk, [0u8], "no partial write on short output");
        assert_eq!(keygen_calls_for_test(), 1);

        // The retry reuses the cached key material.
        let mut vk = vec![0u8; vk_len];
        let mut pk = vec![0u8; pk_len];
        let (status, _, _) = prepare_into(circuit_id, k, &mut vk, &mut pk);
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(keygen_calls_for_test(), 1);
        assert_eq!(validate_vk(&vk), RUSTCRYPTO_OK);
        assert_eq!(validate_pk(&pk), RUSTCRYPTO_OK);
    }

    #[test]
    fn prepare_different_params_replace_cached_material() {
        reset_ipa_state_for_test();
        let cubic = HALO2_IPA_BN254_CIRCUIT_CUBIC_V1;
        let poseidon2 = HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1;

        assert_eq!(prepare_sizing(cubic, 8).0, RUSTCRYPTO_ERR_NULL_OUTPUT);
        assert_eq!(keygen_calls_for_test(), 1);

        // Different k with the same circuit.
        assert_eq!(prepare_sizing(cubic, 9).0, RUSTCRYPTO_ERR_NULL_OUTPUT);
        assert_eq!(keygen_calls_for_test(), 2);

        // Different circuit id.
        let (_, poseidon_vk_len, poseidon_pk_len) = prepare_sizing(poseidon2, 8);
        assert_eq!(keygen_calls_for_test(), 3);

        // The newest entry (Poseidon2) is still reused by the body call.
        let mut vk = vec![0u8; poseidon_vk_len];
        let mut pk = vec![0u8; poseidon_pk_len];
        let (status, _, _) = prepare_into(poseidon2, 8, &mut vk, &mut pk);
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(keygen_calls_for_test(), 3);
        assert_eq!(read_u32_be(&vk, 8).unwrap(), poseidon2);
        assert_eq!(read_u32_be(&pk, 8).unwrap(), poseidon2);

        // Going back to the cubic circuit regenerates because the cache holds
        // only the most recent `(circuit_id, k)`.
        assert_eq!(prepare_sizing(cubic, 8).0, RUSTCRYPTO_ERR_NULL_OUTPUT);
        assert_eq!(keygen_calls_for_test(), 4);
    }

    #[test]
    fn prove_sizing_and_body_share_one_proof() {
        let (vk, pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
        let (witness, instances) = cubic_statement(3);
        reset_ipa_state_for_test();

        let (sizing, required) = prove_raw(
            &pk,
            &witness,
            &instances,
            core::ptr::null_mut(),
            0,
        );
        assert_eq!(sizing, RUSTCRYPTO_ERR_NULL_OUTPUT);
        assert!(required > 0);
        assert_eq!(
            proof_calls_for_test(),
            1,
            "sizing prove must generate once"
        );

        let mut proof = vec![0u8; required];
        let (status, proof_len) = prove_raw(&pk, &witness, &instances, proof.as_mut_ptr(), proof.len());
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(proof_len, required);
        assert_eq!(
            proof_calls_for_test(),
            1,
            "body prove must reuse the sizing proof"
        );
        proof.truncate(proof_len);
        assert_eq!(validate_proof(&proof), RUSTCRYPTO_OK);
        assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);

        // A successful write consumes the one-shot entry: the next call proves
        // again instead of replaying the same proof forever.
        let (again_status, again_len) =
            prove_raw(&pk, &witness, &instances, proof.as_mut_ptr(), proof.len());
        assert_eq!(again_status, RUSTCRYPTO_OK);
        assert_eq!(again_len, required);
        assert_eq!(proof_calls_for_test(), 2);
    }

    #[test]
    fn prove_short_output_retry_reuses_cached_proof() {
        let (vk, pk) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
        let (witness, instances) = cubic_statement(3);
        reset_ipa_state_for_test();

        let mut short = [0u8; 1];
        let (status, required) = prove_raw(&pk, &witness, &instances, short.as_mut_ptr(), short.len());
        assert_eq!(status, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
        assert!(required > 1);
        assert_eq!(proof_calls_for_test(), 1);

        let mut proof = vec![0u8; required];
        let (status, proof_len) = prove_raw(&pk, &witness, &instances, proof.as_mut_ptr(), proof.len());
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(proof_len, required);
        assert_eq!(
            proof_calls_for_test(),
            1,
            "retry after a short buffer must reuse the cached proof"
        );
        proof.truncate(proof_len);
        assert_eq!(verify(&vk, &proof, &instances), RUSTCRYPTO_OK);
    }

    #[test]
    fn prove_changed_statement_never_reuses_old_proof() {
        let (vk8, pk8) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 8).expect("keygen");
        let (vk9, pk9) =
            generate_key_material_v1(HALO2_IPA_BN254_CIRCUIT_CUBIC_V1, 9).expect("keygen");
        let (witness_a, instances_a) = cubic_statement(3);
        let (witness_b, instances_b) = cubic_statement(4);
        reset_ipa_state_for_test();

        // Cache statement A.
        let (_, _) = prove_raw(&pk8, &witness_a, &instances_a, core::ptr::null_mut(), 0);
        assert_eq!(proof_calls_for_test(), 1);

        // A different witness (and its matching instance) must not reuse A.
        let (status, required_b) =
            prove_raw(&pk8, &witness_b, &instances_b, core::ptr::null_mut(), 0);
        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
        assert!(required_b > 0);
        assert_eq!(proof_calls_for_test(), 2);

        // The cached proof belongs to B now; writing it must verify for B.
        let mut proof_b = vec![0u8; required_b];
        let (status, len_b) =
            prove_raw(&pk8, &witness_b, &instances_b, proof_b.as_mut_ptr(), proof_b.len());
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(proof_calls_for_test(), 2);
        proof_b.truncate(len_b);
        assert_eq!(verify(&vk8, &proof_b, &instances_b), RUSTCRYPTO_OK);
        assert_ne!(
            verify(&vk8, &proof_b, &instances_a),
            RUSTCRYPTO_OK,
            "proof for B must not verify for A"
        );

        // An instances blob that does not match the witness is rejected before
        // any proof is generated, and it does not consume the cache.
        let (_, _) = prove_raw(&pk8, &witness_a, &instances_a, core::ptr::null_mut(), 0);
        assert_eq!(proof_calls_for_test(), 3);
        let mismatched = encode_instances_v1(&[vec![Fr::from(999u64)]]).expect("instances");
        let (status, _) =
            prove_raw(&pk8, &witness_a, &mismatched, core::ptr::null_mut(), 0);
        assert_eq!(status, RUSTCRYPTO_ERR_INVALID_PARAMETER);
        assert_eq!(proof_calls_for_test(), 3);

        // A different proving key (same circuit statement) must regenerate the
        // proof rather than replaying the k=8 proof.
        let (status, required_k9) =
            prove_raw(&pk9, &witness_a, &instances_a, core::ptr::null_mut(), 0);
        assert_eq!(status, RUSTCRYPTO_ERR_NULL_OUTPUT);
        assert!(required_k9 > 0);
        assert_eq!(proof_calls_for_test(), 4);
        let mut proof_k9 = vec![0u8; required_k9];
        let (status, len_k9) = prove_raw(
            &pk9,
            &witness_a,
            &instances_a,
            proof_k9.as_mut_ptr(),
            proof_k9.len(),
        );
        assert_eq!(status, RUSTCRYPTO_OK);
        assert_eq!(proof_calls_for_test(), 4);
        proof_k9.truncate(len_k9);
        assert_eq!(verify(&vk9, &proof_k9, &instances_a), RUSTCRYPTO_OK);
    }
}
