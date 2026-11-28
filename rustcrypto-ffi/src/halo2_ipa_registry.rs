//! Compile-time registry and generic adapter for external Halo2 IPA / BN254
//! circuits.
//!
//! # Why this module exists
//!
//! `VerifyingKey::read` / `ProvingKey::read` need a concrete [`Circuit`] type,
//! so a raw `circuit_id` byte from the wire cannot select arbitrary circuit
//! code. An application that wants its own circuit must therefore register the
//! concrete Rust type at **compile time**. This module provides:
//!
//! - [`CircuitProfile`]: the reviewed, per-circuit configuration (circuit id
//!   and version, witness encoding length, instance column/value shape, `k`
//!   bounds, and VK/PK/proof size bounds).
//! - [`ApprovedCircuit`]: implemented by the application's circuit type. It
//!   adds the profile and the witness decoder to [`Circuit`].
//! - Typed generic functions [`prepare`], [`prove`], [`verify`] and
//!   [`validate_vk`] / [`validate_pk`] / [`validate_instances`].
//! - [`halo2_ipa_export_circuit!`] / [`halo2_ipa_export_circuit_verifier!`]:
//!   macros that emit `#[unsafe(export_name = ...)]` `extern "C"` entry points
//!   with a caller-chosen symbol prefix, using the same owned-buffer, two-call
//!   sizing convention as the built-in
//!   [`crate::halo2_ipa::rustcrypto_halo2_ipa_bn254_prepare`] family.
//!
//! No runtime code loading, dynamic circuit descriptor, or unapproved VK
//! execution exists: only types listed in the consuming crate's source can be
//! used, and the circuit id embedded in a key envelope must equal the
//! registered profile's id.
//!
//! # Adapter requirements for an external circuit
//!
//! A circuit implementing [`ApprovedCircuit`] **must**:
//!
//! - use `type Params = ()` and `type FloorPlanner = SimpleFloorPlanner`;
//! - implement `Default` and have `without_witnesses()` return a circuit with
//!   the **same layout** as every witnessed instance (all advice cells assigned,
//!   same regions, same rows, same selectors);
//! - use a deterministic layout (no host-dependent branching on witness values
//!   that changes the number of rows/columns/selectors);
//! - keep the number of rows within `2^k - 6` for the profile's `k` range;
//! - bind the public instance cells it promises with `layouter
//!   .constrain_instance(...)` inside `synthesize`. The registry checks the
//!   *shape* of the expected instance columns but cannot know the circuit's
//!   semantic relation, so the circuit itself must constrain witness cells to
//!   the public instance cells;
//! - decode exactly `profile().witness_len` bytes in `from_witness`, returning
//!   [`crate::RUSTCRYPTO_ERR_INVALID_LENGTH`] or
//!   [`crate::RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT`] before indexing.
//!
//! The application should pin `profile().circuit_id`, the chosen `k`, and a
//! digest of the VK. [`key_digest`] / [`vk_digest`] / [`pk_digest`] and
//! [`params_digest`] are SHA-256 helpers for that purpose. [`verify`] trusts
//! its caller-supplied VK; the digest pin must be checked by the application
//! (or by the built-in pinned C ABI for the built-in circuits) before calling
//! it, because magic/structural checks cannot reject a legacy payload that was
//! relabelled with the V2 magic.
//!
//! # Wire format
//!
//! External circuits always use the V2 key envelopes while sharing the V1
//! header layout and the V1 proof/instance formats:
//!
//! ```text
//! VK: "RCH2IPV2" | circuit_id u32 BE | k u32 BE | vk_len u32 BE | vk
//! PK: "RCH2IPP2" | circuit_id u32 BE | k u32 BE | pk_len u32 BE | pk
//! ```
//!
//! All input validation happens before decoding or indexing, and every C ABI
//! entry point is wrapped in `catch_unwind`. On a `panic = "abort"` target the
//! input checks still return error codes without panicking because they are
//! plain bounds/format checks; `catch_unwind` is only a belt-and-braces guard
//! for unexpected library panics.

use crate::halo2_ipa::{
    CountingReader, HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS,
    HALO2_IPA_BN254_MAX_INSTANCE_VALUES, HALO2_IPA_BN254_MAX_PK_LEN, HALO2_IPA_BN254_MAX_PROOF_LEN,
    HALO2_IPA_BN254_MAX_VK_LEN, HALO2_IPA_BN254_VK_V2_MAGIC, MAX_INSTANCES_BLOB_LEN, VK_HEADER_LEN,
    check_serialized_vk_prefix, fr_from_be, guard, params_for, parse_instances, parse_proof,
    read_input, read_u32_be, read_vk_payload,
};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use crate::halo2_ipa::{
    HALO2_IPA_BN254_PK_V2_MAGIC, PK_HEADER_LEN, encode_proof_v1, parse_pk_with_circuit,
    push_u32_be, write_output,
};
use crate::{
    RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA, RUSTCRYPTO_ERR_INVALID_LENGTH,
    RUSTCRYPTO_ERR_INVALID_PARAMETER, RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
    RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY,
    RUSTCRYPTO_ERR_VERIFICATION_FAILED, RUSTCRYPTO_OK,
};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use crate::{RUSTCRYPTO_ERR_NULL_OUTPUT, RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT};
use core::cell::Cell;
use core::ffi::c_int;
use halo2_axiom::halo2curves::bn256::{Fr, G1Affine};
use halo2_axiom::plonk::{Circuit, VerifyingKey, verify_proof};
use halo2_axiom::poly::VerificationStrategy;
use halo2_axiom::poly::commitment::ParamsProver;
use halo2_axiom::poly::ipa::commitment::IPACommitmentScheme;
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use halo2_axiom::poly::ipa::commitment::ParamsIPA;
use halo2_axiom::poly::ipa::multiopen::VerifierIPA;
use halo2_axiom::poly::ipa::strategy::SingleStrategy;
use halo2_axiom::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use halo2_axiom::plonk::{ProvingKey, create_proof, keygen_pk, keygen_vk};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use halo2_axiom::poly::ipa::multiopen::ProverIPA;
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use halo2_axiom::transcript::{Blake2bWrite, TranscriptWriterBuffer};
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use rand_core::{OsRng, RngCore};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use std::any::TypeId;
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use std::cell::RefCell;
#[cfg(not(feature = "halo2-ipa-verify-only"))]
use zeroize::Zeroize;

/// Lowest circuit id reserved for externally registered circuits.
///
/// Built-in ids (`1`, `2`, `0x100 + 0..=12`) are below this range, so an
/// external adapter can never shadow a built-in circuit.
pub const HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE: u32 = 0x1_0000;

/// Upper bound on a registered circuit's witness encoding (1 MiB).
pub const HALO2_IPA_EXTERNAL_MAX_WITNESS_LEN: usize = 1024 * 1024;

/// Per-circuit, reviewed adapter configuration.
///
/// Build one with [`CircuitProfile::new`] (const-friendly) and optionally
/// [`CircuitProfile::with_bounds`]. Instances are described as one length per
/// column, so circuits with different column shapes are supported up to the
/// global 8-column / 4096-value limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitProfile {
    /// Registered circuit id. Must be `>= HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE`.
    pub circuit_id: u32,
    /// Application-defined circuit version, pinned by the caller.
    pub circuit_version: u32,
    /// Minimum accepted `k`.
    pub min_k: u32,
    /// Maximum accepted `k` (at most 16).
    pub max_k: u32,
    /// Exact witness encoding length in bytes.
    pub witness_len: usize,
    /// Exact length of each public instance column, in field elements.
    pub instance_column_lengths: &'static [usize],
    /// Maximum accepted VK envelope size in bytes.
    pub max_vk_len: usize,
    /// Maximum accepted PK envelope size in bytes.
    pub max_pk_len: usize,
    /// Maximum accepted proof envelope size in bytes.
    pub max_proof_len: usize,
}

impl CircuitProfile {
    /// Creates a profile with the global maximum key/proof bounds.
    pub const fn new(
        circuit_id: u32,
        circuit_version: u32,
        min_k: u32,
        max_k: u32,
        witness_len: usize,
        instance_column_lengths: &'static [usize],
    ) -> Self {
        Self {
            circuit_id,
            circuit_version,
            min_k,
            max_k,
            witness_len,
            instance_column_lengths,
            max_vk_len: HALO2_IPA_BN254_MAX_VK_LEN,
            max_pk_len: HALO2_IPA_BN254_MAX_PK_LEN,
            max_proof_len: HALO2_IPA_BN254_MAX_PROOF_LEN,
        }
    }

    /// Overrides the VK/PK/proof size bounds (each still capped by the global
    /// limits during [`CircuitProfile::validate`]).
    pub const fn with_bounds(
        mut self,
        max_vk_len: usize,
        max_pk_len: usize,
        max_proof_len: usize,
    ) -> Self {
        self.max_vk_len = max_vk_len;
        self.max_pk_len = max_pk_len;
        self.max_proof_len = max_proof_len;
        self
    }

    /// Rejects profiles that could weaken the global bounds or collide with a
    /// built-in circuit. The const constructor cannot validate, so every entry
    /// point calls this first.
    pub fn validate(&self) -> Result<(), c_int> {
        if self.circuit_id < HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE {
            return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
        }
        if self.min_k < crate::halo2_ipa::HALO2_IPA_BN254_MIN_K
            || self.max_k > crate::halo2_ipa::HALO2_IPA_BN254_MAX_K
            || self.min_k > self.max_k
        {
            return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
        }
        if self.witness_len > HALO2_IPA_EXTERNAL_MAX_WITNESS_LEN {
            return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
        }
        if self.instance_column_lengths.is_empty()
            || self.instance_column_lengths.len() > HALO2_IPA_BN254_MAX_INSTANCE_COLUMNS
        {
            return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
        }
        let mut total = 0usize;
        for &length in self.instance_column_lengths {
            if length == 0 || length > HALO2_IPA_BN254_MAX_INSTANCE_VALUES {
                return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
            }
            total = match total.checked_add(length) {
                Some(total) if total <= HALO2_IPA_BN254_MAX_INSTANCE_VALUES => total,
                _ => return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER),
            };
        }
        if self.max_vk_len == 0
            || self.max_vk_len > HALO2_IPA_BN254_MAX_VK_LEN
            || self.max_pk_len == 0
            || self.max_pk_len > HALO2_IPA_BN254_MAX_PK_LEN
            || self.max_proof_len == 0
            || self.max_proof_len > HALO2_IPA_BN254_MAX_PROOF_LEN
        {
            return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
        }
        Ok(())
    }

    /// Total number of public instance values across all columns.
    pub fn total_instance_values(&self) -> usize {
        self.instance_column_lengths.iter().sum()
    }
}

/// A circuit type approved at compile time.
///
/// Implement this trait (or use [`halo2_ipa_export_circuit!`], which requires
/// it) in the consuming crate. The registry never loads circuit code from
/// bytes: the concrete type is the only source of truth for decoding keys and
/// witnesses.
pub trait ApprovedCircuit: Circuit<Fr, Params = ()> + Default + Clone + 'static {
    /// Reviewed profile for this circuit. Must be constant for the type.
    fn profile() -> CircuitProfile;

    /// Decodes the witness encoding into a circuit instance.
    ///
    /// The registry already checked `bytes.len() == profile().witness_len`.
    /// Implementations must still validate field elements and return an error
    /// code instead of panicking.
    fn from_witness(bytes: &[u8]) -> Result<Self, c_int>;
}

fn approved_profile<C: ApprovedCircuit>() -> Result<CircuitProfile, c_int> {
    let profile = C::profile();
    profile.validate()?;
    Ok(profile)
}

fn check_k(profile: &CircuitProfile, k: u32) -> Result<(), c_int> {
    if (profile.min_k..=profile.max_k).contains(&k) {
        Ok(())
    } else {
        Err(RUSTCRYPTO_ERR_INVALID_PARAMETER)
    }
}

/// Decodes a canonical big-endian BN254 `Fr` from one 32-byte chunk.
pub fn decode_fr_be(bytes: &[u8]) -> Result<Fr, c_int> {
    fr_from_be(bytes)
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn encode_v2_vk(circuit_id: u32, k: u32, vk_bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    if vk_bytes.is_empty() || vk_bytes.len() > HALO2_IPA_BN254_MAX_VK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let vk_len = u32::try_from(vk_bytes.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let mut out = Vec::with_capacity(VK_HEADER_LEN + vk_bytes.len());
    out.extend_from_slice(HALO2_IPA_BN254_VK_V2_MAGIC);
    push_u32_be(&mut out, circuit_id);
    push_u32_be(&mut out, k);
    push_u32_be(&mut out, vk_len);
    out.extend_from_slice(vk_bytes);
    Ok(out)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn encode_v2_pk(circuit_id: u32, k: u32, pk_bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    if pk_bytes.is_empty() || pk_bytes.len() > HALO2_IPA_BN254_MAX_PK_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let pk_len = u32::try_from(pk_bytes.len()).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let mut out = Vec::with_capacity(PK_HEADER_LEN + pk_bytes.len());
    out.extend_from_slice(HALO2_IPA_BN254_PK_V2_MAGIC);
    push_u32_be(&mut out, circuit_id);
    push_u32_be(&mut out, k);
    push_u32_be(&mut out, pk_len);
    out.extend_from_slice(pk_bytes);
    Ok(out)
}

fn parse_v2_vk<C: ApprovedCircuit>(
    bytes: &[u8],
) -> Result<(u32, u32, VerifyingKey<G1Affine>), c_int> {
    let profile = approved_profile::<C>()?;
    if bytes.len() < VK_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if &bytes[..8] != HALO2_IPA_BN254_VK_V2_MAGIC {
        // V1 keys, including old vulnerable Poseidon2 artifacts, are never
        // accepted as external-circuit keys.
        return Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY);
    }
    let circuit_id = read_u32_be(bytes, 8).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let k = read_u32_be(bytes, 12).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let vk_len = read_u32_be(bytes, 16).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)? as usize;
    if vk_len == 0
        || vk_len > profile.max_vk_len
        || vk_len > HALO2_IPA_BN254_MAX_VK_LEN
        || bytes.len() != VK_HEADER_LEN + vk_len
    {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if circuit_id != profile.circuit_id {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    check_k(&profile, k).map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;
    let payload = &bytes[VK_HEADER_LEN..];
    check_serialized_vk_prefix(payload, k, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;
    let vk = catch_unwind(AssertUnwindSafe(|| {
        read_vk_payload::<C>(payload, RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)
    }))
    .unwrap_or(Err(RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY))?;
    Ok((circuit_id, k, vk))
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn parse_v2_pk<C: ApprovedCircuit>(bytes: &[u8]) -> Result<(u32, u32, ProvingKey<G1Affine>), c_int> {
    let profile = approved_profile::<C>()?;
    if bytes.len() < PK_HEADER_LEN {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if &bytes[..8] != HALO2_IPA_BN254_PK_V2_MAGIC {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    let circuit_id = read_u32_be(bytes, 8).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let k = read_u32_be(bytes, 12).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let pk_len = read_u32_be(bytes, 16).map_err(|_| RUSTCRYPTO_ERR_INVALID_LENGTH)? as usize;
    if pk_len == 0
        || pk_len > profile.max_pk_len
        || pk_len > HALO2_IPA_BN254_MAX_PK_LEN
        || bytes.len() != PK_HEADER_LEN + pk_len
    {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    if circuit_id != profile.circuit_id {
        return Err(RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA);
    }
    check_k(&profile, k).map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;
    let payload = &bytes[PK_HEADER_LEN..];
    let pk = parse_pk_with_circuit::<C>(payload, k)?;
    Ok((circuit_id, k, pk))
}

fn parse_instance_columns<C: ApprovedCircuit>(bytes: &[u8]) -> Result<Vec<Vec<Fr>>, c_int> {
    let profile = approved_profile::<C>()?;
    let columns = parse_instances(bytes)?;
    if columns.len() != profile.instance_column_lengths.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
    }
    for (column, &expected) in columns.iter().zip(profile.instance_column_lengths) {
        if column.len() != expected {
            return Err(RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT);
        }
    }
    Ok(columns)
}

// ---------------------------------------------------------------------------
// Keygen / proving / verification (typed core)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn key_material<C: ApprovedCircuit>(k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    let profile = approved_profile::<C>()?;
    check_k(&profile, k)?;
    let params = params_for(k);
    let circuit = C::default();
    let vk = keygen_vk(&params, &circuit).map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;
    let pk = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;

    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, halo2_axiom::SerdeFormat::Processed)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY)?;
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, halo2_axiom::SerdeFormat::Processed)
        .map_err(|_| RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA)?;

    let vk_blob = encode_v2_vk(profile.circuit_id, k, &vk_bytes)?;
    let pk_blob = encode_v2_pk(profile.circuit_id, k, &pk_bytes)?;
    // `parse_v2_vk` / `parse_v2_pk` reject envelopes above the profile bounds,
    // so a keygen that exceeds them would produce a key that `prepare` hands
    // out but `prove` / `verify` refuse. Fail at generation time instead.
    if vk_blob.len() > profile.max_vk_len || pk_blob.len() > profile.max_pk_len {
        return Err(RUSTCRYPTO_ERR_INVALID_PARAMETER);
    }
    Ok((vk_blob, pk_blob))
}

/// Deterministically keygens an approved external circuit for `k`.
///
/// Returns the V2 VK and PK envelopes. No randomness is used: `ParamsIPA` is
/// derived from `k` and `keygen_*` is deterministic for a fixed circuit layout.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub fn prepare<C: ApprovedCircuit>(k: u32) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    key_material::<C>(k)
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_parsed<C: ApprovedCircuit, R: RngCore>(
    k: u32,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instance_columns: &[Vec<Fr>],
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let params: ParamsIPA<G1Affine> = params_for(k);
    let column_slices: Vec<&[Fr]> = instance_columns.iter().map(Vec::as_slice).collect();
    let instances: [&[&[Fr]]; 1] = [column_slices.as_slice()];

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
    encode_proof_v1(&transcript.finalize())
}

/// Proves an approved external circuit with a caller-supplied CSPRNG.
///
/// `expected_instances` is the V1 instances envelope supplied by the caller and
/// is passed to the prover unchanged. `witness` must be exactly
/// `profile().witness_len` bytes.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub fn prove_with_rng<C: ApprovedCircuit, R: RngCore>(
    pk_blob: &[u8],
    witness: &[u8],
    expected_instances: &[u8],
    rng: R,
) -> Result<Vec<u8>, c_int> {
    let profile = approved_profile::<C>()?;
    if witness.len() != profile.witness_len {
        return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
    }
    let (_, k, pk) = parse_v2_pk::<C>(pk_blob)?;
    let instance_columns = parse_instance_columns::<C>(expected_instances)?;
    let circuit = C::from_witness(witness)?;
    prove_parsed::<C, R>(k, &pk, circuit, &instance_columns, rng)
}

/// Proves an approved external circuit using the operating-system CSPRNG.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub fn prove<C: ApprovedCircuit>(
    pk_blob: &[u8],
    witness: &[u8],
    expected_instances: &[u8],
) -> Result<Vec<u8>, c_int> {
    prove_with_rng::<C, _>(pk_blob, witness, expected_instances, OsRng)
}

/// Verifies a proof against an independently supplied expected-instances blob.
///
/// Returns `Ok(())` only for a structurally valid proof that verifies for this
/// circuit's VK and the caller's public instances. A different VK (different
/// circuit id or layout) is rejected before the transcript is read.
pub fn verify<C: ApprovedCircuit>(
    vk_blob: &[u8],
    proof_blob: &[u8],
    expected_instances: &[u8],
) -> Result<(), c_int> {
    let (_, k, vk) = parse_v2_vk::<C>(vk_blob)?;
    let instance_columns = parse_instance_columns::<C>(expected_instances)?;
    let transcript_bytes = parse_proof(proof_blob)?;

    let params = params_for(k);
    let verifier_params = params.verifier_params();

    let position = Rc::new(Cell::new(0usize));
    let reader = CountingReader {
        data: transcript_bytes,
        position: position.clone(),
    };
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(reader);

    let column_slices: Vec<&[Fr]> = instance_columns.iter().map(Vec::as_slice).collect();
    let instances: [&[&[Fr]]; 1] = [column_slices.as_slice()];

    match verify_proof::<IPACommitmentScheme<G1Affine>, VerifierIPA<_>, _, _, SingleStrategy<_>>(
        verifier_params,
        &vk,
        SingleStrategy::new(verifier_params),
        &instances,
        &mut transcript,
    ) {
        Ok(()) => {}
        Err(_) => return Err(RUSTCRYPTO_ERR_VERIFICATION_FAILED),
    }

    if position.get() != transcript_bytes.len() {
        return Err(RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT);
    }
    Ok(())
}

/// Structurally validates a V2 VK envelope, including decoding it with the
/// registered circuit type.
pub fn validate_vk<C: ApprovedCircuit>(vk_blob: &[u8]) -> c_int {
    match parse_v2_vk::<C>(vk_blob) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

/// Structurally validates a V2 PK envelope, including the bounded layout scan
/// and decoding it with the registered circuit type.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub fn validate_pk<C: ApprovedCircuit>(pk_blob: &[u8]) -> c_int {
    match parse_v2_pk::<C>(pk_blob) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

/// Validates the revision-independent proof envelope.
pub fn validate_proof(proof_blob: &[u8]) -> c_int {
    match parse_proof(proof_blob) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

/// Validates the revision-independent instances envelope and this circuit's
/// exact column shape.
pub fn validate_instances<C: ApprovedCircuit>(instances_blob: &[u8]) -> c_int {
    match parse_instance_columns::<C>(instances_blob) {
        Ok(_) => RUSTCRYPTO_OK,
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// Pinning helpers
// ---------------------------------------------------------------------------

/// SHA-256 of an arbitrary key envelope (or raw key payload).
pub fn key_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// SHA-256 of a verifying-key envelope. Pin this in the application.
pub fn vk_digest(vk_blob: &[u8]) -> [u8; 32] {
    key_digest(vk_blob)
}

/// SHA-256 of a proving-key envelope.
pub fn pk_digest(pk_blob: &[u8]) -> [u8; 32] {
    key_digest(pk_blob)
}

/// Digest binding the transparent IPA params **profile/version** to `k`.
///
/// The params themselves are derived deterministically from `k` (no trusted
/// setup), so pinning this digest plus the VK digest pins the whole setup
/// profile. This is **not** a cryptographic digest of the generated
/// `ParamsIPA` contents: it hashes a domain tag and `k`, so a change to the
/// generator derivation would not change this value. Rename/replace it only
/// together with a profile revision; do not treat it as content binding.
pub fn params_digest(k: u32) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"RCH2IP-PARAMS-V2");
    hasher.update(k.to_be_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// FFI core (C ABI helpers used by the export macros)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "halo2-ipa-verify-only"))]
struct PreparedKeyMaterial {
    type_id: TypeId,
    circuit_id: u32,
    k: u32,
    vk_bytes: Vec<u8>,
    pk_bytes: Vec<u8>,
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
struct CachedProof {
    type_id: TypeId,
    circuit_id: u32,
    k: u32,
    pk_bytes: Vec<u8>,
    witness_bytes: Vec<u8>,
    instances_bytes: Vec<u8>,
    proof: Vec<u8>,
}

/// Zeroizes the staged witness / instances / PK bytes when the one-shot entry
/// is consumed, replaced, or dropped.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
impl Drop for CachedProof {
    fn drop(&mut self) {
        self.witness_bytes.zeroize();
        self.instances_bytes.zeroize();
        self.pk_bytes.zeroize();
    }
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
std::thread_local! {
    /// One-shot sizing/body staging entry, exactly like the built-in C ABI.
    /// Ordinary heap memory, not a trusted SRS and not persisted.
    static PREPARED_KEY_MATERIAL: RefCell<Option<PreparedKeyMaterial>> =
        const { RefCell::new(None) };
    static CACHED_PROOF: RefCell<Option<CachedProof>> = const { RefCell::new(None) };
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prepare_status<C: ApprovedCircuit>(
    k: u32,
    vk_out: *mut u8,
    vk_cap: usize,
    vk_len: *mut usize,
    pk_out: *mut u8,
    pk_cap: usize,
    pk_len: *mut usize,
) -> Result<c_int, c_int> {
    let profile = approved_profile::<C>()?;
    check_k(&profile, k)?;
    if vk_len.is_null() || pk_len.is_null() {
        return Ok(RUSTCRYPTO_ERR_NULL_OUTPUT);
    }
    PREPARED_KEY_MATERIAL.with(|slot| {
        let mut slot = slot.borrow_mut();
        let type_id = TypeId::of::<C>();
        let reuse = slot.as_ref().is_some_and(|cached| {
            cached.type_id == type_id && cached.circuit_id == profile.circuit_id && cached.k == k
        });
        if !reuse {
            *slot = None;
            let (vk_bytes, pk_bytes) = key_material::<C>(k)?;
            *slot = Some(PreparedKeyMaterial {
                type_id,
                circuit_id: profile.circuit_id,
                k,
                vk_bytes,
                pk_bytes,
            });
        }
        let cached = slot
            .as_ref()
            .ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)?;
        unsafe {
            *vk_len = cached.vk_bytes.len();
            *pk_len = cached.pk_bytes.len();
        }
        if vk_out.is_null() || pk_out.is_null() {
            return Ok(RUSTCRYPTO_ERR_NULL_OUTPUT);
        }
        if vk_cap < cached.vk_bytes.len() || pk_cap < cached.pk_bytes.len() {
            return Ok(RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT);
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
        Ok(RUSTCRYPTO_OK)
    })
}

#[cfg(not(feature = "halo2-ipa-verify-only"))]
fn prove_status<C: ApprovedCircuit>(
    pk_ptr: *const u8,
    pk_len: usize,
    witness_ptr: *const u8,
    witness_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
    proof_out: *mut u8,
    proof_cap: usize,
    proof_len: *mut usize,
) -> Result<c_int, c_int> {
    let profile = approved_profile::<C>()?;
    if proof_len.is_null() {
        return Ok(RUSTCRYPTO_ERR_NULL_OUTPUT);
    }
    let pk_bytes = read_input(pk_ptr, pk_len, profile.max_pk_len, RUSTCRYPTO_ERR_INVALID_LENGTH)?;
    let (circuit_id, k, pk) = parse_v2_pk::<C>(pk_bytes)?;

    let witness_expected = profile.witness_len;
    let witness_bytes: &[u8] = if witness_expected == 0 {
        if witness_len != 0 {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        &[]
    } else {
        let bytes = read_input(
            witness_ptr,
            witness_len,
            witness_expected,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        )?;
        if bytes.len() != witness_expected {
            return Err(RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        bytes
    };

    let instances_bytes = read_input(
        instances_ptr,
        instances_len,
        MAX_INSTANCES_BLOB_LEN,
        RUSTCRYPTO_ERR_INVALID_LENGTH,
    )?;
    let instance_columns = parse_instance_columns::<C>(instances_bytes)?;

    CACHED_PROOF.with(|slot| {
        let mut slot = slot.borrow_mut();
        let type_id = TypeId::of::<C>();
        let reuse = slot.as_ref().is_some_and(|cached| {
            cached.type_id == type_id
                && cached.circuit_id == circuit_id
                && cached.k == k
                && cached.pk_bytes.as_slice() == pk_bytes
                && cached.witness_bytes.as_slice() == witness_bytes
                && cached.instances_bytes.as_slice() == instances_bytes
        });
        if !reuse {
            let circuit = C::from_witness(witness_bytes)?;
            let proof = prove_parsed::<C, _>(k, &pk, circuit, &instance_columns, OsRng)?;
            *slot = Some(CachedProof {
                type_id,
                circuit_id,
                k,
                pk_bytes: pk_bytes.to_vec(),
                witness_bytes: witness_bytes.to_vec(),
                instances_bytes: instances_bytes.to_vec(),
                proof,
            });
        }
        let cached = slot
            .as_ref()
            .ok_or(RUSTCRYPTO_ERR_INVALID_PARAMETER)?;
        let status = write_output(proof_out, proof_cap, &cached.proof, proof_len);
        if status == RUSTCRYPTO_OK {
            *slot = None;
        }
        Ok(status)
    })
}

/// C ABI-compatible prepare entry point for `C` (used by the export macro).
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub fn ffi_prepare<C: ApprovedCircuit>(
    k: u32,
    vk_out: *mut u8,
    vk_cap: usize,
    vk_len: *mut usize,
    pk_out: *mut u8,
    pk_cap: usize,
    pk_len: *mut usize,
) -> c_int {
    guard(|| {
        prepare_status::<C>(k, vk_out, vk_cap, vk_len, pk_out, pk_cap, pk_len)
            .unwrap_or_else(|error| error)
    })
}

/// C ABI-compatible prove entry point for `C` (used by the export macro).
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub fn ffi_prove<C: ApprovedCircuit>(
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
        prove_status::<C>(
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
        .unwrap_or_else(|error| error)
    })
}

/// C ABI-compatible verify entry point for `C` (used by the export macro).
pub fn ffi_verify<C: ApprovedCircuit>(
    vk_ptr: *const u8,
    vk_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    guard(|| {
        let profile = match approved_profile::<C>() {
            Ok(profile) => profile,
            Err(error) => return error,
        };
        let vk_bytes = match read_input(vk_ptr, vk_len, profile.max_vk_len, RUSTCRYPTO_ERR_INVALID_LENGTH)
        {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };
        let proof_bytes = match read_input(
            proof_ptr,
            proof_len,
            profile.max_proof_len,
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
        match verify::<C>(vk_bytes, proof_bytes, instances_bytes) {
            Ok(()) => RUSTCRYPTO_OK,
            Err(error) => error,
        }
    })
}

/// C ABI-compatible VK validate entry point for `C`.
pub fn ffi_validate_vk<C: ApprovedCircuit>(vk_ptr: *const u8, vk_len: usize) -> c_int {
    guard(|| {
        let profile = match approved_profile::<C>() {
            Ok(profile) => profile,
            Err(error) => return error,
        };
        let bytes = match read_input(vk_ptr, vk_len, profile.max_vk_len, RUSTCRYPTO_ERR_INVALID_LENGTH)
        {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };
        validate_vk::<C>(bytes)
    })
}

/// C ABI-compatible PK validate entry point for `C`.
#[cfg(not(feature = "halo2-ipa-verify-only"))]
pub fn ffi_validate_pk<C: ApprovedCircuit>(pk_ptr: *const u8, pk_len: usize) -> c_int {
    guard(|| {
        let profile = match approved_profile::<C>() {
            Ok(profile) => profile,
            Err(error) => return error,
        };
        let bytes = match read_input(pk_ptr, pk_len, profile.max_pk_len, RUSTCRYPTO_ERR_INVALID_LENGTH)
        {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };
        validate_pk::<C>(bytes)
    })
}

/// C ABI-compatible proof validate entry point (circuit independent).
pub fn ffi_validate_proof(proof_ptr: *const u8, proof_len: usize) -> c_int {
    guard(|| {
        let bytes = match read_input(
            proof_ptr,
            proof_len,
            HALO2_IPA_BN254_MAX_PROOF_LEN,
            RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT,
        ) {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };
        validate_proof(bytes)
    })
}

/// C ABI-compatible instances validate entry point for `C`.
pub fn ffi_validate_instances<C: ApprovedCircuit>(
    instances_ptr: *const u8,
    instances_len: usize,
) -> c_int {
    guard(|| {
        let bytes = match read_input(
            instances_ptr,
            instances_len,
            MAX_INSTANCES_BLOB_LEN,
            RUSTCRYPTO_ERR_INVALID_LENGTH,
        ) {
            Ok(bytes) => bytes,
            Err(error) => return error,
        };
        validate_instances::<C>(bytes)
    })
}

// ---------------------------------------------------------------------------
// Export macros
// ---------------------------------------------------------------------------

/// Exports a full (prepare/prove/verify/validate) C ABI adapter for an
/// [`ApprovedCircuit`] under a caller-chosen symbol prefix.
///
/// ```ignore
/// rust_crypto_ffi::halo2_ipa_export_circuit!(MyCircuit, my_circuit);
/// // C symbols: my_circuit_prepare, my_circuit_prove, my_circuit_verify,
/// //            my_circuit_vk_validate, my_circuit_pk_validate,
/// //            my_circuit_proof_validate, my_circuit_instances_validate
/// // Rust:      my_circuit::prepare(...), my_circuit::prove(...), ...
/// ```
///
/// The generated functions use the same owned-buffer, two-call sizing
/// convention as [`crate::halo2_ipa`]: call `prepare` / `prove` with a null
/// output first to obtain the required length (`RUSTCRYPTO_ERR_NULL_OUTPUT`),
/// then call again with caller-owned buffers.
///
/// This macro requires the prover symbols of `rustcrypto-ffi`. A verifier-only
/// consumer should use [`halo2_ipa_export_circuit_verifier!`] and enable
/// `rustcrypto-ffi/halo2-ipa-verify-only` instead.
#[macro_export]
macro_rules! halo2_ipa_export_circuit {
    ($circuit:ty, $prefix:ident) => {
        #[allow(non_snake_case, non_camel_case_types, dead_code, unused_imports)]
        pub mod $prefix {
            use super::*;
            use ::core::ffi::c_int;

            #[unsafe(export_name = concat!(stringify!($prefix), "_prepare"))]
            pub extern "C" fn prepare(
                k: u32,
                vk_out: *mut u8,
                vk_cap: usize,
                vk_len: *mut usize,
                pk_out: *mut u8,
                pk_cap: usize,
                pk_len: *mut usize,
            ) -> c_int {
                $crate::halo2_ipa_registry::ffi_prepare::<$circuit>(
                    k, vk_out, vk_cap, vk_len, pk_out, pk_cap, pk_len,
                )
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_prove"))]
            pub extern "C" fn prove(
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
                $crate::halo2_ipa_registry::ffi_prove::<$circuit>(
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
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_verify"))]
            pub extern "C" fn verify(
                vk_ptr: *const u8,
                vk_len: usize,
                proof_ptr: *const u8,
                proof_len: usize,
                instances_ptr: *const u8,
                instances_len: usize,
            ) -> c_int {
                $crate::halo2_ipa_registry::ffi_verify::<$circuit>(
                    vk_ptr,
                    vk_len,
                    proof_ptr,
                    proof_len,
                    instances_ptr,
                    instances_len,
                )
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_vk_validate"))]
            pub extern "C" fn vk_validate(vk_ptr: *const u8, vk_len: usize) -> c_int {
                $crate::halo2_ipa_registry::ffi_validate_vk::<$circuit>(vk_ptr, vk_len)
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_pk_validate"))]
            pub extern "C" fn pk_validate(pk_ptr: *const u8, pk_len: usize) -> c_int {
                $crate::halo2_ipa_registry::ffi_validate_pk::<$circuit>(pk_ptr, pk_len)
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_proof_validate"))]
            pub extern "C" fn proof_validate(proof_ptr: *const u8, proof_len: usize) -> c_int {
                $crate::halo2_ipa_registry::ffi_validate_proof(proof_ptr, proof_len)
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_instances_validate"))]
            pub extern "C" fn instances_validate(
                instances_ptr: *const u8,
                instances_len: usize,
            ) -> c_int {
                $crate::halo2_ipa_registry::ffi_validate_instances::<$circuit>(
                    instances_ptr,
                    instances_len,
                )
            }
        }
    };
}

/// Exports a verifier-only C ABI adapter (verify + validators, no keygen or
/// proving symbols) for an [`ApprovedCircuit`].
///
/// Use this in a `halo2-ipa-verify-only` consumer so its static library does
/// not contain prover/keygen code. Pair it with
/// `rustcrypto-ffi = { ..., features = ["halo2-ipa-verify-only"] }`.
#[macro_export]
macro_rules! halo2_ipa_export_circuit_verifier {
    ($circuit:ty, $prefix:ident) => {
        #[allow(non_snake_case, non_camel_case_types, dead_code, unused_imports)]
        pub mod $prefix {
            use super::*;
            use ::core::ffi::c_int;

            #[unsafe(export_name = concat!(stringify!($prefix), "_verify"))]
            pub extern "C" fn verify(
                vk_ptr: *const u8,
                vk_len: usize,
                proof_ptr: *const u8,
                proof_len: usize,
                instances_ptr: *const u8,
                instances_len: usize,
            ) -> c_int {
                $crate::halo2_ipa_registry::ffi_verify::<$circuit>(
                    vk_ptr,
                    vk_len,
                    proof_ptr,
                    proof_len,
                    instances_ptr,
                    instances_len,
                )
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_vk_validate"))]
            pub extern "C" fn vk_validate(vk_ptr: *const u8, vk_len: usize) -> c_int {
                $crate::halo2_ipa_registry::ffi_validate_vk::<$circuit>(vk_ptr, vk_len)
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_proof_validate"))]
            pub extern "C" fn proof_validate(proof_ptr: *const u8, proof_len: usize) -> c_int {
                $crate::halo2_ipa_registry::ffi_validate_proof(proof_ptr, proof_len)
            }

            #[unsafe(export_name = concat!(stringify!($prefix), "_instances_validate"))]
            pub extern "C" fn instances_validate(
                instances_ptr: *const u8,
                instances_len: usize,
            ) -> c_int {
                $crate::halo2_ipa_registry::ffi_validate_instances::<$circuit>(
                    instances_ptr,
                    instances_len,
                )
            }
        }
    };
}


