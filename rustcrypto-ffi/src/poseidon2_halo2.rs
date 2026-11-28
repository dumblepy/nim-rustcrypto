//! Halo2 custom gate for the Poseidon2/BN254 permutation and sponge.
//!
//! # Scope
//!
//! This module constrains **every** Poseidon2 round (8 full + 56 partial) with a
//! Halo2 custom gate over the BN254 scalar field `Fr`. The constants, round
//! ordering, linear layers and Noir/Barretenberg sponge framing are the same as
//! [`crate::poseidon2`].
//!
//! Two circuits are provided:
//!
//! - [`Poseidon2PermutationCircuit`] constrains one width-4 permutation and
//!   binds the input state and output state to the instance column.
//! - [`Poseidon2HashCircuit`] constrains the full fixed-length sponge
//!   (length IV, rate-3 absorption, Noir final-permutation rule) and binds the
//!   raw inputs and the squeezed digest to the instance column.
//!
//! # Layout
//!
//! One permutation occupies 65 rows:
//!
//! ```text
//! row base + 0 : state = M(input)              (s_init + s_absorb)
//! row base + r : round r transition, r = 0..63
//! row base + 64: final state
//! ```
//!
//! `s_full` is enabled on rows `0..=3` and `60..=63`; `s_partial` on rows
//! `4..=59`. The per-round constants live in four fixed columns (assigned once
//! per permutation block) and are queried at `Rotation::cur()`. Fixed columns
//! are part of the verifying key, so a prover cannot change them.
//!
//! # Security notes
//!
//! This is a demonstration circuit, not an audited generic frontend. The
//! Poseidon2 parameters and their provenance are unchanged from
//! [`crate::poseidon2`]; see `docs/poseidon2-halo2-gate.md`.

use crate::poseidon2::{
    POSEIDON2_BN254_MAX_INPUTS, POSEIDON2_BN254_RATE, POSEIDON2_BN254_WIDTH,
    constants::BN254_CONFIG,
};
use ark_ff::PrimeField as ArkPrimeField;
use halo2_axiom::circuit::{Cell, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::plonk::{
    Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance,
    Selector,
};
use halo2_axiom::poly::Rotation;

/// Poseidon2 state width constrained by the gate.
pub const POSEIDON2_HALO2_WIDTH: usize = POSEIDON2_BN254_WIDTH;
/// Poseidon2 sponge rate constrained by the gate.
pub const POSEIDON2_HALO2_RATE: usize = POSEIDON2_BN254_RATE;
/// Number of Poseidon2 rounds (R_F + R_P) constrained by the gate.
pub const POSEIDON2_HALO2_ROUNDS: usize = 64;
/// Number of full rounds.
pub const POSEIDON2_HALO2_FULL_ROUNDS: usize = 8;
/// Number of partial rounds.
pub const POSEIDON2_HALO2_PARTIAL_ROUNDS: usize = 56;
/// Rows occupied by one permutation (`ROUNDS + 1`).
pub const POSEIDON2_HALO2_PERMUTATION_ROWS: usize = POSEIDON2_HALO2_ROUNDS + 1;

const RF_FIRST: usize = POSEIDON2_HALO2_FULL_ROUNDS / 2;
const P_END: usize = RF_FIRST + POSEIDON2_HALO2_PARTIAL_ROUNDS;

/// The vendored constants are `ark_bn254::Fr`; the gate lives in
/// `halo2_axiom`'s `Fr`. Both are BN254's scalar field, so the canonical
/// 64-bit limbs are reinterpreted directly (infallibly) into the gate field.
fn halo_fr(value: ark_bn254::Fr) -> Fr {
    // `ark_bn254::Fr` and `halo2_axiom`'s `Fr` are the same BN254 scalar field,
    // so `into_bigint` already yields the canonical (non-Montgomery) 64-bit
    // limbs, which are `< modulus`. `Fr::from_raw` maps canonical limbs into
    // the Montgomery representation without any fallible decode. Using it
    // (instead of a fallible byte decode) keeps the wasm32 `panic=abort`
    // production path free of a trap on malformed inputs.
    Fr::from_raw(value.into_bigint().0)
}

/// Inverse of [`halo_fr`], used by tests to compare against the vendored
/// `ark_bn254::Fr` implementation.
#[cfg(test)]
fn ark_fr(value: Fr) -> ark_bn254::Fr {
    use halo2_axiom::halo2curves::ff::PrimeField as _;
    ark_bn254::Fr::from_le_bytes_mod_order(value.to_repr().as_ref())
}

#[inline(always)]
fn diagonal_constant(index: usize) -> Fr {
    halo_fr(BN254_CONFIG.internal_matrix_diagonal[index])
}

#[inline(always)]
fn round_constant(round: usize, index: usize) -> Fr {
    halo_fr(BN254_CONFIG.round_constant[round][index])
}

fn length_iv(len: usize) -> Fr {
    // 2^64, computed without a `u128` conversion.
    let two_pow_64 = Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
    Fr::from(len as u64) * two_pow_64
}

#[inline(always)]
fn is_full_round(round: usize) -> bool {
    round < RF_FIRST || round >= P_END
}

/// Number of permutations needed by the Noir/Barretenberg sponge.
///
/// The final permutation is skipped exactly when the input count is a non-zero
/// multiple of the rate.
pub fn hash_permutation_count(input_count: usize) -> usize {
    let full = input_count / POSEIDON2_HALO2_RATE;
    if input_count == 0 || input_count % POSEIDON2_HALO2_RATE != 0 {
        full + 1
    } else {
        full
    }
}

/// Number of rows used by [`Poseidon2PermutationCircuit`].
pub fn permutation_circuit_rows() -> usize {
    POSEIDON2_HALO2_PERMUTATION_ROWS
}

/// Number of rows used by [`Poseidon2HashCircuit`] for `input_count` inputs.
///
/// The raw-input cells are placed in the absorption columns at block base
/// rows, so they do not increase the row count.
pub fn hash_circuit_rows(input_count: usize) -> usize {
    hash_permutation_count(input_count) * POSEIDON2_HALO2_PERMUTATION_ROWS
}

/// Expected permutation output for a width-4 state.
pub fn permutation_output(input: [Fr; 4]) -> [Fr; 4] {
    permutation_trace(input)[POSEIDON2_HALO2_ROUNDS]
}

/// Expected Noir/Barretenberg sponge digest for `inputs`.
///
/// This computes the same sponge as the vendored `ark_bn254::Fr`
/// implementation; tests compare both representations.
pub fn hash_output(inputs: &[Fr]) -> Fr {
    let blocks = sponge_witnesses(inputs);
    // `hash_permutation_count` is always `>= 1`, so the sponge always performs
    // at least one permutation and `blocks` is never empty. `last()` keeps the
    // production path free of a panicking `expect`/index; the fallback mirrors
    // the exact single-block sponge for the empty input state and is therefore
    // the same digest rather than an arbitrary value.
    match blocks.last() {
        Some(block) => block.trace[POSEIDON2_HALO2_ROUNDS][0],
        None => permutation_trace([
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            length_iv(inputs.len()),
        ])[POSEIDON2_HALO2_ROUNDS][0],
    }
}

/// Instance values bound by [`Poseidon2PermutationCircuit`]:
/// `[input0..input3, output0..output3]`.
pub fn permutation_public_inputs(input: [Fr; 4]) -> Vec<Fr> {
    let output = permutation_output(input);
    let mut values = Vec::with_capacity(2 * POSEIDON2_HALO2_WIDTH);
    values.extend_from_slice(&input);
    values.extend_from_slice(&output);
    values
}

/// Instance values bound by [`Poseidon2HashCircuit`]:
/// `[digest, input0, .., input_{n-1}]`.
pub fn hash_public_inputs(inputs: &[Fr]) -> Vec<Fr> {
    let mut values = Vec::with_capacity(inputs.len() + 1);
    values.push(hash_output(inputs));
    values.extend_from_slice(inputs);
    values
}

// ---------------------------------------------------------------------------
// Native witness computation (mirrors crate::poseidon2)
// ---------------------------------------------------------------------------

#[inline(always)]
fn s_box(x: Fr) -> Fr {
    let x2 = x * x;
    x2 * x2 * x
}

#[inline(always)]
fn external_matrix(state: &mut [Fr; 4]) {
    let t0 = state[0] + state[1];
    let t1 = state[2] + state[3];
    let mut t2 = state[1] + state[1];
    t2 += t1;
    let mut t3 = state[3] + state[3];
    t3 += t0;
    let mut t4 = t1 + t1;
    t4 += t4;
    t4 += t3;
    let mut t5 = t0 + t0;
    t5 += t5;
    t5 += t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    state[0] = t6;
    state[1] = t5;
    state[2] = t7;
    state[3] = t4;
}

#[inline(always)]
fn internal_matrix(state: &mut [Fr; 4]) {
    let mut sum = Fr::from(0u64);
    for value in state.iter() {
        sum += *value;
    }
    for (index, value) in state.iter_mut().enumerate() {
        *value *= diagonal_constant(index);
        *value += sum;
    }
}

#[inline(always)]
fn add_round_constants(state: &mut [Fr; 4], round: usize) {
    for (index, value) in state.iter_mut().enumerate() {
        *value += round_constant(round, index);
    }
}

/// `(u^2, u^5)` for `u = state + RC` on a round row. Rows without a round
/// (the final state row) get zeros; the `s_round` selector is disabled there.
fn round_powers(state: &[[Fr; 4]], row: usize) -> ([Fr; 4], [Fr; 4]) {
    let mut pow2 = [Fr::from(0u64); 4];
    let mut pow5 = [Fr::from(0u64); 4];
    if row < POSEIDON2_HALO2_ROUNDS {
        for index in 0..4 {
            let u = state[row][index] + round_constant(row, index);
            pow2[index] = u * u;
            pow5[index] = pow2[index] * pow2[index] * u;
        }
    }
    (pow2, pow5)
}

fn apply_round(mut state: [Fr; 4], round: usize) -> [Fr; 4] {
    if is_full_round(round) {
        add_round_constants(&mut state, round);
        for value in state.iter_mut() {
            *value = s_box(*value);
        }
        external_matrix(&mut state);
    } else {
        state[0] += round_constant(round, 0);
        state[0] = s_box(state[0]);
        internal_matrix(&mut state);
    }
    state
}

/// Computes the 65-row trace: row 0 is `M(input)`, row `r + 1` is round `r`.
fn permutation_trace(input: [Fr; 4]) -> Vec<[Fr; 4]> {
    let mut trace = Vec::with_capacity(POSEIDON2_HALO2_PERMUTATION_ROWS);
    let mut state = input;
    external_matrix(&mut state);
    trace.push(state);
    for round in 0..POSEIDON2_HALO2_ROUNDS {
        state = apply_round(state, round);
        trace.push(state);
    }
    trace
}

/// One sponge block: the state before absorption, the absorbed block, the
/// pre-matrix input state and the 65-row permutation trace.
#[derive(Clone, Debug)]
struct SpongeBlockWitness {
    prev: [Fr; 4],
    absorb: [Fr; 4],
    input: [Fr; 4],
    trace: Vec<[Fr; 4]>,
}

fn sponge_witnesses(inputs: &[Fr]) -> Vec<SpongeBlockWitness> {
    let len = inputs.len();
    let iv = length_iv(len);
    let mut state = [Fr::from(0u64), Fr::from(0u64), Fr::from(0u64), iv];

    let full = len / POSEIDON2_HALO2_RATE;
    let mut blocks = Vec::with_capacity(hash_permutation_count(len));
    for block in 0..full {
        let mut absorb = [Fr::from(0u64); 4];
        absorb[..POSEIDON2_HALO2_RATE]
            .copy_from_slice(&inputs[block * POSEIDON2_HALO2_RATE..][..POSEIDON2_HALO2_RATE]);
        let prev = state;
        for (value, added) in state.iter_mut().zip(absorb.iter()) {
            *value += *added;
        }
        let input = state;
        let trace = permutation_trace(input);
        state = trace[POSEIDON2_HALO2_ROUNDS];
        blocks.push(SpongeBlockWitness {
            prev,
            absorb,
            input,
            trace,
        });
    }

    let remainder = len % POSEIDON2_HALO2_RATE;
    if len == 0 || remainder != 0 {
        let mut absorb = [Fr::from(0u64); 4];
        absorb[..remainder].copy_from_slice(&inputs[full * POSEIDON2_HALO2_RATE..][..remainder]);
        let prev = state;
        for (value, added) in state.iter_mut().zip(absorb.iter()) {
            *value += *added;
        }
        let input = state;
        let trace = permutation_trace(input);
        blocks.push(SpongeBlockWitness {
            prev,
            absorb,
            input,
            trace,
        });
    }

    blocks
}

// ---------------------------------------------------------------------------
// Gate expressions
// ---------------------------------------------------------------------------

#[inline(always)]
fn constant(value: u64) -> Expression<Fr> {
    Expression::Constant(Fr::from(value))
}

/// Barretenberg/Noir external linear layer as a linear combination.
fn external_matrix_expr(state: [Expression<Fr>; 4]) -> [Expression<Fr>; 4] {
    let [s0, s1, s2, s3] = state;
    [
        constant(5) * s0.clone() + constant(7) * s1.clone() + s2.clone() + constant(3) * s3.clone(),
        constant(4) * s0.clone() + constant(6) * s1.clone() + s2.clone() + s3.clone(),
        s0.clone() + constant(3) * s1.clone() + constant(5) * s2.clone() + constant(7) * s3.clone(),
        s0 + s1 + constant(4) * s2 + constant(6) * s3,
    ]
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration shared by both Poseidon2 Halo2 circuits.
#[derive(Clone, Debug)]
pub struct Poseidon2Halo2Config {
    state: [Column<Advice>; 4],
    input: [Column<Advice>; 4],
    prev: [Column<Advice>; 4],
    absorb: [Column<Advice>; 4],
    /// `(state + RC)^2` for each state element on a round row.
    pow2: [Column<Advice>; 4],
    /// `(state + RC)^5` for each state element on a round row.
    pow5: [Column<Advice>; 4],
    raw: Column<Advice>,
    round_constant: [Column<Fixed>; 4],
    instance: Column<Instance>,
    s_init: Selector,
    s_round: Selector,
    s_full: Selector,
    s_partial: Selector,
    s_absorb: Selector,
}

fn configure_poseidon2(meta: &mut ConstraintSystem<Fr>) -> Poseidon2Halo2Config {
    let state_columns = core::array::from_fn(|_| meta.advice_column());
    let input_columns = core::array::from_fn(|_| meta.advice_column());
    let prev_columns = core::array::from_fn(|_| meta.advice_column());
    let absorb_columns = core::array::from_fn(|_| meta.advice_column());
    let pow2_columns = core::array::from_fn(|_| meta.advice_column());
    let pow5_columns = core::array::from_fn(|_| meta.advice_column());
    let raw = meta.advice_column();
    let round_constant_columns = core::array::from_fn(|_| meta.fixed_column());
    let instance = meta.instance_column();

    // `assign_advice_from_constant` needs one constant-enabled fixed column.
    let constants = meta.fixed_column();
    meta.enable_constant(constants);

    for column in state_columns
        .iter()
        .chain(input_columns.iter())
        .chain(pow2_columns.iter())
        .chain(pow5_columns.iter())
    {
        meta.enable_equality(*column);
    }
    for column in prev_columns.iter().chain(absorb_columns.iter()) {
        meta.enable_equality(*column);
    }
    meta.enable_equality(raw);
    meta.enable_equality(instance);

    let s_init = meta.selector();
    let s_round = meta.selector();
    let s_full = meta.selector();
    let s_partial = meta.selector();
    let s_absorb = meta.selector();

    // row0: state == M(input)
    meta.create_gate("poseidon2 initial external matrix", |meta| {
        let enabled = meta.query_selector(s_init);
        let input: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(input_columns[i], Rotation::cur()));
        let state: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(state_columns[i], Rotation::cur()));
        let mixed = external_matrix_expr(input);
        let constraints: Vec<Expression<Fr>> = (0..4)
            .map(|i| enabled.clone() * (state[i].clone() - mixed[i].clone()))
            .collect();
        constraints
    });

    // S-box low-degree decomposition: pow2 = u^2, pow5 = pow2^2 * u.
    // Splitting the degree-5 S-box keeps every gate within the vendored
    // halo2 `MAX_DEGREE` cap (default 5) while still constraining `u^5`
    // exactly on every round row.
    meta.create_gate("poseidon2 s-box square", |meta| {
        let enabled = meta.query_selector(s_round);
        let constraints: Vec<Expression<Fr>> = (0..4)
            .map(|i| {
                let state = meta.query_advice(state_columns[i], Rotation::cur());
                let pow2 = meta.query_advice(pow2_columns[i], Rotation::cur());
                let round_constant = meta.query_fixed(round_constant_columns[i], Rotation::cur());
                let u = state + round_constant;
                enabled.clone() * (pow2 - u.clone() * u)
            })
            .collect();
        constraints
    });

    meta.create_gate("poseidon2 s-box fifth power", |meta| {
        let enabled = meta.query_selector(s_round);
        let constraints: Vec<Expression<Fr>> = (0..4)
            .map(|i| {
                let state = meta.query_advice(state_columns[i], Rotation::cur());
                let pow2 = meta.query_advice(pow2_columns[i], Rotation::cur());
                let pow5 = meta.query_advice(pow5_columns[i], Rotation::cur());
                let round_constant = meta.query_fixed(round_constant_columns[i], Rotation::cur());
                let u = state + round_constant;
                enabled.clone() * (pow5 - pow2.clone() * pow2 * u)
            })
            .collect();
        constraints
    });

    // Full round: next[i] == M(pow5)[i]
    meta.create_gate("poseidon2 full round", |meta| {
        let enabled = meta.query_selector(s_full);
        let next: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(state_columns[i], Rotation::next()));
        let s_boxed: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(pow5_columns[i], Rotation::cur()));
        let mixed = external_matrix_expr(s_boxed);
        let constraints: Vec<Expression<Fr>> = (0..4)
            .map(|i| enabled.clone() * (next[i].clone() - mixed[i].clone()))
            .collect();
        constraints
    });

    // Partial round: only state[0] gets the S-box, then the internal layer.
    meta.create_gate("poseidon2 partial round", |meta| {
        let enabled = meta.query_selector(s_partial);
        let state: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(state_columns[i], Rotation::cur()));
        let next: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(state_columns[i], Rotation::next()));
        let b0 = meta.query_advice(pow5_columns[0], Rotation::cur());
        let b1 = state[1].clone();
        let b2 = state[2].clone();
        let b3 = state[3].clone();
        let sum = b0.clone() + b1.clone() + b2.clone() + b3.clone();
        let b = [b0, b1, b2, b3];
        let constraints: Vec<Expression<Fr>> = (0..4)
            .map(|i| {
                let diagonal = Expression::Constant(diagonal_constant(i));
                enabled.clone() * (next[i].clone() - (diagonal * b[i].clone() + sum.clone()))
            })
            .collect();
        constraints
    });

    // Sponge absorption: input == prev + absorb.
    meta.create_gate("poseidon2 sponge absorption", |meta| {
        let enabled = meta.query_selector(s_absorb);
        let constraints: Vec<Expression<Fr>> = (0..4)
            .map(|i| {
                let input = meta.query_advice(input_columns[i], Rotation::cur());
                let prev = meta.query_advice(prev_columns[i], Rotation::cur());
                let absorb = meta.query_advice(absorb_columns[i], Rotation::cur());
                enabled.clone() * (input - prev - absorb)
            })
            .collect();
        constraints
    });

    Poseidon2Halo2Config {
        state: state_columns,
        input: input_columns,
        prev: prev_columns,
        absorb: absorb_columns,
        pow2: pow2_columns,
        pow5: pow5_columns,
        raw,
        round_constant: round_constant_columns,
        instance,
        s_init,
        s_round,
        s_full,
        s_partial,
        s_absorb,
    }
}

// ---------------------------------------------------------------------------
// Block assignment
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Tamper {
    row: usize,
    column: usize,
    value: Fr,
}

enum PrevBinding {
    /// No sponge gate (permutation circuit).
    Unused,
    /// First sponge block: `prev` cells are constants (the length IV state).
    First([Fr; 4]),
    /// Later sponge block: copy `prev` from the previous permutation output.
    Copied {
        values: Value<[Fr; 4]>,
        cells: [Cell; 4],
    },
}

struct BlockCells {
    input: [Cell; 4],
    absorb: [Cell; 4],
    state: Vec<[Cell; 4]>,
}

#[allow(clippy::too_many_arguments)]
fn assign_block(
    region: &mut Region<'_, Fr>,
    config: &Poseidon2Halo2Config,
    base: usize,
    input: Value<[Fr; 4]>,
    trace: Value<Vec<[Fr; 4]>>,
    prev: PrevBinding,
    absorb: Value<[Fr; 4]>,
    sponge: bool,
    disabled_round: Option<usize>,
) -> Result<BlockCells, Error> {
    // Per-round constants as fixed columns (part of the verifying key).
    for round in 0..POSEIDON2_HALO2_ROUNDS {
        for (index, column) in config.round_constant.iter().enumerate() {
            region.assign_fixed(*column, base + round, round_constant(round, index));
        }
    }

    config.s_init.enable(region, base)?;
    if sponge {
        config.s_absorb.enable(region, base)?;
    }
    for round in 0..POSEIDON2_HALO2_ROUNDS {
        config.s_round.enable(region, base + round)?;
        if disabled_round == Some(round) {
            continue;
        }
        if is_full_round(round) {
            config.s_full.enable(region, base + round)?;
        } else {
            config.s_partial.enable(region, base + round)?;
        }
    }

    let input_cells = core::array::from_fn(|i| {
        region
            .assign_advice(
                config.input[i],
                base,
                input.map(|values| Assigned::from(values[i])),
            )
            .cell()
    });

    let absorb_cells = core::array::from_fn(|i| {
        region
            .assign_advice(
                config.absorb[i],
                base,
                absorb.map(|values| Assigned::from(values[i])),
            )
            .cell()
    });

    if sponge {
        match prev {
            PrevBinding::Unused => {}
            PrevBinding::First(values) => {
                for (i, value) in values.iter().enumerate() {
                    region.assign_advice_from_constant(
                        || format!("poseidon2 length IV {i}"),
                        config.prev[i],
                        base,
                        *value,
                    )?;
                }
            }
            PrevBinding::Copied { values, cells } => {
                for i in 0..4 {
                    let cell = region
                        .assign_advice(
                            config.prev[i],
                            base,
                            values.map(|state| Assigned::from(state[i])),
                        )
                        .cell();
                    region.constrain_equal(cell, cells[i]);
                }
            }
        }
    }

    let trace = trace.as_ref();
    let mut state_cells = Vec::with_capacity(POSEIDON2_HALO2_PERMUTATION_ROWS);
    for row in 0..POSEIDON2_HALO2_PERMUTATION_ROWS {
        let power = trace.map(|trace| round_powers(trace, row));
        let pow2 = power.map(|(pow2, _)| pow2);
        let pow5 = power.map(|(_, pow5)| pow5);
        let cells = core::array::from_fn(|i| {
            let value = trace.map(|trace| trace[row][i]);
            region
                .assign_advice(config.state[i], base + row, value.map(Assigned::from))
                .cell()
        });
        for i in 0..4 {
            region.assign_advice(
                config.pow2[i],
                base + row,
                pow2.map(|values| Assigned::from(values[i])),
            );
            region.assign_advice(
                config.pow5[i],
                base + row,
                pow5.map(|values| Assigned::from(values[i])),
            );
        }
        state_cells.push(cells);
    }

    Ok(BlockCells {
        input: input_cells,
        absorb: absorb_cells,
        state: state_cells,
    })
}

// ---------------------------------------------------------------------------
// Permutation circuit
// ---------------------------------------------------------------------------

/// Halo2 circuit constraining one Poseidon2 permutation.
///
/// Instance column (8 rows): `[input0..input3, output0..output3]`.
#[derive(Clone, Debug)]
pub struct Poseidon2PermutationCircuit {
    input: Value<[Fr; 4]>,
    tamper: Option<Tamper>,
    recompute_after_tamper: bool,
    disabled_round: Option<usize>,
}

impl Poseidon2PermutationCircuit {
    /// Builds a circuit for a known input state.
    pub fn new(input: [Fr; 4]) -> Self {
        Self {
            input: Value::known(input),
            tamper: None,
            recompute_after_tamper: false,
            disabled_round: None,
        }
    }
}

impl Default for Poseidon2PermutationCircuit {
    fn default() -> Self {
        Self {
            input: Value::unknown(),
            tamper: None,
            recompute_after_tamper: false,
            disabled_round: None,
        }
    }
}

impl Circuit<Fr> for Poseidon2PermutationCircuit {
    type Config = Poseidon2Halo2Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            input: Value::unknown(),
            tamper: None,
            recompute_after_tamper: self.recompute_after_tamper,
            disabled_round: self.disabled_round,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        configure_poseidon2(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let tamper = self.tamper;
        let recompute = self.recompute_after_tamper;
        let trace = self.input.map(|input| {
            let mut trace = permutation_trace(input);
            if let Some(tamper) = tamper {
                if tamper.row < POSEIDON2_HALO2_PERMUTATION_ROWS {
                    trace[tamper.row][tamper.column] = tamper.value;
                    if recompute {
                        for round in tamper.row..POSEIDON2_HALO2_ROUNDS {
                            trace[round + 1] = apply_round(trace[round], round);
                        }
                    }
                }
            }
            trace
        });

        let block = layouter.assign_region(
            || "poseidon2 permutation",
            |mut region| {
                assign_block(
                    &mut region,
                    &config,
                    0,
                    self.input,
                    trace,
                    PrevBinding::Unused,
                    Value::known([Fr::from(0u64); 4]),
                    false,
                    self.disabled_round,
                )
            },
        )?;

        for i in 0..4 {
            layouter.constrain_instance(block.input[i], config.instance, i);
        }
        for i in 0..4 {
            layouter.constrain_instance(
                block.state[POSEIDON2_HALO2_ROUNDS][i],
                config.instance,
                4 + i,
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hash circuit
// ---------------------------------------------------------------------------

/// Halo2 circuit constraining the Noir/Barretenberg Poseidon2 sponge.
///
/// Instance column (`1 + n` rows): `[digest, input0, .., input_{n-1}]`.
#[derive(Clone, Debug, Default)]
pub struct Poseidon2HashCircuit {
    inputs: Vec<Value<Fr>>,
}

impl Poseidon2HashCircuit {
    /// Builds a circuit for known inputs. `inputs.len()` must be `0..=12`.
    pub fn new(inputs: &[Fr]) -> Self {
        Self {
            inputs: inputs.iter().copied().map(Value::known).collect(),
        }
    }
}

impl Circuit<Fr> for Poseidon2HashCircuit {
    type Config = Poseidon2Halo2Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: self.inputs.iter().map(|_| Value::unknown()).collect(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        configure_poseidon2(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let len = self.inputs.len();
        if len > POSEIDON2_BN254_MAX_INPUTS {
            return Err(Error::Synthesis);
        }

        let values: Value<Vec<Fr>> = self.inputs.iter().copied().collect();
        let blocks = values.as_ref().map(|inputs| sponge_witnesses(inputs));
        let permutations = hash_permutation_count(len);
        let full = len / POSEIDON2_HALO2_RATE;
        let remainder = len % POSEIDON2_HALO2_RATE;
        let iv = length_iv(len);

        let (raw_cells, digest_cells) = layouter.assign_region(
            || "poseidon2 hash",
            |mut region| {
                let values_ref = values.as_ref();
                let raw_cells: Vec<Cell> = (0..len)
                    .map(|index| {
                        region
                            .assign_advice(
                                config.raw,
                                index,
                                values_ref.map(|values| Assigned::from(values[index])),
                            )
                            .cell()
                    })
                    .collect();

                let blocks_ref = blocks.as_ref();
                let mut previous_output: Option<[Cell; 4]> = None;
                let mut digest_cells: Option<[Cell; 4]> = None;

                for block_index in 0..permutations {
                    let block = blocks_ref.map(|blocks| &blocks[block_index]);
                    let base = block_index * POSEIDON2_HALO2_PERMUTATION_ROWS;
                    let prev = if block_index == 0 {
                        PrevBinding::First([Fr::from(0u64), Fr::from(0u64), Fr::from(0u64), iv])
                    } else {
                        PrevBinding::Copied {
                            values: block.map(|block| block.prev),
                            cells: previous_output.ok_or(Error::Synthesis)?,
                        }
                    };

                    let assigned = assign_block(
                        &mut region,
                        &config,
                        base,
                        block.map(|block| block.input),
                        block.map(|block| block.trace.clone()),
                        prev,
                        block.map(|block| block.absorb),
                        true,
                        None,
                    )?;

                    // Bind absorbed inputs to the raw public input cells.
                    let absorbed = if block_index < full {
                        (block_index * POSEIDON2_HALO2_RATE, POSEIDON2_HALO2_RATE)
                    } else {
                        (full * POSEIDON2_HALO2_RATE, remainder)
                    };
                    for i in 0..absorbed.1 {
                        region.constrain_equal(assigned.absorb[i], raw_cells[absorbed.0 + i]);
                    }

                    previous_output = Some(assigned.state[POSEIDON2_HALO2_ROUNDS]);
                    digest_cells = Some(assigned.state[POSEIDON2_HALO2_ROUNDS]);
                }

                Ok((raw_cells, digest_cells.ok_or(Error::Synthesis)?))
            },
        )?;

        layouter.constrain_instance(digest_cells[0], config.instance, 0);
        for (index, cell) in raw_cells.iter().enumerate() {
            layouter.constrain_instance(*cell, config.instance, 1 + index);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_axiom::dev::MockProver;
    use halo2_axiom::halo2curves::ff::PrimeField as _;

    const HASH_K: u32 = 10;
    const PERMUTATION_K: u32 = 7;

    fn ark_inputs(inputs: &[Fr]) -> Vec<ark_bn254::Fr> {
        inputs.iter().map(|value| ark_fr(*value)).collect()
    }

    fn from_hex_be(hex: &str) -> Fr {
        assert_eq!(hex.len(), 64, "BN254 Fr hex length");
        let mut repr = [0u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let text = core::str::from_utf8(chunk).expect("ascii hex");
            let byte = u8::from_str_radix(text, 16).expect("hex byte");
            repr[31 - index] = byte;
        }
        Option::<Fr>::from(Fr::from_repr(repr)).expect("canonical BN254 Fr")
    }

    fn minimum_k(rows: usize) -> u32 {
        let mut cs = ConstraintSystem::<Fr>::default();
        let _ = Poseidon2HashCircuit::configure(&mut cs);
        let mut k = 1u32;
        loop {
            let n = 1usize << k;
            if n >= cs.minimum_rows() && rows <= n - (cs.blinding_factors() + 1) {
                return k;
            }
            k += 1;
        }
    }

    fn hash_prover(circuit: &Poseidon2HashCircuit, instance: Vec<Fr>, k: u32) -> MockProver<Fr> {
        MockProver::run(k, circuit, vec![instance]).expect("mock prover run")
    }

    fn permutation_prover(
        circuit: &Poseidon2PermutationCircuit,
        instance: Vec<Fr>,
    ) -> MockProver<Fr> {
        MockProver::run(PERMUTATION_K, circuit, vec![instance]).expect("mock prover run")
    }

    #[test]
    fn permutation_zeroes_kat_is_satisfied() {
        let input = [Fr::from(0u64); 4];
        let expected = [
            from_hex_be("18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
            from_hex_be("095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839"),
            from_hex_be("0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59"),
            from_hex_be("18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d"),
        ];
        assert_eq!(permutation_output(input), expected);

        let circuit = Poseidon2PermutationCircuit::new(input);
        let prover = permutation_prover(&circuit, permutation_public_inputs(input));
        prover.assert_satisfied();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn permutation_matches_vendored_ark_implementation() {
        for (index, input) in [
            [0u64, 0, 0, 0],
            [1, 2, 3, 4],
            [7, 8, 9, 10],
            [11, 12, 13, 14],
        ]
        .into_iter()
        .enumerate()
        {
            let input = input.map(Fr::from);
            let expected =
                crate::poseidon2::poseidon2_bn254_permute_impl(input.map(ark_fr)).map(halo_fr);
            assert_eq!(permutation_output(input), expected, "case {index}");
        }
    }

    #[test]
    fn permutation_rejects_tampered_output() {
        let input = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let expected = permutation_output(input);
        let tampered = Poseidon2PermutationCircuit {
            input: Value::known(input),
            tamper: Some(Tamper {
                row: POSEIDON2_HALO2_ROUNDS,
                column: 0,
                value: expected[0] + Fr::from(1u64),
            }),
            recompute_after_tamper: false,
            disabled_round: None,
        };
        let prover = permutation_prover(&tampered, permutation_public_inputs(input));
        assert!(prover.verify().is_err(), "tampered output was accepted");
    }

    #[test]
    fn every_round_is_constrained() {
        let input = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let base_trace = permutation_trace(input);

        for round in 0..POSEIDON2_HALO2_ROUNDS {
            let row = round + 1;
            let tampered_value = base_trace[row][0] + Fr::from(1u64);
            let tamper = Tamper {
                row,
                column: 0,
                value: tampered_value,
            };

            // The tampered row is propagated through the remaining rounds, so
            // every other round transition and the initial matrix stay
            // consistent. Only round `round` can reject this witness.
            let trace = self::tampered_trace(input, tamper);
            let mut instance = input.to_vec();
            instance.extend_from_slice(&trace[POSEIDON2_HALO2_ROUNDS]);

            let constrained = Poseidon2PermutationCircuit {
                input: Value::known(input),
                tamper: Some(tamper),
                recompute_after_tamper: true,
                disabled_round: None,
            };
            let prover = permutation_prover(&constrained, instance.clone());
            assert!(
                prover.verify().is_err(),
                "round {round} is not constrained by the gate"
            );

            // With that one round disabled, the recomputed trace satisfies all
            // remaining gates: this shows the rejection above came from the
            // round's selector/gate and not from a neighbour.
            let unconstrained = Poseidon2PermutationCircuit {
                input: Value::known(input),
                tamper: Some(tamper),
                recompute_after_tamper: true,
                disabled_round: Some(round),
            };
            let prover = permutation_prover(&unconstrained, instance);
            prover.assert_satisfied();
        }
    }

    fn tampered_trace(input: [Fr; 4], tamper: Tamper) -> Vec<[Fr; 4]> {
        let mut trace = permutation_trace(input);
        trace[tamper.row][tamper.column] = tamper.value;
        for round in tamper.row..POSEIDON2_HALO2_ROUNDS {
            trace[round + 1] = apply_round(trace[round], round);
        }
        trace
    }

    #[test]
    fn hash_output_never_panics_for_supported_arities() {
        // `hash_output` is a public, non-`Result` API used by `halo2_ipa.rs`,
        // so it must be total for every accepted input count. This also fixes
        // the sponge invariant `hash_permutation_count(n) >= 1`.
        for n in 0..=POSEIDON2_BN254_MAX_INPUTS {
            assert!(
                hash_permutation_count(n) >= 1,
                "sponge must perform at least one permutation for n = {n}"
            );
            let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            let digest = hash_output(&inputs);
            let expected = halo_fr(crate::poseidon2::poseidon2_bn254_hash_impl(&ark_inputs(
                &inputs,
            )));
            assert_eq!(digest, expected, "digest mismatch n = {n}");
        }
    }

    #[test]
    fn halo_fr_matches_canonical_representation_for_all_constants() {
        // `halo_fr` must be a value-preserving BN254 scalar conversion for the
        // whole constants table (all round constants and internal diagonals).
        let check = |value: ark_bn254::Fr| {
            let converted = halo_fr(value);
            // Independent round trips: back through the ark representation and
            // through the canonical little-endian byte decode used previously.
            assert_eq!(ark_fr(converted), value);
            let bytes = {
                use ark_ff::BigInteger;
                value.into_bigint().to_bytes_le()
            };
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&bytes[..32]);
            assert_eq!(Option::<Fr>::from(Fr::from_repr(repr)), Some(converted));
        };

        for diagonal in BN254_CONFIG.internal_matrix_diagonal.iter() {
            check(*diagonal);
        }
        for row in BN254_CONFIG.round_constant.iter() {
            for value in row.iter() {
                check(*value);
            }
        }
    }

    #[test]
    fn hash_kat_matches_native_for_supported_arities() {
        for n in [0usize, 1, 2, 3, 4, 6, 8, 9, 12] {
            let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            let expected = halo_fr(crate::poseidon2::poseidon2_bn254_hash_impl(&ark_inputs(
                &inputs,
            )));
            assert_eq!(hash_output(&inputs), expected, "helper n = {n}");

            let circuit = Poseidon2HashCircuit::new(&inputs);
            let instance = hash_public_inputs(&inputs);
            let k = minimum_k(hash_circuit_rows(n)).max(minimum_k(instance.len()));
            let prover = hash_prover(&circuit, instance, k);
            prover.assert_satisfied();
            assert!(prover.verify().is_ok(), "n = {n}");
        }
    }

    #[test]
    fn hash_circuit_rejects_wrong_public_digest() {
        for n in [0usize, 1, 3, 4, 6] {
            let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            let circuit = Poseidon2HashCircuit::new(&inputs);
            let mut instance = hash_public_inputs(&inputs);
            instance[0] += Fr::from(1u64);
            let k = minimum_k(hash_circuit_rows(n)).max(minimum_k(instance.len()));
            let prover = hash_prover(&circuit, instance, k);
            assert!(prover.verify().is_err(), "wrong digest accepted n = {n}");
        }
    }

    #[test]
    fn hash_changed_input_changes_digest() {
        for n in [1usize, 2, 3, 4, 6, 8, 9] {
            let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            let mut changed = inputs.clone();
            changed[0] += Fr::from(1u64);
            assert_ne!(
                hash_output(&inputs),
                hash_output(&changed),
                "digest collision n = {n}"
            );

            let k = minimum_k(hash_circuit_rows(n)).max(minimum_k(n + 1));

            // Old digest with the changed witness must be rejected.
            let circuit = Poseidon2HashCircuit::new(&changed);
            let prover = hash_prover(&circuit, hash_public_inputs(&inputs), k);
            assert!(
                prover.verify().is_err(),
                "changed input accepted old digest n = {n}"
            );

            // The same witness with its own digest is accepted.
            let prover = hash_prover(&circuit, hash_public_inputs(&changed), k);
            prover.assert_satisfied();
        }
    }

    #[test]
    fn hash_rejects_too_many_inputs() {
        let inputs: Vec<Fr> = (0..=POSEIDON2_BN254_MAX_INPUTS as u64)
            .map(Fr::from)
            .collect();
        let circuit = Poseidon2HashCircuit::new(&inputs);
        assert!(
            MockProver::run(HASH_K, &circuit, vec![vec![]]).is_err(),
            "hash circuit accepted more than the maximum input count"
        );
    }

    #[test]
    fn layout_report_and_minimum_k() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let _ = Poseidon2HashCircuit::configure(&mut cs);
        println!(
            "Poseidon2 gate: degree={} advice={} fixed={} selectors={} blinding={} minimum_rows={}",
            cs.degree(),
            cs.num_advice_columns(),
            cs.num_fixed_columns(),
            cs.num_selectors(),
            cs.blinding_factors(),
            cs.minimum_rows()
        );
        let usable = |k: u32| (1usize << k) - (cs.blinding_factors() + 1);
        let permutation_k = minimum_k(permutation_circuit_rows());
        println!(
            "permutation: rows={} minimum_k={} usable_rows={}",
            permutation_circuit_rows(),
            permutation_k,
            usable(permutation_k)
        );
        for n in [0usize, 1, 2, 3, 4, 6, 8, 9, 12] {
            let rows = hash_circuit_rows(n);
            let instance_rows = n + 1;
            let k = minimum_k(rows).max(minimum_k(instance_rows));
            println!(
                "hash n={n}: permutations={} rows={} instance_rows={} minimum_k={} usable_rows={}",
                hash_permutation_count(n),
                rows,
                instance_rows,
                k,
                usable(k)
            );
        }

        // Every supported arity fits in k = 10, the example's default.
        for n in 0..=POSEIDON2_BN254_MAX_INPUTS {
            assert!(minimum_k(hash_circuit_rows(n)) <= HASH_K);
        }
    }
}
