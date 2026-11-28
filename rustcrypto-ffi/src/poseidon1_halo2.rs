//! Halo2 custom gate for the Poseidon1/BN254 permutation and 3-input hash.
//!
//! # Scope
//!
//! This module constrains **every** Poseidon1 round (8 full + 56 partial) over
//! the BN254 scalar field `Fr` with a Halo2 custom gate. The constants, round
//! ordering and permutation framing are the Circom-compatible Poseidon1
//! parameters exposed by `light-poseidon 0.4.1`
//! (`parameters::bn254_x5::get_poseidon_parameters::<ark_bn254::Fr>(4)`).
//!
//! Unlike [`crate::poseidon2_halo2`], Poseidon1 has no length IV and no initial
//! MDS multiplication. The 3-input hash is
//!
//! ```text
//! state = [0, input0, input1, input2]
//! for each round: add ARK to all 4 lanes, S-box (all lanes for full rounds,
//! lane 0 only for partial rounds), multiply by the 4x4 MDS matrix
//! digest = state[0]
//! ```
//!
//! # Layout
//!
//! One permutation occupies 65 rows:
//!
//! ```text
//! row base + 0 : initial state [0, input0, input1, input2]
//! row base + r : round r transition, r = 0..63
//! row base + 64: final state (output)
//! ```
//!
//! `s_full` is enabled on rows `0..=3` and `60..=63`; `s_partial` on rows
//! `4..=59`. Round constants live in four fixed columns (part of the verifying
//! key), and the 4x4 MDS matrix is embedded as gate constants, so neither is
//! prover-controlled.
//!
//! # Security notes
//!
//! This is a comparison/demo circuit, not an audited generic Halo2 frontend.
//! It has no C ABI / Nim registration and no wasm/ICP execution surface. See
//! `docs/poseidon1-halo2-gate.md`.

use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use halo2_axiom::circuit::{Cell, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::halo2curves::ff::PrimeField as HaloPrimeField;
use halo2_axiom::plonk::{
    Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance,
    Selector,
};
use halo2_axiom::poly::Rotation;
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use std::sync::OnceLock;

/// Poseidon1 state width constrained by the gate.
pub const POSEIDON1_HALO2_WIDTH: usize = 4;
/// Number of Poseidon1 rounds (R_F + R_P) constrained by the gate.
pub const POSEIDON1_HALO2_ROUNDS: usize = 64;
/// Number of full rounds.
pub const POSEIDON1_HALO2_FULL_ROUNDS: usize = 8;
/// Number of partial rounds.
pub const POSEIDON1_HALO2_PARTIAL_ROUNDS: usize = 56;
/// Number of inputs supported by [`Poseidon1HashCircuit`].
pub const POSEIDON1_HALO2_INPUTS: usize = 3;
/// Rows occupied by one permutation (`ROUNDS + 1`).
pub const POSEIDON1_HALO2_PERMUTATION_ROWS: usize = POSEIDON1_HALO2_ROUNDS + 1;
/// Instance length for the hash circuit: `[digest, input0, input1, input2]`.
pub const POSEIDON1_HALO2_PUBLIC_INPUTS: usize = POSEIDON1_HALO2_INPUTS + 1;

const RF_FIRST: usize = POSEIDON1_HALO2_FULL_ROUNDS / 2;
const P_END: usize = RF_FIRST + POSEIDON1_HALO2_PARTIAL_ROUNDS;

/// The `light-poseidon` constants are `ark_bn254::Fr`; the gate lives in
/// `halo2_axiom`'s `Fr`. Both are BN254's scalar field, so the canonical
/// little-endian representation is converted byte-for-byte.
fn halo_fr(value: ark_bn254::Fr) -> Fr {
    let bytes = value.into_bigint().to_bytes_le();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[..32]);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("BN254 scalar field")
}

/// Inverse of [`halo_fr`], used by tests to compare against `light-poseidon`.
#[cfg(test)]
fn ark_fr(value: Fr) -> ark_bn254::Fr {
    ark_bn254::Fr::from_le_bytes_mod_order(value.to_repr().as_ref())
}

struct Poseidon1Parameters {
    ark: Vec<Fr>,
    mds: [[Fr; 4]; 4],
}

/// Circom-compatible BN254/x^5 parameters for width 4 (`light-poseidon`).
fn parameters() -> &'static Poseidon1Parameters {
    static PARAMETERS: OnceLock<Poseidon1Parameters> = OnceLock::new();
    PARAMETERS.get_or_init(|| {
        let params = get_poseidon_parameters::<ark_bn254::Fr>(4)
            .expect("light-poseidon BN254/x^5 width-4 parameters");
        assert_eq!(params.width, POSEIDON1_HALO2_WIDTH);
        assert_eq!(params.full_rounds, POSEIDON1_HALO2_FULL_ROUNDS);
        assert_eq!(params.partial_rounds, POSEIDON1_HALO2_PARTIAL_ROUNDS);
        assert_eq!(params.alpha, 5);
        let ark = params.ark.iter().copied().map(halo_fr).collect();
        let mds = core::array::from_fn(|i| core::array::from_fn(|j| halo_fr(params.mds[i][j])));
        Poseidon1Parameters { ark, mds }
    })
}

#[inline(always)]
fn mds_constant(row: usize, column: usize) -> Fr {
    parameters().mds[row][column]
}

#[inline(always)]
fn round_constant(round: usize, index: usize) -> Fr {
    parameters().ark[round * POSEIDON1_HALO2_WIDTH + index]
}

#[inline(always)]
fn is_full_round(round: usize) -> bool {
    round < RF_FIRST || round >= P_END
}

/// Number of rows used by [`Poseidon1HashCircuit`] (one permutation).
pub fn hash_circuit_rows() -> usize {
    POSEIDON1_HALO2_PERMUTATION_ROWS
}

/// Alias for the fixed permutation row count.
pub fn permutation_circuit_rows() -> usize {
    POSEIDON1_HALO2_PERMUTATION_ROWS
}

#[inline(always)]
fn s_box(value: Fr) -> Fr {
    let squared = value * value;
    squared * squared * value
}

fn mds_mul(state: [Fr; 4]) -> [Fr; 4] {
    core::array::from_fn(|i| {
        let mut acc = Fr::from(0u64);
        for j in 0..POSEIDON1_HALO2_WIDTH {
            acc += mds_constant(i, j) * state[j];
        }
        acc
    })
}

fn add_round_constants(state: [Fr; 4], round: usize) -> [Fr; 4] {
    core::array::from_fn(|i| state[i] + round_constant(round, i))
}

fn apply_round(state: [Fr; 4], round: usize) -> [Fr; 4] {
    let u = add_round_constants(state, round);
    let s_boxed = if is_full_round(round) {
        u.map(s_box)
    } else {
        // Partial round: only lane 0 is S-boxed; the other lanes keep the
        // ARK-added value.
        [s_box(u[0]), u[1], u[2], u[3]]
    };
    mds_mul(s_boxed)
}

/// Computes the 65-row trace: row 0 is `[0, input0, input1, input2]`, row
/// `r + 1` is the state after round `r`, and row 64 is the output state.
fn permutation_trace(inputs: [Fr; POSEIDON1_HALO2_INPUTS]) -> Vec<[Fr; 4]> {
    let mut trace = Vec::with_capacity(POSEIDON1_HALO2_PERMUTATION_ROWS);
    let mut state = [Fr::from(0u64), inputs[0], inputs[1], inputs[2]];
    trace.push(state);
    for round in 0..POSEIDON1_HALO2_ROUNDS {
        state = apply_round(state, round);
        trace.push(state);
    }
    trace
}

/// Expected Circom-compatible Poseidon1 digest for 3 inputs.
pub fn hash_output(inputs: &[Fr]) -> Fr {
    assert_eq!(
        inputs.len(),
        POSEIDON1_HALO2_INPUTS,
        "Poseidon1 Halo2 circuit supports exactly 3 inputs"
    );
    permutation_trace([inputs[0], inputs[1], inputs[2]])[POSEIDON1_HALO2_ROUNDS][0]
}

/// Instance values bound by [`Poseidon1HashCircuit`]:
/// `[digest, input0, input1, input2]`.
pub fn hash_public_inputs(inputs: &[Fr]) -> Vec<Fr> {
    assert_eq!(
        inputs.len(),
        POSEIDON1_HALO2_INPUTS,
        "Poseidon1 Halo2 circuit supports exactly 3 inputs"
    );
    let mut values = Vec::with_capacity(POSEIDON1_HALO2_PUBLIC_INPUTS);
    values.push(hash_output(inputs));
    values.extend_from_slice(inputs);
    values
}

// ---------------------------------------------------------------------------
// Gate expressions
// ---------------------------------------------------------------------------

/// `MDS * vector` as a linear combination. MDS entries are gate constants
/// (not witness cells), so the prover cannot change the linear layer.
fn mds_mul_expr(vector: [Expression<Fr>; 4]) -> [Expression<Fr>; 4] {
    core::array::from_fn(|i| {
        let mut acc = Expression::Constant(mds_constant(i, 0)) * vector[0].clone();
        for j in 1..POSEIDON1_HALO2_WIDTH {
            acc = acc + Expression::Constant(mds_constant(i, j)) * vector[j].clone();
        }
        acc
    })
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration used by [`Poseidon1HashCircuit`].
#[derive(Clone, Debug)]
pub struct Poseidon1Halo2Config {
    state: [Column<Advice>; 4],
    /// `(state + RC)^2` for each state element on a round row.
    pow2: [Column<Advice>; 4],
    /// `(state + RC)^5` for each state element on a round row.
    pow5: [Column<Advice>; 4],
    round_constant: [Column<Fixed>; 4],
    instance: Column<Instance>,
    s_init: Selector,
    s_round: Selector,
    s_full: Selector,
    s_partial: Selector,
}

fn configure_poseidon1(meta: &mut ConstraintSystem<Fr>) -> Poseidon1Halo2Config {
    let state_columns = core::array::from_fn(|_| meta.advice_column());
    let pow2_columns = core::array::from_fn(|_| meta.advice_column());
    let pow5_columns = core::array::from_fn(|_| meta.advice_column());
    let round_constant_columns = core::array::from_fn(|_| meta.fixed_column());
    let instance = meta.instance_column();

    for column in state_columns
        .iter()
        .chain(pow2_columns.iter())
        .chain(pow5_columns.iter())
    {
        meta.enable_equality(*column);
    }
    meta.enable_equality(instance);

    let s_init = meta.selector();
    let s_round = meta.selector();
    let s_full = meta.selector();
    let s_partial = meta.selector();

    // row0 lane 0 is the fixed zero of the Circom-compatible state.
    meta.create_gate("poseidon1 initial zero lane", |meta| {
        let enabled = meta.query_selector(s_init);
        let state0 = meta.query_advice(state_columns[0], Rotation::cur());
        vec![enabled * state0]
    });

    // S-box low-degree decomposition: pow2 = u^2, pow5 = pow2^2 * u.
    // Splitting the degree-5 S-box keeps every gate within the vendored
    // halo2 `MAX_DEGREE` cap (default 5).
    meta.create_gate("poseidon1 s-box square", |meta| {
        let enabled = meta.query_selector(s_round);
        let constraints: Vec<Expression<Fr>> = (0..POSEIDON1_HALO2_WIDTH)
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

    meta.create_gate("poseidon1 s-box fifth power", |meta| {
        let enabled = meta.query_selector(s_round);
        let constraints: Vec<Expression<Fr>> = (0..POSEIDON1_HALO2_WIDTH)
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

    // Full round: next[i] == MDS * ((state + RC)^5).
    meta.create_gate("poseidon1 full round", |meta| {
        let enabled = meta.query_selector(s_full);
        let next: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(state_columns[i], Rotation::next()));
        let s_boxed: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(pow5_columns[i], Rotation::cur()));
        let mixed = mds_mul_expr(s_boxed);
        let constraints: Vec<Expression<Fr>> = (0..POSEIDON1_HALO2_WIDTH)
            .map(|i| enabled.clone() * (next[i].clone() - mixed[i].clone()))
            .collect();
        constraints
    });

    // Partial round: only lane 0 is S-boxed, then MDS is applied to
    // [(state0 + RC0)^5, state1 + RC1, state2 + RC2, state3 + RC3].
    meta.create_gate("poseidon1 partial round", |meta| {
        let enabled = meta.query_selector(s_partial);
        let next: [Expression<Fr>; 4] =
            core::array::from_fn(|i| meta.query_advice(state_columns[i], Rotation::next()));
        let b0 = meta.query_advice(pow5_columns[0], Rotation::cur());
        let b: [Expression<Fr>; 4] = core::array::from_fn(|i| {
            if i == 0 {
                b0.clone()
            } else {
                let state = meta.query_advice(state_columns[i], Rotation::cur());
                let round_constant = meta.query_fixed(round_constant_columns[i], Rotation::cur());
                state + round_constant
            }
        });
        let mixed = mds_mul_expr(b);
        let constraints: Vec<Expression<Fr>> = (0..POSEIDON1_HALO2_WIDTH)
            .map(|i| enabled.clone() * (next[i].clone() - mixed[i].clone()))
            .collect();
        constraints
    });

    Poseidon1Halo2Config {
        state: state_columns,
        pow2: pow2_columns,
        pow5: pow5_columns,
        round_constant: round_constant_columns,
        instance,
        s_init,
        s_round,
        s_full,
        s_partial,
    }
}

// ---------------------------------------------------------------------------
// Witness assignment
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Tamper {
    row: usize,
    column: usize,
    value: Fr,
}

/// `(u^2, u^5)` for `u = state + RC` on a round row. Row 64 (the final state)
/// gets zeros; `s_round` is disabled there.
fn round_powers(trace: &[[Fr; 4]], row: usize) -> ([Fr; 4], [Fr; 4]) {
    let mut pow2 = [Fr::from(0u64); 4];
    let mut pow5 = [Fr::from(0u64); 4];
    if row < POSEIDON1_HALO2_ROUNDS {
        for index in 0..POSEIDON1_HALO2_WIDTH {
            let u = trace[row][index] + round_constant(row, index);
            pow2[index] = u * u;
            pow5[index] = pow2[index] * pow2[index] * u;
        }
    }
    (pow2, pow5)
}

#[allow(clippy::too_many_arguments)]
fn assign_permutation(
    region: &mut Region<'_, Fr>,
    config: &Poseidon1Halo2Config,
    base: usize,
    trace: Value<Vec<[Fr; 4]>>,
    disabled_round: Option<usize>,
) -> Result<Vec<[Cell; 4]>, Error> {
    // Per-round constants as fixed columns (part of the verifying key).
    for round in 0..POSEIDON1_HALO2_ROUNDS {
        for (index, column) in config.round_constant.iter().enumerate() {
            region.assign_fixed(*column, base + round, round_constant(round, index));
        }
    }

    config.s_init.enable(region, base)?;
    for round in 0..POSEIDON1_HALO2_ROUNDS {
        if disabled_round == Some(round) {
            continue;
        }
        config.s_round.enable(region, base + round)?;
        if is_full_round(round) {
            config.s_full.enable(region, base + round)?;
        } else {
            config.s_partial.enable(region, base + round)?;
        }
    }

    let trace = trace.as_ref();
    let mut state_cells = Vec::with_capacity(POSEIDON1_HALO2_PERMUTATION_ROWS);
    for row in 0..POSEIDON1_HALO2_PERMUTATION_ROWS {
        let power = trace.map(|trace| round_powers(trace, row));
        let pow2 = power.map(|(pow2, _)| pow2);
        let pow5 = power.map(|(_, pow5)| pow5);
        let cells = core::array::from_fn(|i| {
            let value = trace.map(|trace| trace[row][i]);
            region
                .assign_advice(config.state[i], base + row, value.map(Assigned::from))
                .cell()
        });
        for i in 0..POSEIDON1_HALO2_WIDTH {
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

    Ok(state_cells)
}

// ---------------------------------------------------------------------------
// Hash circuit
// ---------------------------------------------------------------------------

/// Halo2 circuit constraining the 3-input Circom-compatible Poseidon1 hash.
///
/// Instance column (4 rows): `[digest, input0, input1, input2]`.
#[derive(Clone, Debug)]
pub struct Poseidon1HashCircuit {
    inputs: [Value<Fr>; POSEIDON1_HALO2_INPUTS],
    tamper: Option<Tamper>,
    recompute_after_tamper: bool,
    disabled_round: Option<usize>,
}

impl Poseidon1HashCircuit {
    /// Builds a circuit for three known field inputs.
    pub fn new(inputs: &[Fr; POSEIDON1_HALO2_INPUTS]) -> Self {
        Self {
            inputs: inputs.map(Value::known),
            tamper: None,
            recompute_after_tamper: false,
            disabled_round: None,
        }
    }
}

impl Default for Poseidon1HashCircuit {
    fn default() -> Self {
        Self {
            inputs: core::array::from_fn(|_| Value::unknown()),
            tamper: None,
            recompute_after_tamper: false,
            disabled_round: None,
        }
    }
}

impl Circuit<Fr> for Poseidon1HashCircuit {
    type Config = Poseidon1Halo2Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: core::array::from_fn(|_| Value::unknown()),
            tamper: None,
            recompute_after_tamper: self.recompute_after_tamper,
            disabled_round: self.disabled_round,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        configure_poseidon1(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let tamper = self.tamper;
        let recompute = self.recompute_after_tamper;
        let trace = self.inputs[0].zip(self.inputs[1]).zip(self.inputs[2]).map(
            |((input0, input1), input2)| {
                let mut trace = permutation_trace([input0, input1, input2]);
                if let Some(tamper) = tamper {
                    if tamper.row < POSEIDON1_HALO2_PERMUTATION_ROWS {
                        trace[tamper.row][tamper.column] = tamper.value;
                        if recompute {
                            for round in tamper.row..POSEIDON1_HALO2_ROUNDS {
                                trace[round + 1] = apply_round(trace[round], round);
                            }
                        }
                    }
                }
                trace
            },
        );

        let state_cells = layouter.assign_region(
            || "poseidon1 hash",
            |mut region| assign_permutation(&mut region, &config, 0, trace, self.disabled_round),
        )?;

        // Instance: [digest, input0, input1, input2].
        for i in 0..POSEIDON1_HALO2_INPUTS {
            layouter.constrain_instance(state_cells[0][i + 1], config.instance, i + 1);
        }
        layouter.constrain_instance(state_cells[POSEIDON1_HALO2_ROUNDS][0], config.instance, 0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_axiom::dev::MockProver;
    use light_poseidon::{Poseidon, PoseidonHasher};

    const HASH_K: u32 = 10;

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
        let _ = Poseidon1HashCircuit::configure(&mut cs);
        let mut k = 1u32;
        loop {
            let n = 1usize << k;
            if n >= cs.minimum_rows() && rows <= n - (cs.blinding_factors() + 1) {
                return k;
            }
            k += 1;
        }
    }

    fn hash_prover(circuit: &Poseidon1HashCircuit, instance: Vec<Fr>, k: u32) -> MockProver<Fr> {
        MockProver::run(k, circuit, vec![instance]).expect("mock prover run")
    }

    fn expected_light_poseidon(inputs: &[Fr]) -> Fr {
        let mut poseidon = Poseidon::<ark_bn254::Fr>::new_circom(POSEIDON1_HALO2_INPUTS)
            .expect("Poseidon1 params");
        halo_fr(poseidon.hash(&ark_inputs(inputs)).expect("Poseidon1 hash"))
    }

    fn tampered_trace(inputs: [Fr; 3], tamper: Tamper) -> Vec<[Fr; 4]> {
        let mut trace = permutation_trace(inputs);
        trace[tamper.row][tamper.column] = tamper.value;
        for round in tamper.row..POSEIDON1_HALO2_ROUNDS {
            trace[round + 1] = apply_round(trace[round], round);
        }
        trace
    }

    #[test]
    fn hash_kat_matches_light_poseidon() {
        // KAT from `Poseidon::<ark_bn254::Fr>::new_circom(3)`.
        let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let expected =
            from_hex_be("0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732");
        let light = expected_light_poseidon(&inputs);
        assert_eq!(light, expected, "KAT constant drifted from light-poseidon");
        assert_eq!(hash_output(&inputs), light);

        let circuit = Poseidon1HashCircuit::new(&inputs);
        let instance = hash_public_inputs(&inputs);
        assert_eq!(instance[0], expected);
        let prover = hash_prover(&circuit, instance, HASH_K);
        prover.assert_satisfied();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn hash_matches_light_poseidon_for_multiple_triples() {
        let cases: [[u64; 3]; 8] = [
            [0, 0, 0],
            [1, 0, 0],
            [0, 1, 0],
            [0, 0, 1],
            [1, 2, 3],
            [7, 8, 9],
            [42, 43, 44],
            [1_000_000, 2_000_000, 3_000_000],
        ];

        for inputs in cases {
            let inputs = inputs.map(Fr::from);
            let expected = expected_light_poseidon(&inputs);
            assert_eq!(hash_output(&inputs), expected, "native hash {inputs:?}");

            let circuit = Poseidon1HashCircuit::new(&inputs);
            let instance = hash_public_inputs(&inputs);
            let prover = hash_prover(&circuit, instance, HASH_K);
            prover.assert_satisfied();
            assert!(prover.verify().is_ok(), "mock prover {inputs:?}");
        }
    }

    #[test]
    fn hash_circuit_rejects_wrong_public_digest() {
        let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let circuit = Poseidon1HashCircuit::new(&inputs);
        let mut instance = hash_public_inputs(&inputs);
        instance[0] += Fr::from(1u64);
        let prover = hash_prover(&circuit, instance, HASH_K);
        assert!(prover.verify().is_err(), "wrong digest was accepted");
    }

    #[test]
    fn hash_circuit_rejects_tampered_output_and_witness() {
        let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let expected = hash_output(&inputs);

        // Tampered output row, correct public digest: both the final round
        // gate and the instance binding reject it.
        let tampered_output = Poseidon1HashCircuit {
            inputs: inputs.map(Value::known),
            tamper: Some(Tamper {
                row: POSEIDON1_HALO2_ROUNDS,
                column: 0,
                value: expected + Fr::from(1u64),
            }),
            recompute_after_tamper: false,
            disabled_round: None,
        };
        let prover = hash_prover(&tampered_output, hash_public_inputs(&inputs), HASH_K);
        assert!(prover.verify().is_err(), "tampered output was accepted");

        // Tampered intermediate witness, correct digest.
        let tampered_witness = Poseidon1HashCircuit {
            inputs: inputs.map(Value::known),
            tamper: Some(Tamper {
                row: 20,
                column: 2,
                value: Fr::from(123456u64),
            }),
            recompute_after_tamper: false,
            disabled_round: None,
        };
        let prover = hash_prover(&tampered_witness, hash_public_inputs(&inputs), HASH_K);
        assert!(prover.verify().is_err(), "tampered witness was accepted");
    }

    #[test]
    fn hash_changed_input_changes_digest() {
        let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let mut changed = inputs;
        changed[0] += Fr::from(1u64);
        assert_ne!(hash_output(&inputs), hash_output(&changed));

        let circuit = Poseidon1HashCircuit::new(&changed);
        let prover = hash_prover(&circuit, hash_public_inputs(&inputs), HASH_K);
        assert!(
            prover.verify().is_err(),
            "changed input accepted the old digest"
        );

        let prover = hash_prover(&circuit, hash_public_inputs(&changed), HASH_K);
        prover.assert_satisfied();
    }

    #[test]
    fn every_round_is_constrained() {
        let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let base_trace = permutation_trace(inputs);

        for round in 0..POSEIDON1_HALO2_ROUNDS {
            let row = round + 1;
            let tamper = Tamper {
                row,
                column: 0,
                value: base_trace[row][0] + Fr::from(1u64),
            };

            // Recompute the rest of the trace so only the transition into
            // `row` is inconsistent. The final instance uses the recomputed
            // digest, so the failure must come from round `round`'s gate.
            let trace = tampered_trace(inputs, tamper);
            let mut instance = inputs.to_vec();
            instance.insert(0, trace[POSEIDON1_HALO2_ROUNDS][0]);

            let constrained = Poseidon1HashCircuit {
                inputs: inputs.map(Value::known),
                tamper: Some(tamper),
                recompute_after_tamper: true,
                disabled_round: None,
            };
            let prover = hash_prover(&constrained, instance.clone(), HASH_K);
            assert!(
                prover.verify().is_err(),
                "round {round} is not constrained by the gate"
            );

            // Disabling only that round's selector accepts the same witness,
            // proving the rejection above came from this round.
            let unconstrained = Poseidon1HashCircuit {
                inputs: inputs.map(Value::known),
                tamper: Some(tamper),
                recompute_after_tamper: true,
                disabled_round: Some(round),
            };
            let prover = hash_prover(&unconstrained, instance, HASH_K);
            prover.assert_satisfied();
        }
    }

    #[test]
    fn layout_report_and_minimum_k() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let _ = Poseidon1HashCircuit::configure(&mut cs);
        let k = minimum_k(hash_circuit_rows());
        println!(
            "Poseidon1 gate: degree={} advice={} fixed={} selectors={} blinding={} minimum_rows={}",
            cs.degree(),
            cs.num_advice_columns(),
            cs.num_fixed_columns(),
            cs.num_selectors(),
            cs.blinding_factors(),
            cs.minimum_rows()
        );
        println!(
            "hash: rows={} instance_rows={} minimum_k={} usable_rows={}",
            hash_circuit_rows(),
            POSEIDON1_HALO2_PUBLIC_INPUTS,
            k,
            (1usize << k) - (cs.blinding_factors() + 1)
        );
        assert!(k <= HASH_K, "3-input hash must fit the example's k = 10");
    }
}
