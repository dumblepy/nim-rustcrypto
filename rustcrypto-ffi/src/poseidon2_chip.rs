//! Reusable Halo2 gadgets and a composite sample circuit built on
//! [`crate::poseidon2_halo2::Poseidon2Chip`].
//!
//! # Scope
//!
//! This module provides a small, dependency-free set of Halo2 gadgets:
//!
//! - boolean constraint ([`GadgetConfig::assign_boolean`],
//!   [`GadgetConfig::constrain_boolean`]),
//! - conditional select `out = cond ? a : b`
//!   ([`GadgetConfig::select`]),
//! - equality / zero test based on the standard inverse witness
//!   ([`GadgetConfig::is_equal`], [`GadgetConfig::is_zero`]),
//! - nonzero check ([`GadgetConfig::assert_nonzero`]),
//! - field addition ([`GadgetConfig::add`]),
//! - `u64` / `u128` range checks by bit decomposition
//!   ([`GadgetConfig::range_check_u64`],
//!   [`GadgetConfig::range_check_u128`]),
//! - a copy-binding helper ([`GadgetConfig::copy`]).
//!
//! [`GadgetConfig::configure`] only adds its own advice/fixed columns and
//! selectors, so it can be called in the same [`ConstraintSystem`] as
//! [`crate::poseidon2_halo2::Poseidon2Chip::configure`].
//!
//! The composite sample [`Poseidon2MerkleCircuit`] keeps the leaf, the
//! siblings and the direction bits private and exposes only the final Merkle
//! root via the instance column. [`Poseidon2U128ExampleCircuit`] demonstrates
//! the range/boolean/select/add/equality gadgets with secret `u128` values.
//!
//! # Security notes
//!
//! - Every bit produced or consumed by a gadget is boolean-constrained by a
//!   gate (`b * (1 - b) = 0`).
//! - The range check binds the bit decomposition to the checked value with a
//!   running accumulator gate and a copy constraint. A prover cannot choose
//!   bits whose weighted sum differs from the value, so field elements
//!   `>= 2^n` are rejected (including the field wraparound case `-1`).
//! - The zero test uses `diff * inv = 1 - is_zero` together with
//!   `is_zero * diff = 0` and a boolean `is_zero`, which is sound for both
//!   `diff == 0` and `diff != 0`.
//! - Caller-provided [`GadgetValue`] cells must live in columns with equality
//!   enabled (all cells produced by [`Poseidon2Chip`] and by this module are).
//! - This is a demonstration frontend, not an audited generic gadget library.
//!
//! # Regions and the vendored floor planner
//!
//! The vendored `halo2-axiom` `SimpleFloorPlanner` places every
//! `assign_region` call at row 0 and does not pack regions. Circuits in this
//! module therefore place all levels/instructions in a single region using
//! explicit absolute offsets (the same pattern as `poseidon2_halo2.rs`), which
//! also makes the layout independent of the witnesses.

use crate::poseidon2_halo2::{
    POSEIDON2_HALO2_PERMUTATION_ROWS, Poseidon2Chip, Poseidon2Halo2Config, Poseidon2Input,
    hash_output,
};
use halo2_axiom::circuit::{Cell, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::halo2curves::ff::{Field as _, PrimeField as _};
use halo2_axiom::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
};
use halo2_axiom::poly::Rotation;

/// Number of bits checked by [`GadgetConfig::range_check_u64`].
pub const U64_RANGE_BITS: usize = 64;
/// Number of bits checked by [`GadgetConfig::range_check_u128`].
pub const U128_RANGE_BITS: usize = 128;
/// Recommended minimum Merkle depth for the composite sample circuit.
pub const MERKLE_RECOMMENDED_MIN_DEPTH: usize = 4;

#[inline(always)]
fn one() -> Expression<Fr> {
    Expression::Constant(Fr::from(1u64))
}

#[inline(always)]
fn zero_value() -> Value<Fr> {
    Value::known(Fr::from(0u64))
}

/// `2^index` as a field element.
fn power_of_two(index: usize) -> Fr {
    let two_pow_64 = Fr::from(1u64 << 32) * Fr::from(1u64 << 32);
    if index < 64 {
        Fr::from(1u64 << index)
    } else if index < 128 {
        // `index - 64 < 64`, so the shift is always defined.
        two_pow_64 * Fr::from(1u64 << (index - 64))
    } else {
        // Only used by tests for `2^128`; doubling keeps this panic-free.
        let mut value = two_pow_64 * two_pow_64;
        for _ in 128..index {
            value = value + value;
        }
        value
    }
}

/// Bit `index` of the canonical little-endian representation of `value`.
///
/// Bits at or beyond the modulus width read as zero, so this never panics.
fn field_bit(value: Fr, index: usize) -> Fr {
    let repr = value.to_repr();
    let bytes = repr.as_ref();
    let byte = bytes.get(index / 8).copied().unwrap_or(0);
    if (byte >> (index % 8)) & 1 == 1 {
        Fr::from(1u64)
    } else {
        Fr::from(0u64)
    }
}

/// A cell together with the value assigned to it.
///
/// The pair mirrors [`Poseidon2Input`]: gadgets copy [`cell`](Self::cell) into
/// their own columns and assign [`value`](Self::value), keeping the witness and
/// the copy constraint in sync. During key generation `value` is
/// [`Value::unknown()`].
#[derive(Clone, Copy, Debug)]
pub struct GadgetValue {
    /// Caller-owned cell. Its column must have equality enabled.
    pub cell: Cell,
    /// Value assigned to `cell`.
    pub value: Value<Fr>,
}

/// Configuration for the small reusable gadgets in this module.
///
/// All columns created here have equality enabled. The config can coexist with
/// [`Poseidon2Halo2Config`] in the same constraint system.
#[derive(Clone, Debug)]
pub struct GadgetConfig {
    bit: Column<Advice>,
    select_cond: Column<Advice>,
    select_a: Column<Advice>,
    select_b: Column<Advice>,
    select_out: Column<Advice>,
    eq_a: Column<Advice>,
    eq_b: Column<Advice>,
    eq_diff: Column<Advice>,
    eq_inv: Column<Advice>,
    eq_out: Column<Advice>,
    add_a: Column<Advice>,
    add_b: Column<Advice>,
    add_out: Column<Advice>,
    range_value: Column<Advice>,
    range_acc: Column<Advice>,
    aux: Column<Advice>,
    range_coeff: Column<Fixed>,
    s_bool: Selector,
    s_select: Selector,
    s_eq: Selector,
    s_add: Selector,
    s_range: Selector,
}

fn configure_gadgets(meta: &mut ConstraintSystem<Fr>) -> GadgetConfig {
    let bit = meta.advice_column();
    let select_cond = meta.advice_column();
    let select_a = meta.advice_column();
    let select_b = meta.advice_column();
    let select_out = meta.advice_column();
    let eq_a = meta.advice_column();
    let eq_b = meta.advice_column();
    let eq_diff = meta.advice_column();
    let eq_inv = meta.advice_column();
    let eq_out = meta.advice_column();
    let add_a = meta.advice_column();
    let add_b = meta.advice_column();
    let add_out = meta.advice_column();
    let range_value = meta.advice_column();
    let range_acc = meta.advice_column();
    let aux = meta.advice_column();
    let range_coeff = meta.fixed_column();

    let constants = meta.fixed_column();
    meta.enable_constant(constants);

    for column in [
        bit,
        select_cond,
        select_a,
        select_b,
        select_out,
        eq_a,
        eq_b,
        eq_diff,
        eq_inv,
        eq_out,
        add_a,
        add_b,
        add_out,
        range_value,
        range_acc,
        aux,
    ] {
        meta.enable_equality(column);
    }

    let s_bool = meta.selector();
    let s_select = meta.selector();
    let s_eq = meta.selector();
    let s_add = meta.selector();
    let s_range = meta.selector();

    // b * (1 - b) = 0
    meta.create_gate("gadget boolean", |meta| {
        let enabled = meta.query_selector(s_bool);
        let bit = meta.query_advice(bit, Rotation::cur());
        vec![enabled * bit.clone() * (one() - bit)]
    });

    // out = b + cond * (a - b), with cond constrained to {0, 1}.
    meta.create_gate("gadget select", |meta| {
        let enabled = meta.query_selector(s_select);
        let cond = meta.query_advice(select_cond, Rotation::cur());
        let a = meta.query_advice(select_a, Rotation::cur());
        let b = meta.query_advice(select_b, Rotation::cur());
        let out = meta.query_advice(select_out, Rotation::cur());
        let value = b.clone() + cond.clone() * (a - b);
        vec![
            enabled.clone() * (out - value),
            enabled * cond.clone() * (one() - cond),
        ]
    });

    // Sound inverse-based zero test:
    //   diff = a - b
    //   diff * inv = 1 - out
    //   out * diff = 0
    //   out * (1 - out) = 0
    meta.create_gate("gadget equality", |meta| {
        let enabled = meta.query_selector(s_eq);
        let a = meta.query_advice(eq_a, Rotation::cur());
        let b = meta.query_advice(eq_b, Rotation::cur());
        let diff = meta.query_advice(eq_diff, Rotation::cur());
        let inv = meta.query_advice(eq_inv, Rotation::cur());
        let out = meta.query_advice(eq_out, Rotation::cur());
        vec![
            enabled.clone() * (diff.clone() - (a - b)),
            enabled.clone() * (diff.clone() * inv + out.clone() - one()),
            enabled.clone() * (out.clone() * diff),
            enabled * (out.clone() * (one() - out)),
        ]
    });

    // out = a + b
    meta.create_gate("gadget add", |meta| {
        let enabled = meta.query_selector(s_add);
        let a = meta.query_advice(add_a, Rotation::cur());
        let b = meta.query_advice(add_b, Rotation::cur());
        let out = meta.query_advice(add_out, Rotation::cur());
        vec![enabled * (out - a - b)]
    });

    // acc_next = acc_cur + bit * 2^row_index
    meta.create_gate("gadget range accumulator", |meta| {
        let enabled = meta.query_selector(s_range);
        let acc_cur = meta.query_advice(range_acc, Rotation::cur());
        let acc_next = meta.query_advice(range_acc, Rotation::next());
        let bit = meta.query_advice(bit, Rotation::cur());
        let coeff = meta.query_fixed(range_coeff, Rotation::cur());
        vec![enabled * (acc_next - acc_cur - bit * coeff)]
    });

    GadgetConfig {
        bit,
        select_cond,
        select_a,
        select_b,
        select_out,
        eq_a,
        eq_b,
        eq_diff,
        eq_inv,
        eq_out,
        add_a,
        add_b,
        add_out,
        range_value,
        range_acc,
        aux,
        range_coeff,
        s_bool,
        s_select,
        s_eq,
        s_add,
        s_range,
    }
}

impl GadgetConfig {
    /// Configures the gadget columns, fixed columns and selectors.
    ///
    /// May be called in the same [`ConstraintSystem`] as
    /// [`Poseidon2Chip::configure`].
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        configure_gadgets(meta)
    }

    /// Assigns a secret value into an auxiliary advice cell without adding a
    /// gate. The cell has equality enabled, so it can be copied later.
    pub fn assign_value(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        value: Value<Fr>,
    ) -> Result<GadgetValue, Error> {
        let cell = region.assign_advice(self.aux, offset, value).cell();
        Ok(GadgetValue { cell, value })
    }

    /// Copies `input` into an auxiliary advice cell and returns the copy.
    pub fn copy(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        input: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        let copy = self.assign_value(region, offset, input.value)?;
        region.constrain_equal(copy.cell, input.cell);
        Ok(copy)
    }

    /// Assigns a fresh boolean witness and constrains it to `{0, 1}`.
    pub fn assign_boolean(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        value: Value<Fr>,
    ) -> Result<GadgetValue, Error> {
        let cell = region.assign_advice(self.bit, offset, value).cell();
        self.s_bool.enable(region, offset)?;
        Ok(GadgetValue { cell, value })
    }

    /// Copies `input` into the boolean column and constrains it to `{0, 1}`.
    pub fn constrain_boolean(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        input: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        let out = self.assign_boolean(region, offset, input.value)?;
        region.constrain_equal(out.cell, input.cell);
        Ok(out)
    }

    /// The constant zero as a [`GadgetValue`].
    pub fn zero(&self, region: &mut Region<'_, Fr>, offset: usize) -> Result<GadgetValue, Error> {
        let cell = region
            .assign_advice_from_constant(|| "gadget zero", self.aux, offset, Fr::from(0u64))?
            .cell();
        Ok(GadgetValue {
            cell,
            value: zero_value(),
        })
    }

    /// `out = cond ? a : b`, with `cond` constrained to be boolean.
    pub fn select(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        cond: GadgetValue,
        a: GadgetValue,
        b: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        let cond_cell = region
            .assign_advice(self.select_cond, offset, cond.value)
            .cell();
        region.constrain_equal(cond_cell, cond.cell);

        let a_cell = region.assign_advice(self.select_a, offset, a.value).cell();
        region.constrain_equal(a_cell, a.cell);

        let b_cell = region.assign_advice(self.select_b, offset, b.value).cell();
        region.constrain_equal(b_cell, b.cell);

        // Same field formula as the gate, so the witness stays consistent even
        // for a non-boolean `cond`; the gate's boolean constraint is then the
        // constraint that rejects it.
        let value = cond
            .value
            .zip(a.value)
            .zip(b.value)
            .map(|((c, x), y)| y + c * (x - y));
        let out_cell = region.assign_advice(self.select_out, offset, value).cell();
        self.s_select.enable(region, offset)?;
        Ok(GadgetValue {
            cell: out_cell,
            value,
        })
    }

    /// Returns a boolean cell `is_zero` with `is_zero = 1` iff `input == 0`.
    pub fn is_zero(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        input: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        let zero = self.zero(region, offset)?;
        self.is_equal(region, offset, input, zero)
    }

    /// Returns a boolean cell `out` with `out = 1` iff `a == b`.
    pub fn is_equal(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        a: GadgetValue,
        b: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        let a_cell = region.assign_advice(self.eq_a, offset, a.value).cell();
        region.constrain_equal(a_cell, a.cell);
        let b_cell = region.assign_advice(self.eq_b, offset, b.value).cell();
        region.constrain_equal(b_cell, b.cell);

        let diff = a.value - b.value;
        // When `diff == 0` the host chooses `inv = 0`, which is safe because
        // the `diff * inv = 1 - out` gate then forces `out = 1`.
        let inv = diff.map(|d| d.invert().unwrap_or(Fr::from(0u64)));
        let out = diff.map(|d| {
            if bool::from(d.is_zero()) {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            }
        });

        region.assign_advice(self.eq_diff, offset, diff);
        region.assign_advice(self.eq_inv, offset, inv);
        let out_cell = region.assign_advice(self.eq_out, offset, out).cell();
        self.s_eq.enable(region, offset)?;
        Ok(GadgetValue {
            cell: out_cell,
            value: out,
        })
    }

    /// Constrains `input != 0`.
    pub fn assert_nonzero(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        input: GadgetValue,
    ) -> Result<(), Error> {
        let is_zero = self.is_zero(region, offset, input)?;
        region.constrain_constant(is_zero.cell, Fr::from(0u64))?;
        Ok(())
    }

    /// `out = a + b` over the field.
    pub fn add(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        a: GadgetValue,
        b: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        let a_cell = region.assign_advice(self.add_a, offset, a.value).cell();
        region.constrain_equal(a_cell, a.cell);
        let b_cell = region.assign_advice(self.add_b, offset, b.value).cell();
        region.constrain_equal(b_cell, b.cell);

        let value = a.value + b.value;
        let out_cell = region.assign_advice(self.add_out, offset, value).cell();
        self.s_add.enable(region, offset)?;
        Ok(GadgetValue {
            cell: out_cell,
            value,
        })
    }

    /// Constrains `input < 2^64`.
    pub fn range_check_u64(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        input: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        self.range_check(region, offset, input, U64_RANGE_BITS)
    }

    /// Constrains `input < 2^128`.
    ///
    /// Field elements `>= 2^128` (including `-1 = p - 1`) are rejected: the
    /// low 128 bits cannot recompose to the value.
    pub fn range_check_u128(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        input: GadgetValue,
    ) -> Result<GadgetValue, Error> {
        self.range_check(region, offset, input, U128_RANGE_BITS)
    }

    /// Bit decomposition with a boolean-constrained bit column and a running
    /// accumulator.
    ///
    /// Rows `offset .. offset + bits` are used (bits at `offset + i`, the
    /// accumulator at `offset` and `offset + 1 ..= offset + bits`).
    fn range_check(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        input: GadgetValue,
        bits: usize,
    ) -> Result<GadgetValue, Error> {
        let value_cell = region
            .assign_advice(self.range_value, offset, input.value)
            .cell();
        region.constrain_equal(value_cell, input.cell);

        let initial = region
            .assign_advice(self.range_acc, offset, zero_value())
            .cell();
        region.constrain_constant(initial, Fr::from(0u64))?;

        let mut acc_value = zero_value();
        let mut acc_cell = initial;
        for index in 0..bits {
            let row = offset + index;
            let bit_value = input.value.map(move |value| field_bit(value, index));
            region.assign_advice(self.bit, row, bit_value);
            self.s_bool.enable(region, row)?;

            let coefficient = power_of_two(index);
            region.assign_fixed(self.range_coeff, row, coefficient);
            self.s_range.enable(region, row)?;

            acc_value = acc_value + bit_value * Value::known(coefficient);
            acc_cell = region
                .assign_advice(self.range_acc, row + 1, acc_value)
                .cell();
        }

        // The recomposed value must be exactly the value being checked.
        region.constrain_equal(acc_cell, value_cell);
        Ok(GadgetValue {
            cell: value_cell,
            value: input.value,
        })
    }
}

// ---------------------------------------------------------------------------
// Composite sample: private Merkle path, public root only
// ---------------------------------------------------------------------------

/// Host-side Merkle root for a Poseidon2 binary tree.
///
/// `directions[i] == 1` means the current node is the right child (the sibling
/// is on the left). Returns `None` if the slices have different lengths or if a
/// direction is not the field element `0` or `1`; the circuit additionally
/// boolean-constrains every direction bit, so this helper is only a witness
/// convenience.
pub fn merkle_root(leaf: Fr, siblings: &[Fr], directions: &[Fr]) -> Option<Fr> {
    if siblings.len() != directions.len() {
        return None;
    }
    let zero = Fr::from(0u64);
    let one = Fr::from(1u64);
    let mut current = leaf;
    for (sibling, direction) in siblings.iter().zip(directions.iter()) {
        if *direction == zero {
            current = hash_output(&[current, *sibling]);
        } else if *direction == one {
            current = hash_output(&[*sibling, current]);
        } else {
            return None;
        }
    }
    Some(current)
}

/// Composite Merkle path circuit.
///
/// - `leaf`: secret leaf digest,
/// - `siblings[i]`: secret sibling at level `i`,
/// - `directions[i]`: secret direction bit at level `i` (`0` = current is the
///   left child, `1` = current is the right child).
///
/// Each level calls [`Poseidon2Chip::hash`] with arity 2, reusing the same chip.
/// The instance column contains only the final root (`1` value). The leaf,
/// siblings, direction bits and intermediate digests are never copied to the
/// instance column.
///
/// `DEPTH` is fixed at compile time for a given type. A depth of at least
/// [`MERKLE_RECOMMENDED_MIN_DEPTH`] (4) is recommended.
#[derive(Clone, Debug)]
pub struct Poseidon2MerkleCircuit<const DEPTH: usize> {
    leaf: Value<Fr>,
    siblings: [Value<Fr>; DEPTH],
    directions: [Value<Fr>; DEPTH],
    #[cfg(test)]
    tamper: Option<MerkleTamper>,
}

/// Test-only witness tampering used to demonstrate which constraint rejects a
/// malicious prover. Never available in production builds.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum MerkleTamper {
    /// Replace the direction witness at `level` with `value` (e.g. `2`).
    Direction { level: usize, value: Fr },
    /// Replace the sibling witness at `level`.
    Sibling { level: usize, value: Fr },
    /// Pass a host-computed value to the chip's absorb lane while keeping the
    /// constrained cell. The copy constraint must reject it.
    SubstitutedParent { level: usize },
}

impl<const DEPTH: usize> Poseidon2MerkleCircuit<DEPTH> {
    /// Builds a circuit for a known path.
    pub fn new(leaf: Fr, siblings: [Fr; DEPTH], directions: [Fr; DEPTH]) -> Self {
        Self {
            leaf: Value::known(leaf),
            siblings: siblings.map(Value::known),
            directions: directions.map(Value::known),
            #[cfg(test)]
            tamper: None,
        }
    }

    /// Test-only constructor hook for malicious witnesses.
    #[cfg(test)]
    fn with_tamper(mut self, tamper: MerkleTamper) -> Self {
        self.tamper = Some(tamper);
        self
    }
}

impl<const DEPTH: usize> Default for Poseidon2MerkleCircuit<DEPTH> {
    fn default() -> Self {
        Self {
            leaf: Value::unknown(),
            siblings: [Value::unknown(); DEPTH],
            directions: [Value::unknown(); DEPTH],
            #[cfg(test)]
            tamper: None,
        }
    }
}

/// Configuration used by [`Poseidon2MerkleCircuit`].
#[derive(Clone, Debug)]
pub struct Poseidon2MerkleConfig {
    poseidon2: Poseidon2Halo2Config,
    gadgets: GadgetConfig,
}

impl<const DEPTH: usize> Circuit<Fr> for Poseidon2MerkleCircuit<DEPTH> {
    type Config = Poseidon2MerkleConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poseidon2 = Poseidon2Chip::configure(meta);
        let gadgets = GadgetConfig::configure(meta);
        Poseidon2MerkleConfig { poseidon2, gadgets }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = Poseidon2Chip::new(config.poseidon2.clone());
        let gadgets = &config.gadgets;

        let root = layouter.assign_region(
            || "poseidon2 merkle path",
            |mut region| {
                // Gadget rows and Poseidon2 block rows use disjoint columns, so
                // a single region with fixed offsets gives a witness-independent
                // layout.
                let mut current = gadgets.assign_value(&mut region, 4 * DEPTH, self.leaf)?;

                for level in 0..DEPTH {
                    let row = 4 * level;

                    #[allow(unused_mut)]
                    let mut sibling_value = self.siblings[level];
                    #[allow(unused_mut)]
                    let mut direction_value = self.directions[level];
                    #[cfg(test)]
                    let mut substitute_parent = false;

                    #[cfg(test)]
                    if let Some(tamper) = self.tamper {
                        match tamper {
                            MerkleTamper::Direction { level: at, value } if at == level => {
                                direction_value = Value::known(value);
                            }
                            MerkleTamper::Sibling { level: at, value } if at == level => {
                                sibling_value = Value::known(value);
                            }
                            MerkleTamper::SubstitutedParent { level: at } if at == level => {
                                substitute_parent = true;
                            }
                            _ => {}
                        }
                    }

                    let sibling = gadgets.assign_value(&mut region, row + 3, sibling_value)?;
                    let direction = gadgets.assign_boolean(&mut region, row, direction_value)?;
                    let left = gadgets.select(&mut region, row + 1, direction, sibling, current)?;
                    let right =
                        gadgets.select(&mut region, row + 2, direction, current, sibling)?;

                    let left_input = Poseidon2Input {
                        cell: left.cell,
                        value: left.value,
                    };
                    #[cfg(test)]
                    let left_input = if substitute_parent {
                        Poseidon2Input {
                            cell: left.cell,
                            value: left.value + Value::known(Fr::from(1u64)),
                        }
                    } else {
                        left_input
                    };

                    let digest = chip.hash(
                        &mut region,
                        level * POSEIDON2_HALO2_PERMUTATION_ROWS,
                        &[
                            left_input,
                            Poseidon2Input {
                                cell: right.cell,
                                value: right.value,
                            },
                        ],
                    )?;

                    let digest_value = left
                        .value
                        .zip(right.value)
                        .map(|(left, right)| hash_output(&[left, right]));
                    current = GadgetValue {
                        cell: digest[0],
                        value: digest_value,
                    };
                }

                Ok(current.cell)
            },
        )?;

        layouter.constrain_instance(root, config.poseidon2.instance_column(), 0);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Composite sample: u128 range / overflow / select / equality
// ---------------------------------------------------------------------------

/// Configuration used by [`Poseidon2U128ExampleCircuit`].
#[derive(Clone, Debug)]
pub struct Poseidon2U128ExampleConfig {
    gadgets: GadgetConfig,
    instance: Column<Instance>,
}

/// Small sample circuit exercising the reusable gadgets with secret `u128`
/// values.
///
/// The instance column is `[a + b, cond ? a : b]`. The circuit:
///
/// 1. range-checks secret `a` and `b` as `u128`,
/// 2. computes `sum = a + b` and range-checks `sum` (rejects overflow),
/// 3. boolean-constrains a secret `cond` and selects `cond ? a : b`,
/// 4. also exercises the equality/zero test on `a` and `b`.
#[derive(Clone, Debug)]
pub struct Poseidon2U128ExampleCircuit {
    a: Value<Fr>,
    b: Value<Fr>,
    cond: Value<Fr>,
}

impl Poseidon2U128ExampleCircuit {
    /// Builds a circuit for known secret values.
    pub fn new(a: Fr, b: Fr, cond: Fr) -> Self {
        Self {
            a: Value::known(a),
            b: Value::known(b),
            cond: Value::known(cond),
        }
    }
}

impl Default for Poseidon2U128ExampleCircuit {
    fn default() -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
            cond: Value::unknown(),
        }
    }
}

impl Circuit<Fr> for Poseidon2U128ExampleCircuit {
    type Config = Poseidon2U128ExampleConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let gadgets = GadgetConfig::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Poseidon2U128ExampleConfig { gadgets, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let gadgets = &config.gadgets;

        let (sum_cell, selected_cell) = layouter.assign_region(
            || "poseidon2 u128 gadget example",
            |mut region| {
                let a = gadgets.assign_value(&mut region, 0, self.a)?;
                let b = gadgets.assign_value(&mut region, 1, self.b)?;

                // Two independent 128-bit decompositions.
                gadgets.range_check_u128(&mut region, 4, a)?;
                gadgets.range_check_u128(&mut region, 140, b)?;

                let sum = gadgets.add(&mut region, 275, a, b)?;
                // `a, b < 2^128` and `p > 2^254`, so field addition cannot wrap;
                // this gate + range check is therefore a no-overflow check.
                gadgets.range_check_u128(&mut region, 280, sum)?;

                let cond = gadgets.assign_boolean(&mut region, 415, self.cond)?;
                let selected = gadgets.select(&mut region, 416, cond, a, b)?;

                // Exercise the equality gadget as well; the returned bit is
                // constrained but not published.
                gadgets.is_equal(&mut region, 417, a, b)?;

                Ok((sum.cell, selected.cell))
            },
        )?;

        layouter.constrain_instance(sum_cell, config.instance, 0);
        layouter.constrain_instance(selected_cell, config.instance, 1);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_axiom::dev::MockProver;

    const MERKLE_DEPTH: usize = 4;

    fn minimum_k<C: Circuit<Fr>>(rows: usize) -> u32 {
        let mut cs = ConstraintSystem::<Fr>::default();
        let _ = C::configure(&mut cs);
        let mut k = 1u32;
        loop {
            let n = 1usize << k;
            if n >= cs.minimum_rows() && rows + cs.blinding_factors() + 1 <= n {
                return k;
            }
            k += 1;
        }
    }

    fn two_pow(bits: usize) -> Fr {
        power_of_two(bits)
    }

    fn merkle_rows(depth: usize) -> usize {
        depth * POSEIDON2_HALO2_PERMUTATION_ROWS + 4 * depth + 4
    }

    fn sample_path() -> (Fr, [Fr; MERKLE_DEPTH], [Fr; MERKLE_DEPTH]) {
        let leaf = Fr::from(0x1234_5678u64);
        let siblings = [
            Fr::from(11u64),
            Fr::from(22u64),
            Fr::from(33u64),
            Fr::from(44u64),
        ];
        let directions = [
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(1u64),
        ];
        (leaf, siblings, directions)
    }

    fn run_merkle(
        circuit: &Poseidon2MerkleCircuit<MERKLE_DEPTH>,
        instance: Vec<Fr>,
    ) -> MockProver<Fr> {
        let k = minimum_k::<Poseidon2MerkleCircuit<MERKLE_DEPTH>>(merkle_rows(MERKLE_DEPTH));
        MockProver::run(k, circuit, vec![instance]).expect("mock prover run")
    }

    /// Witness root the circuit actually commits to for arbitrary (possibly
    /// non-boolean) direction values, using the select gate's field formula.
    fn circuit_root_with_direction(
        leaf: Fr,
        siblings: &[Fr; MERKLE_DEPTH],
        directions: &[Fr; MERKLE_DEPTH],
        level: usize,
        direction: Fr,
    ) -> Fr {
        let mut current = leaf;
        for index in 0..MERKLE_DEPTH {
            let direction = if index == level {
                direction
            } else {
                directions[index]
            };
            let sibling = siblings[index];
            let left = sibling + direction * (current - sibling);
            let right = current + direction * (sibling - current);
            current = hash_output(&[left, right]);
        }
        current
    }

    // ------------------------------------------------------------------
    // Merkle circuit
    // ------------------------------------------------------------------

    #[test]
    fn merkle_correct_path_is_satisfied() {
        let (leaf, siblings, directions) = sample_path();
        let root = merkle_root(leaf, &siblings, &directions).expect("boolean path");
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(leaf, siblings, directions);
        let prover = run_merkle(&circuit, vec![root]);
        prover.assert_satisfied();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn merkle_wrong_public_root_is_rejected() {
        let (leaf, siblings, directions) = sample_path();
        let root = merkle_root(leaf, &siblings, &directions).expect("boolean path");
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(leaf, siblings, directions);
        let prover = run_merkle(&circuit, vec![root + Fr::from(1u64)]);
        assert!(
            prover.verify().is_err(),
            "unrelated public root must be rejected"
        );
    }

    #[test]
    fn merkle_wrong_direction_bit_is_rejected() {
        let (leaf, siblings, directions) = sample_path();
        let root = merkle_root(leaf, &siblings, &directions).expect("boolean path");
        let mut flipped = directions;
        flipped[1] = if directions[1] == Fr::from(1u64) {
            Fr::from(0u64)
        } else {
            Fr::from(1u64)
        };

        // Flipping a direction is a different path; the honest root must not
        // verify, while the flipped path's own root does.
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(leaf, siblings, flipped);
        let prover = run_merkle(&circuit, vec![root]);
        assert!(
            prover.verify().is_err(),
            "flipped direction accepted for the honest root"
        );

        let flipped_root = merkle_root(leaf, &siblings, &flipped).expect("boolean path");
        let prover = run_merkle(&circuit, vec![flipped_root]);
        prover.assert_satisfied();
    }

    #[test]
    fn merkle_non_boolean_direction_is_rejected() {
        let (leaf, siblings, directions) = sample_path();
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(leaf, siblings, directions)
            .with_tamper(MerkleTamper::Direction {
                level: 1,
                value: Fr::from(2u64),
            });

        // Supply the root the tampered witness would produce, so the instance
        // binding cannot be what rejects it: only the boolean gate can.
        let tampered_root =
            circuit_root_with_direction(leaf, &siblings, &directions, 1, Fr::from(2u64));
        let prover = run_merkle(&circuit, vec![tampered_root]);
        assert!(
            prover.verify().is_err(),
            "non-boolean direction must be rejected by the boolean gate"
        );
    }

    #[test]
    fn merkle_wrong_sibling_is_rejected() {
        let (leaf, siblings, directions) = sample_path();
        let root = merkle_root(leaf, &siblings, &directions).expect("boolean path");
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(leaf, siblings, directions)
            .with_tamper(MerkleTamper::Sibling {
                level: 2,
                value: siblings[2] + Fr::from(1u64),
            });
        let prover = run_merkle(&circuit, vec![root]);
        assert!(prover.verify().is_err(), "tampered sibling accepted");
    }

    #[test]
    fn merkle_substituted_parent_is_rejected() {
        let (leaf, siblings, directions) = sample_path();
        let root = merkle_root(leaf, &siblings, &directions).expect("boolean path");
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(leaf, siblings, directions)
            .with_tamper(MerkleTamper::SubstitutedParent { level: 2 });
        let prover = run_merkle(&circuit, vec![root]);
        assert!(
            prover.verify().is_err(),
            "host-computed parent substituted into the absorb lane was accepted"
        );
    }

    #[test]
    fn merkle_different_leaf_for_same_root_is_rejected() {
        let (leaf, siblings, directions) = sample_path();
        let root = merkle_root(leaf, &siblings, &directions).expect("boolean path");
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(
            leaf + Fr::from(1u64),
            siblings,
            directions,
        );
        let prover = run_merkle(&circuit, vec![root]);
        assert!(
            prover.verify().is_err(),
            "a different leaf was accepted for the same root"
        );
    }

    #[test]
    fn merkle_exposes_only_the_root() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let _ = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::configure(&mut cs);
        assert_eq!(cs.num_instance_columns(), 1);

        let (leaf, siblings, directions) = sample_path();
        let root = merkle_root(leaf, &siblings, &directions).expect("boolean path");
        assert_ne!(root, leaf);

        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::new(leaf, siblings, directions);
        // A single instance value satisfies the circuit. If any secret had been
        // copied to instance row 1+, the padding there (zero) would fail.
        let prover = run_merkle(&circuit, vec![root]);
        prover.assert_satisfied();

        // The secret leaf is not a valid public value.
        let prover = run_merkle(&circuit, vec![leaf]);
        assert!(
            prover.verify().is_err(),
            "the secret leaf was accepted as the instance value"
        );
    }

    #[test]
    fn merkle_without_witnesses_keygen_succeeds() {
        use halo2_axiom::halo2curves::bn256::G1Affine;
        use halo2_axiom::plonk::keygen_vk;
        use halo2_axiom::poly::commitment::ParamsProver;
        use halo2_axiom::poly::ipa::commitment::ParamsIPA;

        let k = minimum_k::<Poseidon2MerkleCircuit<MERKLE_DEPTH>>(merkle_rows(MERKLE_DEPTH));
        let params = ParamsIPA::<G1Affine>::new(k);
        let circuit = Poseidon2MerkleCircuit::<MERKLE_DEPTH>::default();
        let vk = keygen_vk(&params, &circuit.without_witnesses())
            .expect("keygen must not require witnesses");
        drop(vk);

        let params = ParamsIPA::<G1Affine>::new(10);
        let circuit = Poseidon2U128ExampleCircuit::default();
        let vk = keygen_vk(&params, &circuit.without_witnesses())
            .expect("u128 example keygen must not require witnesses");
        drop(vk);
    }

    // ------------------------------------------------------------------
    // u128 / overflow example
    // ------------------------------------------------------------------

    fn run_u128(circuit: &Poseidon2U128ExampleCircuit, a: Fr, b: Fr, cond: Fr) -> MockProver<Fr> {
        let k = minimum_k::<Poseidon2U128ExampleCircuit>(420);
        let sum = a + b;
        let selected = if cond == Fr::from(1u64) { a } else { b };
        MockProver::run(k, circuit, vec![vec![sum, selected]]).expect("mock prover run")
    }

    #[test]
    fn u128_accepts_in_range_values() {
        let max = two_pow(128) - Fr::from(1u64);
        let a = max - Fr::from(1u64);
        let b = Fr::from(1u64);
        let circuit = Poseidon2U128ExampleCircuit::new(a, b, Fr::from(1u64));
        let prover = run_u128(&circuit, a, b, Fr::from(1u64));
        prover.assert_satisfied();

        let zero = Fr::from(0u64);
        let circuit = Poseidon2U128ExampleCircuit::new(zero, max, Fr::from(0u64));
        let prover = run_u128(&circuit, zero, max, Fr::from(0u64));
        prover.assert_satisfied();
    }

    #[test]
    fn u128_rejects_overflow() {
        let max = two_pow(128) - Fr::from(1u64);
        let circuit = Poseidon2U128ExampleCircuit::new(max, Fr::from(1u64), Fr::from(1u64));
        let prover = run_u128(&circuit, max, Fr::from(1u64), Fr::from(1u64));
        assert!(
            prover.verify().is_err(),
            "2^128 - 1 + 1 must be rejected as u128 overflow"
        );
    }

    // ------------------------------------------------------------------
    // Range-check gadget
    // ------------------------------------------------------------------

    #[derive(Clone, Debug)]
    struct RangeCircuit {
        value: Value<Fr>,
        bits: usize,
    }

    impl RangeCircuit {
        fn new(value: Fr, bits: usize) -> Self {
            Self {
                value: Value::known(value),
                bits,
            }
        }
    }

    impl Circuit<Fr> for RangeCircuit {
        type Config = GadgetConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                value: Value::unknown(),
                bits: self.bits,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            GadgetConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "range check",
                |mut region| {
                    let value = config.assign_value(&mut region, 0, self.value)?;
                    match self.bits {
                        64 => config.range_check_u64(&mut region, 10, value)?,
                        128 => config.range_check_u128(&mut region, 10, value)?,
                        _ => return Err(Error::Synthesis),
                    };
                    Ok(())
                },
            )
        }
    }

    fn run_range(value: Fr, bits: usize) -> MockProver<Fr> {
        let k = minimum_k::<RangeCircuit>(10 + bits + 2);
        let circuit = RangeCircuit::new(value, bits);
        MockProver::run(k, &circuit, vec![]).expect("mock prover run")
    }

    #[test]
    fn range_check_u64_accepts_boundaries() {
        for value in [Fr::from(0u64), two_pow(64) - Fr::from(1u64)] {
            let prover = run_range(value, 64);
            prover.assert_satisfied();
        }
    }

    #[test]
    fn range_check_u64_rejects_2_pow_64() {
        let prover = run_range(two_pow(64), 64);
        assert!(prover.verify().is_err(), "2^64 must be rejected by u64");
    }

    #[test]
    fn range_check_u128_accepts_boundaries() {
        for value in [Fr::from(0u64), two_pow(64), two_pow(128) - Fr::from(1u64)] {
            let prover = run_range(value, 128);
            prover.assert_satisfied();
        }
    }

    #[test]
    fn range_check_u128_rejects_2_pow_128() {
        let prover = run_range(two_pow(128), 128);
        assert!(prover.verify().is_err(), "2^128 must be rejected by u128");
    }

    #[test]
    fn range_check_rejects_field_wraparound() {
        // -1 = p - 1, a canonical field element far above 2^128.
        let minus_one = Fr::from(0u64) - Fr::from(1u64);
        let prover = run_range(minus_one, 128);
        assert!(
            prover.verify().is_err(),
            "field wraparound (-1) must be rejected"
        );
    }

    // ------------------------------------------------------------------
    // Boolean / equality / select / nonzero gadgets
    // ------------------------------------------------------------------

    #[derive(Clone, Debug)]
    struct BooleanCircuit {
        value: Value<Fr>,
    }

    impl Circuit<Fr> for BooleanCircuit {
        type Config = GadgetConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                value: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            GadgetConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "boolean",
                |mut region| {
                    config.assign_boolean(&mut region, 0, self.value)?;
                    Ok(())
                },
            )
        }
    }

    fn run_boolean(value: Fr) -> MockProver<Fr> {
        let k = minimum_k::<BooleanCircuit>(8);
        let circuit = BooleanCircuit {
            value: Value::known(value),
        };
        MockProver::run(k, &circuit, vec![]).expect("mock prover run")
    }

    #[test]
    fn boolean_accepts_zero_and_one() {
        for value in [Fr::from(0u64), Fr::from(1u64)] {
            run_boolean(value).assert_satisfied();
        }
    }

    #[test]
    fn boolean_rejects_two() {
        let prover = run_boolean(Fr::from(2u64));
        assert!(prover.verify().is_err(), "2 is not boolean");
    }

    #[derive(Clone, Debug)]
    struct NonzeroCircuit {
        value: Value<Fr>,
    }

    impl Circuit<Fr> for NonzeroCircuit {
        type Config = GadgetConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                value: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            GadgetConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "nonzero",
                |mut region| {
                    let value = config.assign_value(&mut region, 0, self.value)?;
                    config.assert_nonzero(&mut region, 1, value)?;
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn nonzero_check_accepts_nonzero_and_rejects_zero() {
        let k = minimum_k::<NonzeroCircuit>(8);
        let nonzero = NonzeroCircuit {
            value: Value::known(Fr::from(7u64)),
        };
        MockProver::run(k, &nonzero, vec![])
            .expect("mock prover run")
            .assert_satisfied();

        let zero = NonzeroCircuit {
            value: Value::known(Fr::from(0u64)),
        };
        let prover = MockProver::run(k, &zero, vec![]).expect("mock prover run");
        assert!(prover.verify().is_err(), "zero must fail the nonzero check");
    }

    /// Assigns a cell but hands `copy` an inconsistent host value for the same
    /// cell. The copy constraint must reject the mismatch.
    #[derive(Clone, Debug)]
    struct CopyBindingCircuit {
        assigned: Fr,
        copy_value: Fr,
    }

    impl Circuit<Fr> for CopyBindingCircuit {
        type Config = GadgetConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            GadgetConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "copy binding",
                |mut region| {
                    let original =
                        config.assign_value(&mut region, 0, Value::known(self.assigned))?;
                    config.copy(
                        &mut region,
                        1,
                        GadgetValue {
                            cell: original.cell,
                            value: Value::known(self.copy_value),
                        },
                    )?;
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn copy_helper_binds_the_assigned_cell() {
        let k = minimum_k::<CopyBindingCircuit>(8);

        let honest = CopyBindingCircuit {
            assigned: Fr::from(7u64),
            copy_value: Fr::from(7u64),
        };
        MockProver::run(k, &honest, vec![])
            .expect("mock prover run")
            .assert_satisfied();

        let inconsistent = CopyBindingCircuit {
            assigned: Fr::from(7u64),
            copy_value: Fr::from(9u64),
        };
        let prover = MockProver::run(k, &inconsistent, vec![]).expect("mock prover run");
        assert!(
            prover.verify().is_err(),
            "an inconsistent host value bypassed the copy constraint"
        );
    }

    #[derive(Clone, Debug)]
    struct GadgetLogicConfig {
        gadgets: GadgetConfig,
        instance: Column<Instance>,
    }

    #[derive(Clone, Debug)]
    struct GadgetLogicCircuit {
        a: Value<Fr>,
        b: Value<Fr>,
        cond: Value<Fr>,
    }

    impl Circuit<Fr> for GadgetLogicCircuit {
        type Config = GadgetLogicConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                a: Value::unknown(),
                b: Value::unknown(),
                cond: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let gadgets = GadgetConfig::configure(meta);
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            GadgetLogicConfig { gadgets, instance }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let gadgets = &config.gadgets;
            let (eq, selected) = layouter.assign_region(
                || "gadget logic",
                |mut region| {
                    let a = gadgets.assign_value(&mut region, 0, self.a)?;
                    let b = gadgets.assign_value(&mut region, 1, self.b)?;
                    let eq = gadgets.is_equal(&mut region, 2, a, b)?;
                    let cond = gadgets.assign_boolean(&mut region, 3, self.cond)?;
                    let selected = gadgets.select(&mut region, 4, cond, a, b)?;
                    Ok((eq.cell, selected.cell))
                },
            )?;
            layouter.constrain_instance(eq, config.instance, 0);
            layouter.constrain_instance(selected, config.instance, 1);
            Ok(())
        }
    }

    fn run_logic(a: Fr, b: Fr, cond: Fr, instance: [Fr; 2]) -> MockProver<Fr> {
        let k = minimum_k::<GadgetLogicCircuit>(8);
        let circuit = GadgetLogicCircuit {
            a: Value::known(a),
            b: Value::known(b),
            cond: Value::known(cond),
        };
        MockProver::run(k, &circuit, vec![instance.to_vec()]).expect("mock prover run")
    }

    #[test]
    fn equality_and_select_are_correct() {
        // Equal inputs, cond = 1 selects `a`.
        let prover = run_logic(
            Fr::from(7u64),
            Fr::from(7u64),
            Fr::from(1u64),
            [Fr::from(1u64), Fr::from(7u64)],
        );
        prover.assert_satisfied();

        // Unequal inputs, cond = 0 selects `b`.
        let prover = run_logic(
            Fr::from(7u64),
            Fr::from(9u64),
            Fr::from(0u64),
            [Fr::from(0u64), Fr::from(9u64)],
        );
        prover.assert_satisfied();
    }

    #[test]
    fn equality_and_select_claims_are_rejected() {
        // a != b but the public equality bit claims 1.
        let prover = run_logic(
            Fr::from(7u64),
            Fr::from(9u64),
            Fr::from(0u64),
            [Fr::from(1u64), Fr::from(9u64)],
        );
        assert!(prover.verify().is_err(), "false equality claim accepted");

        // cond = 0 must select b, not a.
        let prover = run_logic(
            Fr::from(7u64),
            Fr::from(9u64),
            Fr::from(0u64),
            [Fr::from(0u64), Fr::from(7u64)],
        );
        assert!(prover.verify().is_err(), "wrong selected value accepted");
    }

    /// Raw assignment into the equality gate to test gate soundness directly
    /// (a malicious prover can choose any witness, not only `is_equal`'s).
    #[derive(Clone, Debug)]
    struct RawEqualityCircuit {
        a: Fr,
        b: Fr,
        diff: Fr,
        inv: Fr,
        out: Fr,
    }

    impl Circuit<Fr> for RawEqualityCircuit {
        type Config = GadgetConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            GadgetConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "raw equality",
                |mut region| {
                    region.assign_advice(config.eq_a, 0, Value::known(self.a));
                    region.assign_advice(config.eq_b, 0, Value::known(self.b));
                    region.assign_advice(config.eq_diff, 0, Value::known(self.diff));
                    region.assign_advice(config.eq_inv, 0, Value::known(self.inv));
                    region.assign_advice(config.eq_out, 0, Value::known(self.out));
                    config.s_eq.enable(&mut region, 0)?;
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn equality_gate_rejects_unsound_witnesses() {
        let k = minimum_k::<RawEqualityCircuit>(8);

        let honest = RawEqualityCircuit {
            a: Fr::from(1u64),
            b: Fr::from(1u64),
            diff: Fr::from(0u64),
            inv: Fr::from(0u64),
            out: Fr::from(1u64),
        };
        MockProver::run(k, &honest, vec![])
            .expect("mock prover run")
            .assert_satisfied();

        // a != b but out = 1: `out * diff = 0` must fail.
        let unsound = RawEqualityCircuit {
            a: Fr::from(1u64),
            b: Fr::from(2u64),
            diff: Fr::from(1u64),
            inv: Fr::from(1u64),
            out: Fr::from(1u64),
        };
        let prover = MockProver::run(k, &unsound, vec![]).expect("mock prover run");
        assert!(
            prover.verify().is_err(),
            "unsound zero test witness was accepted"
        );

        // Wrong inverse: diff * inv != 1 - out.
        let unsound_inverse = RawEqualityCircuit {
            a: Fr::from(1u64),
            b: Fr::from(2u64),
            diff: Fr::from(1u64),
            inv: Fr::from(2u64),
            out: Fr::from(0u64),
        };
        let prover = MockProver::run(k, &unsound_inverse, vec![]).expect("mock prover run");
        assert!(
            prover.verify().is_err(),
            "wrong inverse was accepted by the zero test"
        );
    }

    /// Raw assignment into the select gate to show the gate equation is
    /// enforced independently of the host helper.
    #[derive(Clone, Debug)]
    struct RawSelectCircuit {
        cond: Fr,
        a: Fr,
        b: Fr,
        out: Fr,
    }

    impl Circuit<Fr> for RawSelectCircuit {
        type Config = GadgetConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            GadgetConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "raw select",
                |mut region| {
                    region.assign_advice(config.select_cond, 0, Value::known(self.cond));
                    region.assign_advice(config.select_a, 0, Value::known(self.a));
                    region.assign_advice(config.select_b, 0, Value::known(self.b));
                    region.assign_advice(config.select_out, 0, Value::known(self.out));
                    config.s_select.enable(&mut region, 0)?;
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn select_gate_rejects_wrong_output_and_non_boolean_cond() {
        let k = minimum_k::<RawSelectCircuit>(8);

        let honest = RawSelectCircuit {
            cond: Fr::from(1u64),
            a: Fr::from(5u64),
            b: Fr::from(9u64),
            out: Fr::from(5u64),
        };
        MockProver::run(k, &honest, vec![])
            .expect("mock prover run")
            .assert_satisfied();

        let wrong_out = RawSelectCircuit {
            cond: Fr::from(1u64),
            a: Fr::from(5u64),
            b: Fr::from(9u64),
            out: Fr::from(9u64),
        };
        let prover = MockProver::run(k, &wrong_out, vec![]).expect("mock prover run");
        assert!(prover.verify().is_err(), "wrong select output accepted");

        let non_boolean = RawSelectCircuit {
            cond: Fr::from(2u64),
            a: Fr::from(5u64),
            b: Fr::from(9u64),
            // Field formula for cond = 2: b + 2 * (a - b) = 1.
            out: Fr::from(1u64),
        };
        let prover = MockProver::run(k, &non_boolean, vec![]).expect("mock prover run");
        assert!(
            prover.verify().is_err(),
            "non-boolean select condition accepted"
        );
    }
}
