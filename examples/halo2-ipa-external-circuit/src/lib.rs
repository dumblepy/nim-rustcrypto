//! Example external Halo2 IPA / BN254 circuit using the compile-time registry.
//!
//! This crate is deliberately **separate** from `rustcrypto-ffi`: it adds its
//! own composite circuits and exports C ABI adapters with
//! [`rust_crypto_ffi::halo2_ipa_export_circuit!`] without editing any
//! `rustcrypto-ffi` source file.
//!
//! Two circuits are registered:
//!
//! - [`ChainCircuit`] (id `0x10001`): a 16-step `acc = acc^2 + input` chain with
//!   a custom gate `q * (acc_prev^2 + input - acc)`. The single instance column
//!   exposes 17 values `[acc_1, .., acc_15, input_0, input_15]`; the other
//!   inputs stay in private advice cells.
//! - [`LinearCircuit`] (id `0x10002`): the additive analogue
//!   `acc = acc + input`, used to show that a proof is bound to its circuit's
//!   VK and that a verifier-only adapter can be exported separately.
//!
//! Both use `Params = ()`, `SimpleFloorPlanner`, a deterministic 16-row layout,
//! and `without_witnesses()` with the same layout.

use halo2_axiom::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::plonk::{Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Selector};
use halo2_axiom::poly::Rotation;
use rust_crypto_ffi::halo2_ipa_export_circuit;
use rust_crypto_ffi::halo2_ipa_export_circuit_verifier;
use rust_crypto_ffi::halo2_ipa_registry::{ApprovedCircuit, CircuitProfile, decode_fr_be};

/// Number of private witness field elements.
pub const WITNESS_VALUES: usize = 16;
/// Number of public instance values (one column).
pub const INSTANCE_VALUES: usize = 17;
/// Reserved halo2 rows for blinding (`blinding_factors + 1`).
const RESERVED_ROWS: usize = 6;
/// Rows used by the deterministic layout.
const LAYOUT_ROWS: usize = WITNESS_VALUES;
/// Smallest `k` with `2^k - 6 >= 16` is 5; use 6 for comfortable headroom.
const MIN_K: u32 = 6;
const MAX_K: u32 = 12;

pub const CHAIN_CIRCUIT_ID: u32 = 0x1_0001;
pub const CHAIN_CIRCUIT_VERSION: u32 = 1;
pub const LINEAR_CIRCUIT_ID: u32 = 0x1_0002;
pub const LINEAR_CIRCUIT_VERSION: u32 = 1;

const INSTANCE_COLUMNS: &[usize] = &[INSTANCE_VALUES];

/// Shared configuration for the example chain circuits.
#[derive(Clone)]
pub struct ChainConfig {
    input: Column<Advice>,
    accumulator: Column<Advice>,
    instance: Column<halo2_axiom::plonk::Instance>,
    square_add: Selector,
}

/// `acc_i = acc_{i-1}^2 + input_i` over 16 private inputs.
///
/// Public instance column (17 values):
/// `[acc_1, .., acc_15, input_0, input_15]`.
#[derive(Clone)]
pub struct ChainCircuit {
    inputs: Vec<Value<Fr>>,
}

impl Default for ChainCircuit {
    fn default() -> Self {
        Self {
            inputs: vec![Value::unknown(); WITNESS_VALUES],
        }
    }
}

/// Computes the public instance values for [`ChainCircuit`].
pub fn chain_public_values(inputs: &[Fr; WITNESS_VALUES]) -> Vec<Fr> {
    let mut accumulators = Vec::with_capacity(WITNESS_VALUES);
    let mut current = inputs[0];
    accumulators.push(current);
    for input in &inputs[1..] {
        current = current * current + *input;
        accumulators.push(current);
    }
    let mut public = Vec::with_capacity(INSTANCE_VALUES);
    public.extend_from_slice(&accumulators[1..WITNESS_VALUES]);
    public.push(inputs[0]);
    public.push(inputs[WITNESS_VALUES - 1]);
    public
}

impl ChainCircuit {
    pub fn new(inputs: &[Fr; WITNESS_VALUES]) -> Self {
        Self {
            inputs: inputs.iter().copied().map(Value::known).collect(),
        }
    }

    fn accumulators(&self) -> Option<Vec<Value<Fr>>> {
        if self.inputs.len() != WITNESS_VALUES {
            return None;
        }
        let mut accumulators = Vec::with_capacity(WITNESS_VALUES);
        let mut current = self.inputs[0];
        accumulators.push(current);
        for input in &self.inputs[1..] {
            current = current * current + *input;
            accumulators.push(current);
        }
        Some(accumulators)
    }
}

impl Circuit<Fr> for ChainCircuit {
    type Config = ChainConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: self.inputs.iter().map(|_| Value::unknown()).collect(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> ChainConfig {
        let input = meta.advice_column();
        let accumulator = meta.advice_column();
        let instance = meta.instance_column();
        let square_add = meta.selector();

        meta.enable_equality(input);
        meta.enable_equality(accumulator);
        meta.enable_equality(instance);

        meta.create_gate("square-add chain", |meta| {
            let enabled = meta.query_selector(square_add);
            let previous = meta.query_advice(accumulator, Rotation::prev());
            let current_input = meta.query_advice(input, Rotation::cur());
            let next = meta.query_advice(accumulator, Rotation::cur());
            vec![enabled * (previous.clone() * previous + current_input - next)]
        });

        ChainConfig {
            input,
            accumulator,
            instance,
            square_add,
        }
    }

    fn synthesize(
        &self,
        config: ChainConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let accumulators = self.accumulators().ok_or(Error::Synthesis)?;

        let (input_cells, accumulator_cells) = layouter.assign_region(
            || "square-add chain",
            |mut region| {
                let mut input_cells = Vec::with_capacity(WITNESS_VALUES);
                let mut accumulator_cells = Vec::with_capacity(WITNESS_VALUES);
                for row in 0..WITNESS_VALUES {
                    if row > 0 {
                        config.square_add.enable(&mut region, row)?;
                    }
                    input_cells.push(
                        region
                            .assign_advice(
                                config.input,
                                row,
                                self.inputs[row].map(Assigned::from),
                            )
                            .cell(),
                    );
                    accumulator_cells.push(
                        region
                            .assign_advice(
                                config.accumulator,
                                row,
                                accumulators[row].map(Assigned::from),
                            )
                            .cell(),
                    );
                }
                Ok((input_cells, accumulator_cells))
            },
        )?;

        // `[acc_1, .., acc_15, input_0, input_15]` in a fixed row order.
        for (row, cell) in accumulator_cells[1..WITNESS_VALUES].iter().enumerate() {
            layouter.constrain_instance(*cell, config.instance, row);
        }
        layouter.constrain_instance(input_cells[0], config.instance, WITNESS_VALUES - 1);
        layouter.constrain_instance(
            input_cells[WITNESS_VALUES - 1],
            config.instance,
            WITNESS_VALUES,
        );
        Ok(())
    }
}

impl ApprovedCircuit for ChainCircuit {
    fn profile() -> CircuitProfile {
        CircuitProfile::new(
            CHAIN_CIRCUIT_ID,
            CHAIN_CIRCUIT_VERSION,
            MIN_K,
            MAX_K,
            WITNESS_VALUES * 32,
            INSTANCE_COLUMNS,
        )
        .with_bounds(64 * 1024, 8 * 1024 * 1024, 2 * 1024 * 1024)
    }

    fn from_witness(bytes: &[u8]) -> Result<Self, core::ffi::c_int> {
        if bytes.len() != WITNESS_VALUES * 32 {
            return Err(rust_crypto_ffi::RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let mut inputs = Vec::with_capacity(WITNESS_VALUES);
        for chunk in bytes.chunks_exact(32) {
            inputs.push(Value::known(decode_fr_be(chunk)?));
        }
        Ok(Self { inputs })
    }
}

/// `acc_i = acc_{i-1} + input_i` over the same 16-row layout.
///
/// The instance column shape is identical to [`ChainCircuit`], but the gate (and
/// therefore the VK) differs.
#[derive(Clone)]
pub struct LinearCircuit {
    inputs: Vec<Value<Fr>>,
}

impl Default for LinearCircuit {
    fn default() -> Self {
        Self {
            inputs: vec![Value::unknown(); WITNESS_VALUES],
        }
    }
}

/// Computes the public instance values for [`LinearCircuit`].
pub fn linear_public_values(inputs: &[Fr; WITNESS_VALUES]) -> Vec<Fr> {
    let mut accumulators = Vec::with_capacity(WITNESS_VALUES);
    let mut current = inputs[0];
    accumulators.push(current);
    for input in &inputs[1..] {
        current = current + *input;
        accumulators.push(current);
    }
    let mut public = Vec::with_capacity(INSTANCE_VALUES);
    public.extend_from_slice(&accumulators[1..WITNESS_VALUES]);
    public.push(inputs[0]);
    public.push(inputs[WITNESS_VALUES - 1]);
    public
}

impl LinearCircuit {
    pub fn new(inputs: &[Fr; WITNESS_VALUES]) -> Self {
        Self {
            inputs: inputs.iter().copied().map(Value::known).collect(),
        }
    }

    fn accumulators(&self) -> Option<Vec<Value<Fr>>> {
        if self.inputs.len() != WITNESS_VALUES {
            return None;
        }
        let mut accumulators = Vec::with_capacity(WITNESS_VALUES);
        let mut current = self.inputs[0];
        accumulators.push(current);
        for input in &self.inputs[1..] {
            current = current + *input;
            accumulators.push(current);
        }
        Some(accumulators)
    }
}

impl Circuit<Fr> for LinearCircuit {
    type Config = ChainConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: self.inputs.iter().map(|_| Value::unknown()).collect(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> ChainConfig {
        let input = meta.advice_column();
        let accumulator = meta.advice_column();
        let instance = meta.instance_column();
        let linear_add = meta.selector();

        meta.enable_equality(input);
        meta.enable_equality(accumulator);
        meta.enable_equality(instance);

        meta.create_gate("linear-add chain", |meta| {
            let enabled = meta.query_selector(linear_add);
            let previous = meta.query_advice(accumulator, Rotation::prev());
            let current_input = meta.query_advice(input, Rotation::cur());
            let next = meta.query_advice(accumulator, Rotation::cur());
            vec![enabled * (previous + current_input - next)]
        });

        ChainConfig {
            input,
            accumulator,
            instance,
            square_add: linear_add,
        }
    }

    fn synthesize(
        &self,
        config: ChainConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let accumulators = self.accumulators().ok_or(Error::Synthesis)?;

        let (input_cells, accumulator_cells) = layouter.assign_region(
            || "linear-add chain",
            |mut region| {
                let mut input_cells = Vec::with_capacity(WITNESS_VALUES);
                let mut accumulator_cells = Vec::with_capacity(WITNESS_VALUES);
                for row in 0..WITNESS_VALUES {
                    if row > 0 {
                        config.square_add.enable(&mut region, row)?;
                    }
                    input_cells.push(
                        region
                            .assign_advice(
                                config.input,
                                row,
                                self.inputs[row].map(Assigned::from),
                            )
                            .cell(),
                    );
                    accumulator_cells.push(
                        region
                            .assign_advice(
                                config.accumulator,
                                row,
                                accumulators[row].map(Assigned::from),
                            )
                            .cell(),
                    );
                }
                Ok((input_cells, accumulator_cells))
            },
        )?;

        for (row, cell) in accumulator_cells[1..WITNESS_VALUES].iter().enumerate() {
            layouter.constrain_instance(*cell, config.instance, row);
        }
        layouter.constrain_instance(input_cells[0], config.instance, WITNESS_VALUES - 1);
        layouter.constrain_instance(
            input_cells[WITNESS_VALUES - 1],
            config.instance,
            WITNESS_VALUES,
        );
        Ok(())
    }
}

impl ApprovedCircuit for LinearCircuit {
    fn profile() -> CircuitProfile {
        CircuitProfile::new(
            LINEAR_CIRCUIT_ID,
            LINEAR_CIRCUIT_VERSION,
            MIN_K,
            MAX_K,
            WITNESS_VALUES * 32,
            INSTANCE_COLUMNS,
        )
        .with_bounds(64 * 1024, 8 * 1024 * 1024, 2 * 1024 * 1024)
    }

    fn from_witness(bytes: &[u8]) -> Result<Self, core::ffi::c_int> {
        if bytes.len() != WITNESS_VALUES * 32 {
            return Err(rust_crypto_ffi::RUSTCRYPTO_ERR_INVALID_LENGTH);
        }
        let mut inputs = Vec::with_capacity(WITNESS_VALUES);
        for chunk in bytes.chunks_exact(32) {
            inputs.push(Value::known(decode_fr_be(chunk)?));
        }
        Ok(Self { inputs })
    }
}

// Compile-time registration. No runtime descriptor or code loading.
halo2_ipa_export_circuit!(ChainCircuit, chain_adapter);
halo2_ipa_export_circuit!(LinearCircuit, linear_adapter);
halo2_ipa_export_circuit_verifier!(LinearCircuit, linear_verifier);

/// Sanity check that the profile rows fit the chosen `k` range.
const _: () = assert!(LAYOUT_ROWS + RESERVED_ROWS <= (1usize << MIN_K));
