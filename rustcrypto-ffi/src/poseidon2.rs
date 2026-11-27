//! Poseidon2 over BN254 `Fr` (C ABI).
//!
//! # Compatibility profile
//!
//! - Field: BN254 scalar field `Fr`, canonical 32-byte big-endian encoding.
//! - Width `t = 4`, rate `3`, capacity `1`, S-box `x^5`, `R_F = 8`, `R_P = 56`.
//! - Permutation and Noir/Barretenberg sponge, matching Noir
//!   `bn254_blackbox_solver` (tag v1.0.0-beta.22) and Barretenberg.
//! - Round constants, internal diagonal and linear layers are vendored from
//!   `pso-poseidon` 0.5.0 (MIT), which copies them verbatim from Noir. Do not
//!   edit the hex values.
//!
//! This module is deliberately separate from [`crate::poseidon`] (Poseidon1).
//!
//! `poseidon2_bn254_hash_impl` uses the Noir/Barretenberg sponge: the final
//! permutation is skipped when the input length is a non-zero multiple of the
//! rate. This is **not** the psonet framing, which always performs a final
//! permutation.

use crate::aead_common::output_buffer;
use crate::bn254::{fr_from_be, fr_to_be};
use crate::{
    RUSTCRYPTO_ERR_INVALID_LENGTH, RUSTCRYPTO_ERR_INVALID_PARAMETER,
    RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA, RUSTCRYPTO_ERR_NULL_OUTPUT,
    RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT, RUSTCRYPTO_OK,
};
use ark_bn254::Fr;
use core::ffi::c_int;
use core::slice;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub const POSEIDON2_BN254_WIDTH: usize = 4;
pub const POSEIDON2_BN254_RATE: usize = 3;
pub const POSEIDON2_BN254_MAX_INPUTS: usize = 12;

/// Poseidon2 round constants and internal diagonal for BN254 `Fr`.
///
/// Vendored verbatim from Noir `bn254_blackbox_solver` (tag v1.0.0-beta.22)
/// via `pso-poseidon` 0.5.0 (MIT). Only the module visibility was adapted to
/// this crate; the hex values must not be edited.
pub(crate) mod constants {
    use ark_bn254::Fr;
    use ark_ff::{MontFp, PrimeField};

    /// Parameters and round constants for a Poseidon2 instance over the field `F`.
    ///
    /// The constants are **field-specific**: BN254's are vendored below, and a
    /// config for any other field would have to be generated for that field's
    /// modulus. Reusing one field's constants under a different field is not a
    /// valid (or secure) Poseidon2 instance.
    pub struct Poseidon2Config<F: PrimeField> {
        /// State width (or state size, number of field elements in the permutation state).
        #[allow(dead_code)] // documents the state width; the impl hardcodes t = 4.
        pub t: u32,

        /// Number of full rounds (also called R_F).
        /// In full rounds, the S-box is applied to all state elements.
        pub rounds_f: u32,

        /// Number of partial rounds (also called R_P).
        /// In partial rounds, the S-box is applied only to the first state element.
        pub rounds_p: u32,

        /// Internal matrix diagonal values used in the linear layer of partial rounds.
        pub internal_matrix_diagonal: [F; 4],

        /// Round constants added to the state in each round.
        pub round_constant: [[F; 4]; 64],
    }

    /// The complete Poseidon2 configuration for BN254 — the only built-in instance,
    /// bit-compatible with noir's in-circuit `poseidon2`.
    pub(crate) static BN254_CONFIG: Poseidon2Config<Fr> = Poseidon2Config {
        // The value of 4 is optimized for a PLONK proving system width of 4,
        // to align with the number of witness columns available in the constraint system.
        t: 4,
        rounds_f: 8,
        rounds_p: 56,
        internal_matrix_diagonal: INTERNAL_MATRIX_DIAGONAL,
        round_constant: ROUND_CONSTANT,
    };

    /// Internal matrix diagonal for Poseidon2 permutation.
    /// These values are used in the internal rounds for linear layer mixing.
    const INTERNAL_MATRIX_DIAGONAL: [Fr; 4] = [
        MontFp!("0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7"),
        MontFp!("0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b"),
        MontFp!("0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15"),
        MontFp!("0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b"),
    ];

    /// Round constants for all rounds of Poseidon2.
    /// Contains 64 rounds, each with 4 field elements.
    const ROUND_CONSTANT: [[Fr; 4]; 64] = [
        [
            MontFp!("0x19b849f69450b06848da1d39bd5e4a4302bb86744edc26238b0878e269ed23e5"),
            MontFp!("0x265ddfe127dd51bd7239347b758f0a1320eb2cc7450acc1dad47f80c8dcf34d6"),
            MontFp!("0x199750ec472f1809e0f66a545e1e51624108ac845015c2aa3dfc36bab497d8aa"),
            MontFp!("0x157ff3fe65ac7208110f06a5f74302b14d743ea25067f0ffd032f787c7f1cdf8"),
        ],
        [
            MontFp!("0x2e49c43c4569dd9c5fd35ac45fca33f10b15c590692f8beefe18f4896ac94902"),
            MontFp!("0x0e35fb89981890520d4aef2b6d6506c3cb2f0b6973c24fa82731345ffa2d1f1e"),
            MontFp!("0x251ad47cb15c4f1105f109ae5e944f1ba9d9e7806d667ffec6fe723002e0b996"),
            MontFp!("0x13da07dc64d428369873e97160234641f8beb56fdd05e5f3563fa39d9c22df4e"),
        ],
        [
            MontFp!("0x0c009b84e650e6d23dc00c7dccef7483a553939689d350cd46e7b89055fd4738"),
            MontFp!("0x011f16b1c63a854f01992e3956f42d8b04eb650c6d535eb0203dec74befdca06"),
            MontFp!("0x0ed69e5e383a688f209d9a561daa79612f3f78d0467ad45485df07093f367549"),
            MontFp!("0x04dba94a7b0ce9e221acad41472b6bbe3aec507f5eb3d33f463672264c9f789b"),
        ],
        [
            MontFp!("0x0a3f2637d840f3a16eb094271c9d237b6036757d4bb50bf7ce732ff1d4fa28e8"),
            MontFp!("0x259a666f129eea198f8a1c502fdb38fa39b1f075569564b6e54a485d1182323f"),
            MontFp!("0x28bf7459c9b2f4c6d8e7d06a4ee3a47f7745d4271038e5157a32fdf7ede0d6a1"),
            MontFp!("0x0a1ca941f057037526ea200f489be8d4c37c85bbcce6a2aeec91bd6941432447"),
        ],
        [
            MontFp!("0x0c6f8f958be0e93053d7fd4fc54512855535ed1539f051dcb43a26fd926361cf"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x123106a93cd17578d426e8128ac9d90aa9e8a00708e296e084dd57e69caaf811"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x26e1ba52ad9285d97dd3ab52f8e840085e8fa83ff1e8f1877b074867cd2dee75"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1cb55cad7bd133de18a64c5c47b9c97cbe4d8b7bf9e095864471537e6a4ae2c5"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1dcd73e46acd8f8e0e2c7ce04bde7f6d2a53043d5060a41c7143f08e6e9055d0"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x011003e32f6d9c66f5852f05474a4def0cda294a0eb4e9b9b12b9bb4512e5574"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2b1e809ac1d10ab29ad5f20d03a57dfebadfe5903f58bafed7c508dd2287ae8c"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2539de1785b735999fb4dac35ee17ed0ef995d05ab2fc5faeaa69ae87bcec0a5"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0c246c5a2ef8ee0126497f222b3e0a0ef4e1c3d41c86d46e43982cb11d77951d"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x192089c4974f68e95408148f7c0632edbb09e6a6ad1a1c2f3f0305f5d03b527b"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1eae0ad8ab68b2f06a0ee36eeb0d0c058529097d91096b756d8fdc2fb5a60d85"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x179190e5d0e22179e46f8282872abc88db6e2fdc0dee99e69768bd98c5d06bfb"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x29bb9e2c9076732576e9a81c7ac4b83214528f7db00f31bf6cafe794a9b3cd1c"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x225d394e42207599403efd0c2464a90d52652645882aac35b10e590e6e691e08"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x064760623c25c8cf753d238055b444532be13557451c087de09efd454b23fd59"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x10ba3a0e01df92e87f301c4b716d8a394d67f4bf42a75c10922910a78f6b5b87"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0e070bf53f8451b24f9c6e96b0c2a801cb511bc0c242eb9d361b77693f21471c"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1b94cd61b051b04dd39755ff93821a73ccd6cb11d2491d8aa7f921014de252fb"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1d7cb39bafb8c744e148787a2e70230f9d4e917d5713bb050487b5aa7d74070b"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2ec93189bd1ab4f69117d0fe980c80ff8785c2961829f701bb74ac1f303b17db"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2db366bfdd36d277a692bb825b86275beac404a19ae07a9082ea46bd83517926"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x062100eb485db06269655cf186a68532985275428450359adc99cec6960711b8"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0761d33c66614aaa570e7f1e8244ca1120243f92fa59e4f900c567bf41f5a59b"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x20fc411a114d13992c2705aa034e3f315d78608a0f7de4ccf7a72e494855ad0d"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x25b5c004a4bdfcb5add9ec4e9ab219ba102c67e8b3effb5fc3a30f317250bc5a"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x23b1822d278ed632a494e58f6df6f5ed038b186d8474155ad87e7dff62b37f4b"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x22734b4c5c3f9493606c4ba9012499bf0f14d13bfcfcccaa16102a29cc2f69e0"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x26c0c8fe09eb30b7e27a74dc33492347e5bdff409aa3610254413d3fad795ce5"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x070dd0ccb6bd7bbae88eac03fa1fbb26196be3083a809829bbd626df348ccad9"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x12b6595bdb329b6fb043ba78bb28c3bec2c0a6de46d8c5ad6067c4ebfd4250da"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x248d97d7f76283d63bec30e7a5876c11c06fca9b275c671c5e33d95bb7e8d729"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1a306d439d463b0816fc6fd64cc939318b45eb759ddde4aa106d15d9bd9baaaa"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x28a8f8372e3c38daced7c00421cb4621f4f1b54ddc27821b0d62d3d6ec7c56cf"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0094975717f9a8a8bb35152f24d43294071ce320c829f388bc852183e1e2ce7e"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x04d5ee4c3aa78f7d80fde60d716480d3593f74d4f653ae83f4103246db2e8d65"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2a6cf5e9aa03d4336349ad6fb8ed2269c7bef54b8822cc76d08495c12efde187"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2304d31eaab960ba9274da43e19ddeb7f792180808fd6e43baae48d7efcba3f3"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x03fd9ac865a4b2a6d5e7009785817249bff08a7e0726fcb4e1c11d39d199f0b0"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x00b7258ded52bbda2248404d55ee5044798afc3a209193073f7954d4d63b0b64"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x159f81ada0771799ec38fca2d4bf65ebb13d3a74f3298db36272c5ca65e92d9a"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1ef90e67437fbc8550237a75bc28e3bb9000130ea25f0c5471e144cf4264431f"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1e65f838515e5ff0196b49aa41a2d2568df739bc176b08ec95a79ed82932e30d"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2b1b045def3a166cec6ce768d079ba74b18c844e570e1f826575c1068c94c33f"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0832e5753ceb0ff6402543b1109229c165dc2d73bef715e3f1c6e07c168bb173"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x02f614e9cedfb3dc6b762ae0a37d41bab1b841c2e8b6451bc5a8e3c390b6ad16"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0e2427d38bd46a60dd640b8e362cad967370ebb777bedff40f6a0be27e7ed705"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0493630b7c670b6deb7c84d414e7ce79049f0ec098c3c7c50768bbe29214a53a"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x22ead100e8e482674decdab17066c5a26bb1515355d5461a3dc06cc85327cea9"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x25b3e56e655b42cdaae2626ed2554d48583f1ae35626d04de5084e0b6d2a6f16"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1e32752ada8836ef5837a6cde8ff13dbb599c336349e4c584b4fdc0a0cf6f9d0"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2fa2a871c15a387cc50f68f6f3c3455b23c00995f05078f672a9864074d412e5"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x2f569b8a9a4424c9278e1db7311e889f54ccbf10661bab7fcd18e7c7a7d83505"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x044cb455110a8fdd531ade530234c518a7df93f7332ffd2144165374b246b43d"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x227808de93906d5d420246157f2e42b191fe8c90adfe118178ddc723a5319025"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x02fcca2934e046bc623adead873579865d03781ae090ad4a8579d2e7a6800355"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x0ef915f0ac120b876abccceb344a1d36bad3f3c5ab91a8ddcbec2e060d8befac"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ],
        [
            MontFp!("0x1797130f4b7a3e1777eb757bc6f287f6ab0fb85f6be63b09f3b16ef2b1405d38"),
            MontFp!("0x0a76225dc04170ae3306c85abab59e608c7f497c20156d4d36c668555decc6e5"),
            MontFp!("0x1fffb9ec1992d66ba1e77a7b93209af6f8fa76d48acb664796174b5326a31a5c"),
            MontFp!("0x25721c4fc15a3f2853b57c338fa538d85f8fbba6c6b9c6090611889b797b9c5f"),
        ],
        [
            MontFp!("0x0c817fd42d5f7a41215e3d07ba197216adb4c3790705da95eb63b982bfcaf75a"),
            MontFp!("0x13abe3f5239915d39f7e13c2c24970b6df8cf86ce00a22002bc15866e52b5a96"),
            MontFp!("0x2106feea546224ea12ef7f39987a46c85c1bc3dc29bdbd7a92cd60acb4d391ce"),
            MontFp!("0x21ca859468a746b6aaa79474a37dab49f1ca5a28c748bc7157e1b3345bb0f959"),
        ],
        [
            MontFp!("0x05ccd6255c1e6f0c5cf1f0df934194c62911d14d0321662a8f1a48999e34185b"),
            MontFp!("0x0f0e34a64b70a626e464d846674c4c8816c4fb267fe44fe6ea28678cb09490a4"),
            MontFp!("0x0558531a4e25470c6157794ca36d0e9647dbfcfe350d64838f5b1a8a2de0d4bf"),
            MontFp!("0x09d3dca9173ed2faceea125157683d18924cadad3f655a60b72f5864961f1455"),
        ],
        [
            MontFp!("0x0328cbd54e8c0913493f866ed03d218bf23f92d68aaec48617d4c722e5bd4335"),
            MontFp!("0x2bf07216e2aff0a223a487b1a7094e07e79e7bcc9798c648ee3347dd5329d34b"),
            MontFp!("0x1daf345a58006b736499c583cb76c316d6f78ed6a6dffc82111e11a63fe412df"),
            MontFp!("0x176563472456aaa746b694c60e1823611ef39039b2edc7ff391e6f2293d2c404"),
        ],
    ];
}

/// `x^5` S-box.
#[inline(always)]
fn single_box(x: Fr) -> Fr {
    let x2 = x * x;
    x2 * x2 * x
}

/// External 4×4 linear layer (Barretenberg's matrix).
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

/// Internal linear layer: multiply by the diagonal, then add the state sum.
#[inline(always)]
fn internal_matrix(state: &mut [Fr; 4]) {
    let mut sum = Fr::from(0u64);
    for x in state.iter() {
        sum += *x;
    }
    let diagonal = &constants::BN254_CONFIG.internal_matrix_diagonal;
    for (i, x) in state.iter_mut().enumerate() {
        *x *= diagonal[i];
        *x += sum;
    }
}

/// Poseidon2 permutation over BN254 `Fr`.
pub(crate) fn poseidon2_bn254_permute_impl(state: [Fr; 4]) -> [Fr; 4] {
    let cfg = &constants::BN254_CONFIG;
    let mut state = state;
    external_matrix(&mut state);

    let rf_first = (cfg.rounds_f / 2) as usize;
    for r in 0..rf_first {
        for (s, c) in state.iter_mut().zip(cfg.round_constant[r].iter()) {
            *s += *c;
        }
        for s in state.iter_mut() {
            *s = single_box(*s);
        }
        external_matrix(&mut state);
    }

    let p_end = rf_first + cfg.rounds_p as usize;
    for r in rf_first..p_end {
        state[0] += cfg.round_constant[r][0];
        state[0] = single_box(state[0]);
        internal_matrix(&mut state);
    }

    let num_rounds = (cfg.rounds_f + cfg.rounds_p) as usize;
    for r in p_end..num_rounds {
        for (s, c) in state.iter_mut().zip(cfg.round_constant[r].iter()) {
            *s += *c;
        }
        for s in state.iter_mut() {
            *s = single_box(*s);
        }
        external_matrix(&mut state);
    }

    state
}

/// Noir/Barretenberg sponge: `iv = len << 64`, absorb `RATE` inputs per block,
/// and only run a final permutation when the last block was partial or empty.
pub(crate) fn poseidon2_bn254_hash_impl(inputs: &[Fr]) -> Fr {
    let len = inputs.len();
    let iv = Fr::from(len as u64) * Fr::from(1u128 << 64);
    let mut state = [Fr::from(0u64), Fr::from(0u64), Fr::from(0u64), iv];

    let full = len / POSEIDON2_BN254_RATE;
    for block in 0..full {
        state[0] += inputs[block * POSEIDON2_BN254_RATE];
        state[1] += inputs[block * POSEIDON2_BN254_RATE + 1];
        state[2] += inputs[block * POSEIDON2_BN254_RATE + 2];
        state = poseidon2_bn254_permute_impl(state);
    }

    for i in 0..(len % POSEIDON2_BN254_RATE) {
        state[i] += inputs[full * POSEIDON2_BN254_RATE + i];
    }

    if len == 0 || len % POSEIDON2_BN254_RATE != 0 {
        state = poseidon2_bn254_permute_impl(state);
    }

    state[0]
}

fn permute_ffi_impl(
    state: *const u8,
    state_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    let required = POSEIDON2_BN254_WIDTH * 32;
    if state_len != required || output_len != required {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    if state.is_null() {
        return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
    }
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }

    let bytes = unsafe { slice::from_raw_parts(state, state_len) };
    let mut values = [Fr::from(0u64); POSEIDON2_BN254_WIDTH];
    for (value, chunk) in values.iter_mut().zip(bytes.chunks_exact(32)) {
        *value = match fr_from_be(chunk) {
            Ok(value) => value,
            Err(err) => return err,
        };
    }

    let permuted = poseidon2_bn254_permute_impl(values);
    // Create the output slice only after all input bytes have been consumed so
    // that an in-place `state == output` call does not create aliasing slices.
    let output = match output_buffer(output, output_len, required) {
        Ok(output) => output,
        Err(err) => return err,
    };
    for (chunk, value) in output.chunks_exact_mut(32).zip(permuted.iter()) {
        chunk.copy_from_slice(&fr_to_be(value));
    }
    RUSTCRYPTO_OK
}

/// Permutes a width-4 state. `state`/`output` are `4 * 32` canonical BE field elements.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_poseidon2_bn254_permute(
    state: *const u8,
    state_len: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        permute_ffi_impl(state, state_len, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

fn hash_ffi_impl(
    inputs: *const u8,
    inputs_len: usize,
    input_count: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    if input_count > POSEIDON2_BN254_MAX_INPUTS {
        return RUSTCRYPTO_ERR_INVALID_PARAMETER;
    }
    let expected_len = match input_count.checked_mul(32) {
        Some(len) => len,
        None => return RUSTCRYPTO_ERR_INVALID_LENGTH,
    };
    if inputs_len != expected_len {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }
    if output.is_null() {
        return RUSTCRYPTO_ERR_NULL_OUTPUT;
    }
    if output_len < 32 {
        return RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT;
    }
    if output_len != 32 {
        return RUSTCRYPTO_ERR_INVALID_LENGTH;
    }

    let bytes: &[u8] = if inputs_len == 0 {
        &[]
    } else {
        if inputs.is_null() {
            return RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA;
        }
        unsafe { slice::from_raw_parts(inputs, inputs_len) }
    };

    let mut values = Vec::with_capacity(input_count);
    for chunk in bytes.chunks_exact(32) {
        match fr_from_be(chunk) {
            Ok(value) => values.push(value),
            Err(err) => return err,
        }
    }

    let digest = poseidon2_bn254_hash_impl(&values);
    // Create the output slice only after all input bytes have been consumed so
    // that an in-place `inputs == output` call does not create aliasing slices.
    let output = match output_buffer(output, output_len, 32) {
        Ok(output) => output,
        Err(err) => return err,
    };
    output.copy_from_slice(&fr_to_be(&digest));
    RUSTCRYPTO_OK
}

/// Hashes `input_count` field elements with the Noir/Barretenberg sponge.
///
/// `input_count` must be `0..=12`. When it is zero, `inputs_len` must be zero
/// and `inputs` may be null. Otherwise `inputs` points to `input_count * 32`
/// canonical big-endian `Fr` values and `output` must be exactly 32 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rustcrypto_poseidon2_bn254_hash(
    inputs: *const u8,
    inputs_len: usize,
    input_count: usize,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        hash_ffi_impl(inputs, inputs_len, input_count, output, output_len)
    }))
    .unwrap_or(crate::RUSTCRYPTO_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT;
    use ark_ff::MontFp;

    fn hash_fields(values: &[Fr]) -> Fr {
        poseidon2_bn254_hash_impl(values)
    }

    fn bytes_of(values: &[Fr]) -> Vec<u8> {
        values.iter().flat_map(|value| fr_to_be(value)).collect()
    }

    fn hash_ffi(values: &[Fr]) -> Fr {
        let bytes = bytes_of(values);
        let mut out = [0u8; 32];
        let status = hash_ffi_impl(
            if bytes.is_empty() {
                core::ptr::null()
            } else {
                bytes.as_ptr()
            },
            bytes.len(),
            values.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(status, RUSTCRYPTO_OK, "hash FFI failed");
        fr_from_be(&out).expect("canonical output")
    }

    #[test]
    fn permutation_kat_zeroes() {
        let out = poseidon2_bn254_permute_impl([Fr::from(0u64); 4]);
        let expected = [
            MontFp!("0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
            MontFp!("0x095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839"),
            MontFp!("0x0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59"),
            MontFp!("0x18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d"),
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn permutation_ffi_matches_native() {
        let values = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let input = bytes_of(&values);
        let mut out = [0u8; 128];
        assert_eq!(
            permute_ffi_impl(input.as_ptr(), input.len(), out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_OK
        );
        for (chunk, expected) in out
            .chunks_exact(32)
            .zip(poseidon2_bn254_permute_impl(values).iter())
        {
            assert_eq!(chunk, &fr_to_be(expected)[..]);
        }
    }

    #[test]
    fn hash_noir_kat_n0_to_n7() {
        let expected = [
            MontFp!("0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
            MontFp!("0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373"),
            MontFp!("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383"),
            MontFp!("0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8"),
            MontFp!("0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9"),
            MontFp!("0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db"),
            MontFp!("0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a"),
            MontFp!("0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238"),
        ];
        for (n, want) in expected.iter().enumerate() {
            let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            assert_eq!(poseidon2_bn254_hash_impl(&inputs), *want, "n = {n}");
            assert_eq!(hash_ffi(&inputs), *want, "FFI n = {n}");
        }
    }

    #[test]
    fn lengths_are_deterministic_and_separated() {
        let lengths = [0usize, 1, 2, 3, 4, 6, 8, 9];
        for &n in lengths.iter() {
            let inputs: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            let first = hash_fields(&inputs);
            assert_eq!(first, hash_fields(&inputs), "deterministic n = {n}");

            let longer: Vec<Fr> = (1..=n as u64 + 1).map(Fr::from).collect();
            assert_ne!(
                first,
                hash_fields(&longer),
                "arity separation n = {n} vs {}",
                n + 1
            );

            if n >= 2 {
                let mut reversed = inputs.clone();
                reversed.reverse();
                assert_ne!(first, hash_fields(&reversed), "order separation n = {n}");
            }
        }
    }

    #[test]
    fn n3_uses_noir_sponge_not_psonet_framing() {
        let inputs: Vec<Fr> = (1..=3u64).map(Fr::from).collect();
        let digest = poseidon2_bn254_hash_impl(&inputs);
        assert_eq!(
            digest,
            MontFp!("0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8")
        );
        assert_ne!(
            digest,
            MontFp!("0x16f5da1a6b40e7d71bcdf29687e7908cdf74da44c09058fe36a0a99e269c6972")
        );
    }

    #[test]
    fn ffi_empty_input_accepts_null() {
        let mut out = [0u8; 32];
        assert_eq!(
            hash_ffi_impl(core::ptr::null(), 0, 0, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_OK
        );
        assert_eq!(
            out,
            fr_to_be(&MontFp!(
                "0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"
            ))
        );
    }

    #[test]
    fn ffi_rejects_invalid_arguments() {
        let one = fr_to_be(&Fr::from(1u64));
        let mut out = [0u8; 32];

        assert_eq!(
            hash_ffi_impl(core::ptr::null(), 0, 13, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_ERR_INVALID_PARAMETER
        );
        assert_eq!(
            hash_ffi_impl(one.as_ptr(), 31, 1, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
        assert_eq!(
            hash_ffi_impl(core::ptr::null(), 32, 1, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            hash_ffi_impl(one.as_ptr(), one.len(), 1, out.as_mut_ptr(), 31),
            RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT
        );
        let non_canonical = [0xffu8; 32];
        assert_eq!(
            hash_ffi_impl(
                non_canonical.as_ptr(),
                non_canonical.len(),
                1,
                out.as_mut_ptr(),
                out.len()
            ),
            RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );
        assert_eq!(
            hash_ffi_impl(one.as_ptr(), one.len(), 1, core::ptr::null_mut(), 32),
            RUSTCRYPTO_ERR_NULL_OUTPUT
        );
    }

    #[test]
    fn ffi_rejects_invalid_permute_arguments() {
        let input = [0u8; 128];
        let mut out = [0u8; 128];
        assert_eq!(
            permute_ffi_impl(input.as_ptr(), 127, out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
        assert_eq!(
            permute_ffi_impl(input.as_ptr(), input.len(), out.as_mut_ptr(), 127),
            RUSTCRYPTO_ERR_INVALID_LENGTH
        );
        assert_eq!(
            permute_ffi_impl(core::ptr::null(), input.len(), out.as_mut_ptr(), out.len()),
            RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA
        );
        assert_eq!(
            permute_ffi_impl(
                input.as_ptr(),
                input.len(),
                core::ptr::null_mut(),
                out.len()
            ),
            RUSTCRYPTO_ERR_NULL_OUTPUT
        );
        let non_canonical = [0xffu8; 128];
        assert_eq!(
            permute_ffi_impl(
                non_canonical.as_ptr(),
                non_canonical.len(),
                out.as_mut_ptr(),
                out.len()
            ),
            RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT
        );
    }
}
