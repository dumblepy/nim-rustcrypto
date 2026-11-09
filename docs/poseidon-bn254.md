# Poseidon over BN254

Module: `rustcrypto/algorithm/poseidon` (marker type `PoseidonBn254`)

## Fixed parameter profile

- Field: BN254 scalar field `Fr`.
- Parameters: `light-poseidon` 0.4.1, **`bn254_x5`**.
  - S-box: `x^5`.
  - 8 full rounds, partial rounds per state width.
  - Constants compatible with Circom's `Poseidon` implementation for widths `2..=13`.
- The state width is inferred as `inputs.len + 1`, using `Poseidon::new_circom(inputs.len)`.
- Input count: `1..=12`.
- Domain tag: zero (the plain Circom `Poseidon` variant).

A Poseidon implementation with different round constants, S-box, width convention, or
domain tag is **not** interchangeable with this API, even if it is also called
"Poseidon/BN254".

## API

```nim
import rustcrypto/algorithm/bn254
import rustcrypto/algorithm/poseidon

let a = fromHexFr("01".repeat(32))  # 32 bytes of 0x01
let b = fromHexFr("02".repeat(32))  # 32 bytes of 0x02
let digest = PoseidonBn254.hash([a, b])
echo digest.frToHex
```

Inputs are canonical big-endian `Fr` values. Non-canonical values raise `ValueError`;
they are never reduced implicitly. Empty input arrays and more than 12 inputs raise
`ValueError`.

## Known vector (light-poseidon README)

Inputs (each 32 bytes of the repeated byte):

```text
[0x01 x 32, 0x02 x 32]
```

Output:

```text
0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990
```

This vector is asserted by both the Rust and Nim tests.

## C ABI

```c
int rustcrypto_poseidon_bn254_hash(
    const uint8_t *inputs, size_t inputs_len, size_t input_count,
    uint8_t *output, size_t output_len);
```

`inputs_len` must equal `input_count * 32`, `input_count` must be `1..=12`, and
`output_len` must be at least 32. The output is canonical big-endian `Fr`.

## Security notes

- Poseidon parameters are part of the compatibility contract. Do not use this output
  interchangeably with "Poseidon" implementations that use different parameters.
- Domain separation is the caller's responsibility. This module implements the plain
  hash; it does not add application-specific prefixes.
- The implementation is not audited.
