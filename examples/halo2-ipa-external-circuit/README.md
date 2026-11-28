# External Halo2 IPA circuit example

A standalone Cargo crate that registers its **own** Halo2 IPA / BN254 circuits
with `rustcrypto-ffi` at compile time. It does not modify any `rustcrypto-ffi`
source file.

```text
cargo test --manifest-path examples/halo2-ipa-external-circuit/Cargo.toml
```

## What it demonstrates

- `ChainCircuit` (id `0x10001`): a 16-step `acc = acc^2 + input` chain with a
  real custom gate `q * (acc_prev^2 + input - acc)`, private advice cells, and a
  single instance column carrying **17 public `Fr` values**
  `[acc_1, .., acc_15, input_0, input_15]`.
- `LinearCircuit` (id `0x10002`): the additive analogue, used to show that a
  proof is bound to its VK and that a verifier-only adapter can be exported.
- `halo2_ipa_export_circuit!(ChainCircuit, chain_adapter)` exports
  `chain_adapter_prepare`, `chain_adapter_prove`, `chain_adapter_verify`,
  `chain_adapter_vk_validate`, `chain_adapter_pk_validate`,
  `chain_adapter_proof_validate`, and `chain_adapter_instances_validate`.
- `halo2_ipa_export_circuit_verifier!` exports only the verifier-side symbols.

The tests cover the two-call sizing convention, prepare/prove/verify, independent
expected public instances, wrong VK/circuit id, a different circuit's key,
tampered proofs, non-canonical / trailing / oversized encodings, VK digest
pinning, and V1-magic key rejection.

## Adapter requirements

See the `rust_crypto_ffi::halo2_ipa_registry` module documentation. In short:
`Params = ()`, `SimpleFloorPlanner`, deterministic layout, `without_witnesses()`
with the same shape, `Default`, and `synthesize` must bind public instance cells
with `layouter.constrain_instance(...)`.

## Verifier-only consumers

Use `halo2_ipa_export_circuit_verifier!` and enable
`rustcrypto-ffi/halo2-ipa-verify-only`. The full export macro emits keygen and
prover code and therefore requires the default prover build.

Keys use the V2 envelopes (`RCH2IPV2` / `RCH2IPP2`); proofs and instances use
the unchanged `RCH2IPF1` / `RCH2IPI1` formats.
