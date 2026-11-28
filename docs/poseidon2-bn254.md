# Poseidon2 over BN254

Module: `rustcrypto/algorithm/poseidon2`（marker type `Poseidon2Bn254`）

Rust 実装: `rustcrypto-ffi/src/poseidon2.rs`（ネイティブ/C ABI）、
`rustcrypto-ffi/src/poseidon2_gadget.rs`（R1CS gadget）。
既存の Poseidon1（`PoseidonBn254` / `light-poseidon`）とは別モジュール・別 API であり、
Poseidon1 の定数・出力・幅4最適化は変更しない。

## 固定パラメータプロファイル

- Field: BN254 scalar field `Fr`。
- 状態幅 `t = 4`、rate `3`、capacity `1`。
- S-box: `x^5`。
- Full rounds `R_F = 8`、partial rounds `R_P = 56`（合計 64 round）。
- 外部線形層: Barretenberg / Noir の 4×4 行列。
- 内部線形層: 内部対角 `diag[4]` を掛けてから全状態の和を加算。
- round 順序: 初期 4×4 行列 → full 4 round → partial 56 round →
  full 4 round。round constant の index は `0..64` を参照実装どおりに使用。

異なる round 定数・行列・S-box・round 順序を持つ「Poseidon2/BN254」とは
**互換ではない**。Horizen Labs 系の別幅・旧定数とも混同しないこと。

## 来歴・revision・ライセンス

round 定数（64×4）と内部対角（4要素）は、以下の参照実装から**値そのまま**を
vendoring している。16進値は編集禁止。

- 直接の取得元: `pso-poseidon` 0.5.0（MIT、
  <https://github.com/psonet/pso-poseidon>）の
  `src/poseidon2/constants.rs`。
- 上流: Noir `bn254_blackbox_solver` の `poseidon2_constants`
  （tag `v1.0.0-beta.22`）。Noir 本体は Apache-2.0。
- 本リポジトリでの変更: `ark` 0.5 の `Fr` 型に合わせた import と可視性のみ。
  定数の値・行列・round 数は変更していない。

参照実装との対応:

- `pso-poseidon` の `Poseidon2::permutation` と本実装の permutation は一致する。
- `pso-poseidon` の `Poseidon2::hash_noir` と本実装の hash は一致する。

## スポンジの framing（Noir / Barretenberg）

本 API の `hash` は **Noir/Barretenberg のスポンジ**である。

```text
iv = Fr(len) * Fr(1 << 64)
state = [0, 0, 0, iv]                  # rate 3 + capacity 1
for each full block of 3 inputs:
    state[0..3] += block
    state = permute(state)
remaining = len % 3
state[0..remaining] += remaining inputs
if len == 0 || len % 3 != 0:
    state = permute(state)
output = state[0]
```

重要: 入力長が rate の非ゼロ倍数（3, 6, 9, 12）のとき、**最後の permutation を
行わない**。`pso-poseidon` の `PoseidonHasher::hash`（psonet の `hash2.nr` framing）
は常に最終 permutation を行うため、`len` が 3 の倍数のとき結果が異なる。

例（入力 `[1, 2, 3]`）:

| framing | 出力 |
|---|---|
| Noir/Barretenberg（本 API） | `23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8` |
| psonet（常に最終 permutation） | `16f5da1a6b40e7d71bcdf29687e7908cdf74da44c09058fe36a0a99e269c6972` |

本 API は前者を採用する。

## wire encoding

- すべての field 要素は **canonical な 32 byte big-endian BN254 `Fr`**。
- 法 `Fr::MODULUS` 以上の値は **受理しない**。暗黙の mod reduction は行わない。
- 出力も canonical 32 byte big-endian `Fr`。
- `input_count` は `0..=12`。0 のとき `inputs_len == 0` かつ `inputs` は
  `NULL` を許容する。1 以上では `inputs_len == input_count * 32` かつ
  `inputs` は非 `NULL` でなければならない。
- permutation の state は 4 要素 = 128 byte ちょうど。hash の output は 32 byte
  ちょうど。

空入力（`input_count == 0`）は許容され、`iv = 0` の状態から 1 回 permutation を
行った値（permutation の zero-state KAT と同じ値）を返す。

## API の分離

- **permutation**: 幅4状態 `[Fr; 4]` をそのまま置換する。sponge framing や
  length IV は含まない。
- **hash**: Noir/Barretenberg の固定長スポンジ。長さ IV の吸収、rate 3 の
  ブロック処理、最終 permutation の有無まで含む。

両者は別 API であり、hash の内部で permutation を呼ぶ。アプリケーションの
domain separation（例: 最初の field 要素に domain tag を置く）は呼出側の責務で
あり、本モジュールは付加しない。

## C ABI

```c
int rustcrypto_poseidon2_bn254_permute(
    const uint8_t *state, size_t state_len,
    uint8_t *output, size_t output_len);

int rustcrypto_poseidon2_bn254_hash(
    const uint8_t *inputs, size_t inputs_len, size_t input_count,
    uint8_t *output, size_t output_len);
```

- `permute`: `state_len == output_len == 128`。`state` は 4 個の canonical BE
  `Fr`。`output` は 128 byte。
- `hash`: `input_count <= 12`。`input_count > 0` なら
  `inputs_len == input_count * 32`。`output_len == 32`。
- 出力バッファは呼出側が所有する。Rust 側は出力ポインタへ書き込むだけで、
  Rust 所有メモリを返さない。
- すべての exported 関数は `catch_unwind` で panic を境界外に出さない。
  戻り値は既存の `RUSTCRYPTO_*` status code。

主なエラー:

| 条件 | status |
|---|---|
| `input_count > 12` | `RUSTCRYPTO_ERR_INVALID_PARAMETER` |
| `inputs_len` 不一致、長さが 128/32 でない | `RUSTCRYPTO_ERR_INVALID_LENGTH` |
| 非 `NULL` 長の入力に `NULL` | `RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA` |
| `NULL` 出力 | `RUSTCRYPTO_ERR_NULL_OUTPUT` |
| 出力が短い | `RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT` |
| 非 canonical `Fr` | `RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT` |
| 内部 panic | `RUSTCRYPTO_ERR_PANIC` |

## Nim type-first API（想定インターフェース）

Nim wrapper は別タスクで実装する。公開面は marker type を namespace にした
type-first API とする。

```nim
import rustcrypto/algorithm/bn254
import rustcrypto/algorithm/poseidon2

let state: array[4, Bn254Fr] = [a, b, c, d]
let permuted = Poseidon2Bn254.permute(state)

let digest = Poseidon2Bn254.hash([a, b, c])
echo digest.frToHex
```

- `Poseidon2Bn254.permute(state: array[4, Bn254Fr]): array[4, Bn254Fr]`
- `Poseidon2Bn254.hash(inputs: openArray[Bn254Fr]): Bn254Fr`
- 入力個数は `0..Poseidon2Bn254MaxInputs`（12）。非 canonical 値は
  `ValueError` とし、暗黙 reduction は行わない。
- 低水準の `poseidon2Bn254PermuteRaw` / `poseidon2Bn254HashRaw` は
  `rustcrypto/algorithm/ffi` に閉じ込め、通常のアプリコードから直接使わない。

## R1CS gadget

`rustcrypto-ffi/src/poseidon2_gadget.rs` はネイティブ実装と同じ定数・round
順序・線形層・Noir sponge を使う `FpVar<Fr>` gadget を提供する。

```rust
pub fn permute(state: [FpVar<Fr>; 4]) -> Result<[FpVar<Fr>; 4], SynthesisError>;
pub fn hash(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError>;
```

- round 定数と内部対角は `FpVar::Constant` として扱い、追加 witness を
  割り当てない。S-box と状態間の乗算のみが制約になる。
- `hash` は `0..=12` 入力を受け付け、それ以上は
  `SynthesisError::Unsatisfiable` を返す。
- ark-r1cs-std / ark-relations は既存の 0.5 系を使用する。

## 既知のテストベクトル（KAT）

permutation、4 要素すべて 0:

```text
0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e
0x095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839
0x0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59
0x18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d
```

Noir hash、入力 `Fr(1), ..., Fr(n)`:

| n | output |
|---|---|
| 0 | `0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e` |
| 1 | `0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373` |
| 2 | `0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383` |
| 3 | `0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8` |
| 4 | `0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9` |
| 5 | `0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db` |
| 6 | `0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a` |
| 7 | `0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238` |

Rust 側は permutation KAT、`n = 0..=7` の hash KAT、`n = 0,1,2,3,4,6,8,9` の
決定性・arity 分離・順序分離、`n = 3` が psonet framing と異なること、FFI 異常系、
gadget とネイティブの一致を `cargo test --lib poseidon2` で確認する。

## WASM / 実行環境

- RNG、スレッド、OS 時刻、ファイル I/O、ネットワークに依存しない。
  入力から決定的に計算する純粋関数である。
- `std` の `catch_unwind` はネイティブ C ABI 用。WASM では panic 戦略に従うが、
  本モジュールは入力検証後に panic し得る操作（unwrap 等）を行わない。
- 固定幅・固定長の小さな処理であり、Verify-only canister での利用を想定して
  入力個数と長さを事前に制限する。
- `ci/test_poseidon2_wasm.sh` で `wasm32-wasip1`（WASI command）と
  `wasm32-unknown-unknown`（cdylib）の KAT を実行済み。後者は import 0 件で
  実行でき、RNG・ホストサービスを要求しないことを確認している。

## セキュリティ上の注意

- 本実装は**監査済みではない**。本番資産の保護を保証しない。
- round 定数・行列・round 数・sponge framing は互換性契約である。変更すると
  別ハッシュになる。
- 入力は canonical 32 byte BE のみを受理する。呼出側で hex/bytes から変換する
  場合は、法以上の値を拒否すること。
- domain separation は呼出側の責務。用途ごとに domain tag や入力順序を固定し、
  Poseidon1 や他プロファイルの出力と混用しない。
- 許容入力数は 12 に制限している。これは API 上の上限であり、暗号学的な
  安全性の上限ではない。
- 入力は秘密情報を含み得るが、本モジュールはログ出力や zeroize を行わない。
  呼出側のバッファ管理に従う。

## 未実装・対象外

- **Poseidon2 の Halo2 custom gate は別モジュールで実装済み**。
  [`poseidon2-halo2-gate.md`](poseidon2-halo2-gate.md) を参照。ネイティブの
  Rust typed API/example のみで、Nim/C ABI の circuit id には未登録。
- Poseidon1 と Poseidon2 の Halo2 rows/proof size 比較は、Poseidon1 の Halo2
  gate が無いため apples-to-apples ではない。R1CS 制約数・nnz・native 時間・
  ICP Poseidon2 hash instructions は [`benchmarks-branch85.md`](benchmarks-branch85.md)
  と [`ic-branch85.md`](ic-branch85.md) に記録。
- Spartan/WHIR 側の Poseidon2 gadget は Spartan+WHIR 自体が blocked のため未実装。
