# Poseidon1 Halo2 custom gate（BN254 / IPA）

Rust 実装:

- `rustcrypto-ffi/src/poseidon1_halo2.rs` — Halo2 custom gate、3 入力 hash 回路、KAT
- `rustcrypto-ffi/examples/poseidon1_halo2_ipa.rs` — Poseidon1 / Poseidon2 を同一 IPA params で比較する実測デモ

> **未監査・比較デモ**: 本回路は Poseidon2 Halo2 gate との比較用であり、監査済みの
> 汎用 Halo2 frontend ではない。本番資産の証明にそのまま使わない。
> C ABI / Nim 登録はなく、wasm / ICP 実行面にも追加していない。Rust のみ。

## 1. 何を制約するか

`Poseidon1Halo2Config` は Circom 互換 Poseidon1（幅 4、`R_F = 8`、`R_P = 56`、
`x^5`）の **全 64 round** を Halo2 custom gate で制約する。定数・行列・round
順序は `light-poseidon 0.4.1` の
`parameters::bn254_x5::get_poseidon_parameters::<ark_bn254::Fr>(4)` をそのまま
使う。

Poseidon2 gate（`poseidon2_halo2.rs`）との意図的な違い:

| 項目 | Poseidon1 | Poseidon2 |
|---|---|---|
| 初期状態 | `[0, x0, x1, x2]` | 長さ IV を含む sponge 状態 |
| 初期線形層 | なし | 外部行列 `M(input)` |
| 吸収 | なし（3 入力固定） | rate=3 の sponge 吸収 |
| 最終 permutation | なし（1 permutation） | 3 の非ゼロ倍数では省略 |
| MDS | 4×4 固定行列 | full/partial で別の線形層 |

公開している回路は 1 つ:

| 回路 | 内容 | instance |
|---|---|---|
| `Poseidon1HashCircuit` | 3 入力 Circom Poseidon1 hash（1 permutation） | `[digest, input0, input1, input2]` |

## 2. 行レイアウト

1 permutation = **65 行**。

```text
row base + 0 : state = [0, input0, input1, input2]
row base + r : round r の遷移 r = 0..63
row base + 64: 最終 state（output）
```

- `s_init` は `row base + 0` で lane 0 が 0 であることを制約する。
- `s_round` は `row base + 0 .. base + 63`（S-box 分解用）。
- `s_full` は `row base + 0..3` と `base + 60..63`。
- `s_partial` は `row base + 4..59`。
- round 定数は 4 本の fixed 列に `row base + r` へ割り当てる。
- row 64 は最終状態で、round selector は無効。

hash 回路は permutation が 1 個だけなので、`rows = 65`、instance は 4 行。

## 3. 列

advice 列は 12 本。

| 用途 | 本数 |
|---|---|
| `state[4]` | 4 |
| `pow2[4]`（`(state+RC)^2`） | 4 |
| `pow5[4]`（`(state+RC)^5`） | 4 |

fixed 列は 4 本（round 定数）、selector は 4 個
（`s_init`, `s_round`, `s_full`, `s_partial`）。instance 列は 1 本。
Poseidon2 gate の 25 advice / 5 fixed / 5 selector より小さい。

### degree を 5 以下に保つ理由

vendored `halo2-axiom 0.5.3` は `ConstraintSystem::degree()` を環境変数
`MAX_DEGREE`（既定 5）で cap する。selector を掛けた `x^5` ゲートは degree 6
になり `compress_selectors` が失敗するため、S-box を 2 本の低次ゲートに分解した。

```text
u_i    = state_i + RC[r][i]
pow2_i = u_i^2                 （s_round）
pow5_i = pow2_i^2 * u_i        （s_round）
```

`pow2` / `pow5` は witness 列だが、`s_round` が全 round 行で有効なので
`pow5_i = u_i^5` は各 round で制約される。遷移ゲートは `pow5` を入力に取るため
degree は 4 以下になる。

### MDS は gate 定数

4×4 MDS は witness 列にせず、`Expression::Constant` として gate 式へ埋め込む。
MDS は全 round で同じ固定行列なので、prover が差し替えられる余地はない。
round 定数も fixed 列（VK にコミット）で供給する。

## 4. gate 式

### 初期 lane 0（`s_init`）

```text
state_0(row 0) = 0
```

Circom 互換 Poseidon1 の初期状態は `[0, x0, x1, x2]` であり、長さ IV も初期 MDS
もない。`state_1..3(row 0)` は instance の `input0..2` に直接束縛する。

### full round（`s_full`, r = 0..3, 60..63）

```text
u_i        = state_i + RC[r][i]
pow2_i     = u_i^2
pow5_i     = pow2_i^2 * u_i
state_i'   = sum_j MDS[i][j] * pow5_j
```

### partial round（`s_partial`, r = 4..59）

```text
u_i        = state_i + RC[r][i]        （全 lane に ARK を加算）
b0         = u_0^5 = pow5_0
b1         = u_1, b2 = u_2, b3 = u_3
state_i'   = sum_j MDS[i][j] * b_j
```

Circom Poseidon1 は partial round でも **全 lane に** round 定数を加算し、
S-box は lane 0 のみに適用する。Poseidon2 の partial round とはここが異なる。
`pow5_1..3` は lane 1..3 の `u^5` を制約する補助セルで、partial 遷移には使わない。

### 出力と公開入力

```text
digest = state_0(row 64)
instance = [digest, input0, input1, input2]
```

`state_1..3(row 0)` と `state_0(row 64)` を `constrain_instance` で instance に
束縛する。verifier は期待する公開入力を独立に渡すこと。

## 5. 定数の来歴

- 参照実装: `light-poseidon 0.4.1`
  `src/parameters/bn254_x5.rs` の `get_poseidon_parameters::<F>(4)`。
- 体: BN254 scalar field。`light-poseidon` の `ark_bn254::Fr` と
  `halo2_axiom::halo2curves::bn256::Fr` は同じ BN254 スカラー体なので、
  `into_bigint().to_bytes_le()` の canonical little-endian 32 byte を
  `Fr::from_repr` で変換する。
- `ark`: `params.ark[round * 4 + lane]`。64 round × 4 lane = 256 個。
- `mds`: `params.mds[i][j]`（4×4）。`light-poseidon` のクレートドキュメントに
  よれば、公式 Poseidon スクリプト
  `generate_parameters_grain.sage` で BN254 の modulus・`x^5`・
  `t=4`・`R_F=8`・`R_P=56` を指定して生成された値である。
- 本モジュールは値を再生成・改変せず、`light-poseidon` の公開パラメータを
  バイト単位で変換して使う。

## 6. KAT / テスト

`cargo test --locked --lib poseidon1_halo2` で実行する。

- 入力 `[1, 2, 3]` の KAT:

  ```text
  digest = 0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732
  ```

  この値は `Poseidon::<ark_bn254::Fr>::new_circom(3).hash(&[1,2,3])` と一致する。
  `MockProver::assert_satisfied` / `verify()` も通る。
- `[0,0,0]`, `[1,0,0]`, `[0,1,0]`, `[0,0,1]`, `[1,2,3]`, `[7,8,9]`,
  `[42,43,44]`, `[1000000,2000000,3000000]` で `light-poseidon` と一致。
- 誤った公開 digest は `MockProver::verify()` が Err。
- 出力行を改変した witness、中間 witness を改変した witness は Err。
- 入力を変更すると digest が変わり、旧 digest のままでは拒否され、新 digest
  では受理される。
- **全 64 round** について、round r の次行を改変し、以降の round を正しく
  再計算した witness を作る。selector 有効時は拒否され、round r の selector
  だけを無効化すると受理される。これで各 round の gate が実際に効いている
  ことを確認する。

## 7. 行数と最小 k

| 回路 | rows | instance rows | advice | fixed | selector | degree | 最小 k | usable rows |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Poseidon1 hash（3 入力） | 65 | 4 | 12 | 4 | 4 | 4 | 7 | 122 |

`usable rows = 2^k - (blinding_factors + 1)`。blinding factors は 5。
`2^7 = 128`、usable 122 行で 65 行に収まる。example では Poseidon2 と揃えて
**k = 10** を使う。

## 8. IPA 比較（同一 params・同一 k）

`examples/poseidon1_halo2_ipa.rs` は `halo2-axiom 0.5.3` の IPA を直接使う。

- BN254 G1 / scalar field `Fr`
- `ParamsIPA::<G1Affine>::new(10)` を **1 回だけ**生成し、Poseidon1 と
  Poseidon2 の keygen / prove / verify で共有する。
- `keygen_vk` / `keygen_pk`、`create_proof`（fixture 専用 `StdRng([85; 32])`）、
  `verify_proof`（`SingleStrategy`）を使用。`AccumulatorStrategy` は
  `OsRng` を要求するため使わない。
- 入力は両回路とも `[1, 2, 3]`。
- JSON を stdout、人間向け表を stderr に出す。

実行:

```bash
cd /application/rustcrypto-ffi
cargo run --locked --release --example poseidon1_halo2_ipa
```

native release、2 回実行したうち最終回の実測値（サイズと digest は両回で同一）:

| circuit | rows | instance | advice | selector | degree | vk bytes | pk bytes | proof bytes | keygen ms | prove ms | verify ms | verified | wrong digest rejected |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Poseidon1 | 65 | 4 | 12 | 4 | 4 | 682 | 1,475,438 | 3,488 | 339.493 | 1,076.713 | 19.014 | true | true |
| Poseidon2 | 65 | 4 | 25 | 5 | 4 | 1,194 | 2,524,654 | 5,728 | 499.312 | 985.457 | 22.768 | true | true |

共通:

- `shared_params = true`、`params_ms = 580.746`（k=10 の `ParamsIPA::new` 1 回）。
- `tampered_proof_rejected = true`（両回路）。
- Poseidon1 digest:
  `0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732`
  （`light_poseidon_matches = true`）。
- Poseidon2 digest:
  `23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8`
  （`docs/poseidon2-halo2-gate.md` の値と一致）。

相対値:

- rows / instance は同じ 65 / 4。比較は同一 k・同一 params・同一入力で成立。
- **サイズは決定的**で、実行間で同じ: VK は 682 / 1,194 ≈ **0.57 倍**、
  PK は 1,475,438 / 2,524,654 ≈ **0.58 倍**、proof は
  3,488 / 5,728 ≈ **0.61 倍**。advice 列が 12 vs 25、selector が 4 vs 5 と
  小さいことが効いている。
- keygen は 2 回の実行で Poseidon1 が 238.6 / 339.5 ms、Poseidon2 が
  478.3 / 499.3 ms で、Poseidon1 の方が小さい。
- **prove / verify の wall time は回路サイズ差より実行ノイズが大きい**。
  同じ example の 2 回で Poseidon1 prove は 912.6 → 1,076.7 ms、Poseidon2 は
  1,499.9 → 985.5 ms と逆転した。verify も Poseidon1 23.7 → 19.0 ms、
  Poseidon2 20.7 → 22.8 ms だった。**prove/verify の優劣はこの 1〜2 回の
  実測だけでは主張しない**。サイズ・keygen の差は再現している。

**注意**:

- `proof_bytes` はこの回路・この PCS（IPA/BGH19、k=10、instance 4）に対する
  値であり、プロトコル固定の proof size ではない。回路形状、k、multi-open の
  開点数で変わる。
- 時間は 1 環境・1 実行の wall time であり、同一マシン内の相対比較として読む。
- params は回路非依存なので Poseidon1 / Poseidon2 で共有できる。共有できない
  PCS 実装では回路ごとに params を作る必要があるが、本実測では 1 個を共有した。

## 9. 明示的な限界

- **未監査**: 比較デモであり、本番用途の監査済み回路ではない。
- **C ABI / Nim 未登録**: `cargo` の Rust typed API と example のみ。既存
  `rustcrypto_halo2_ipa_bn254_*` の circuit id レジストリには追加していない。
- **wasm / ICP 未対応**: 本回路の wasm32-unknown-unknown / wasm32-wasip1 /
  browser / ICP canister 実行は未実装・未検証。
- **入力は 3 固定**: Circom Poseidon1 の可変長入力や他 width（2..13）は
  本 gate の対象外。
- **Poseidon2 との比較範囲**: 同じ Halo2 IPA 形状での rows / VK / PK / proof /
  keygen / prove / verify を比較した。R1CS / Groth16、WASM instructions、
  ICP cycles、Spartan+WHIR gadget は別タスク。
- **proof bytes は再現しない可能性がある**: vendored prover が内部で
  `thread_rng()` を使う箇所があるため、同一 seed でも byte-identical では
  ない（検証結果には影響しない）。
