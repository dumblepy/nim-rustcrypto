# Poseidon2 Halo2 custom gate（BN254 / IPA）

Rust 実装:

- `rustcrypto-ffi/src/poseidon2_halo2.rs` — Halo2 custom gate、permutation / sponge 回路、KAT
- `rustcrypto-ffi/examples/poseidon2_halo2_ipa.rs` — IPA prove/verify の実測デモ

Poseidon2 のネイティブ実装・定数の来歴は
[`poseidon2-bn254.md`](poseidon2-bn254.md) のまま変更していない。本ドキュメントは
**Halo2 回路だけ**を対象にした追加実装である。

## 1. 何を制約するか

`Poseidon2Halo2Config` は 1 つの Poseidon2 permutation（幅 4、`R_F = 8`、
`R_P = 56`、`x^5`）の**全 64 round**を Halo2 custom gate で制約する。
Noir/Barretenberg の外部行列・内部対角・round 定数・round 順序は
`src/poseidon2.rs` の vendoring 値をそのまま使う。

2 つの回路を公開している。

| 回路 | 内容 | instance |
|---|---|---|
| `Poseidon2PermutationCircuit` | 1 permutation | `[input0..3, output0..3]` |
| `Poseidon2HashCircuit` | Noir/Barretenberg sponge（0..=12 入力） | `[digest, input0..input_{n-1}]` |

## 2. 行レイアウト

1 permutation = **65 行**。

```text
row base + 0 : state = M(input)        （初期外部行列）
row base + r : round r の遷移 r = 0..63
row base + 64: 最終 state
```

- `s_init` は `row base + 0`。
- `s_round` は `row base + 0 .. base + 63`（S-box 分解用）。
- `s_full` は `row base + 0..3` と `base + 60..63`。
- `s_partial` は `row base + 4..59`。
- `s_absorb` は sponge の吸収行（各 permutation の `base + 0`）。

hash 回路では permutation block を `65` 行ずつ並べ、sponge の吸収を各 block の
`base + 0` 行で行う。raw 入力セルは同じ行の `absorb` 列に置くため、行数は
`65 * permutation 数` のまま増えない。

## 3. 列

advice 列は 25 本。

| 用途 | 本数 |
|---|---|
| `state[4]` | 4 |
| `input[4]`（初期行列前の状態） | 4 |
| `prev[4]`（吸収前の状態） | 4 |
| `absorb[4]`（吸収値。capacity は 0） | 4 |
| `pow2[4]`（`(state+RC)^2`） | 4 |
| `pow5[4]`（`(state+RC)^5`） | 4 |
| `raw`（hash の公開入力セル） | 1 |

fixed 列は 5 本（round 定数 4 + 定数用 1）。selector は 5 個
（`s_init`, `s_round`, `s_full`, `s_partial`, `s_absorb`）。

### degree を 5 以下に保つ理由

vendored `halo2-axiom 0.5.3` は `ConstraintSystem::degree()` を環境変数
`MAX_DEGREE`（既定 5）で cap する。selector を掛けた `x^5` ゲートは
degree 6 になり `compress_selectors` が失敗するため、S-box を 2 本の
低次ゲートに分解した。

```text
u_i    = state_i + RC[r][i]
pow2_i = u_i^2                 （s_round）
pow5_i = pow2_i^2 * u_i        （s_round）
```

`pow2` / `pow5` は witness 列だが、`s_round` が全 round 行で有効なので
`pow5_i = u_i^5` は各 round で制約される。遷移ゲートは `pow5` を入力に取るため
degree は 4 以下になる。テストでは vendored `ark_bn254::Fr` 実装との一致も
確認している。

## 4. gate 式

### 初期外部行列（`s_init`）

```text
state_i(row 0) = M(input)_i
```

`M` は Barretenberg の 4×4 外部行列。

```text
out0 = 5*s0 + 7*s1 + 1*s2 + 3*s3
out1 = 4*s0 + 6*s1 + 1*s2 + 1*s3
out2 = 1*s0 + 3*s1 + 5*s2 + 7*s3
out3 = 1*s0 + 1*s1 + 4*s2 + 6*s3
```

### full round（`s_full`, r = 0..3, 60..63）

```text
u_i        = state_i + RC[r][i]
pow2_i     = u_i^2
pow5_i     = pow2_i^2 * u_i
state_i'   = M(pow5)_i
```

### partial round（`s_partial`, r = 4..59）

```text
b0 = (state_0 + RC[r][0])^5   （= pow5_0）
b1 = state_1, b2 = state_2, b3 = state_3
sum = b0 + b1 + b2 + b3
state_i' = b_i * diag_i + sum
```

`RC[r][1..3]` は参照実装どおり partial round では 0 なので、`pow5_1..3` は
`state_1..3^5` を制約するだけの補助セルになる（遷移には使わない）。

### sponge 吸収（`s_absorb`）

```text
input_i = prev_i + absorb_i
```

- block 0 の `prev` は `[0, 0, 0, len << 64]` を
  `assign_advice_from_constant` で固定する。
- 2 block 目以降の `prev` は直前 permutation の row 64 の state セルと
  `constrain_equal` でコピーする。
- `absorb_0..2` は対象の raw 入力セルと `constrain_equal` する。
- capacity の `absorb_3` は 0。
- raw 入力セルと digest セルは instance 列に `constrain_instance` する。

sponge framing は Noir/Barretenberg のまま。

```text
iv = len << 64
state = [0, 0, 0, iv]
for each full block of 3: state[0..3] += block; state = permute(state)
剩余 = len % 3: state[0..剩余] += 残り
if len == 0 || len % 3 != 0: state = permute(state)
digest = state[0]
```

つまり 3 の非ゼロ倍数では最終 permutation を**行わない**。この分岐も
回路の permutation 数（後述）に反映される。

## 5. 行数と最小 k

`MockProver` / `ConstraintSystem` から計測した値。

| 回路 / 入力数 n | permutation 数 | rows | instance rows | 最小 k | usable rows |
|---|---:|---:|---:|---:|---:|
| permutation | 1 | 65 | 8 | 7 | 122 |
| hash n=0 | 1 | 65 | 1 | 7 | 122 |
| hash n=1 | 1 | 65 | 2 | 7 | 122 |
| hash n=2 | 1 | 65 | 3 | 7 | 122 |
| hash n=3 | 1 | 65 | 4 | 7 | 122 |
| hash n=4 | 2 | 130 | 5 | 8 | 250 |
| hash n=6 | 2 | 130 | 7 | 8 | 250 |
| hash n=8 | 3 | 195 | 9 | 8 | 250 |
| hash n=9 | 3 | 195 | 10 | 8 | 250 |
| hash n=12 | 4 | 260 | 13 | 9 | 506 |

`usable rows = 2^k - (blinding_factors + 1)`（この回路では blinding = 5）。

- `ConstraintSystem`: degree 4、advice 25、fixed 5、selector 5、
  blinding factors 5、minimum rows 8。
- 最小 k は `2^k - (blinding + 1) >= rows` と
  `2^k >= minimum_rows` から算出。
- 例では余裕を見て **k = 10** を使う（n=3 の最小は k=7）。

## 6. KAT / テスト

`cargo test --locked --lib poseidon2_halo2` で 9 tests。

- permutation zero-state KAT:
  `18dfb8dc...6732e`, `095c230d...f839`, `0bb95458...aa59`,
  `18a4f34c...ed6d` を `MockProver::assert_satisfied`。
- 出力セルを改変した witness は `MockProver::verify()` が Err。
- **全 64 round** について、round r の次行を改変し、以降の round を正しく
  再計算した witness を作る。selector 有効時は拒否され、round r の selector
  だけを無効化すると受理される。これで各 round の gate が実際に効いている
  ことを確認する。
- hash KAT: n = 0, 1, 2, 3, 4, 6, 8, 9, 12 で
  `poseidon2_bn254_hash_impl`（vendored `ark_bn254::Fr`）と一致。
- 誤った公開 digest は `MockProver::verify()` が Err。
- 入力を変更すると digest が変わり、旧 digest のままでは拒否され、
  新 digest では受理される。
- 12 入力超は `Error::Synthesis`。

代表値（入力 `[1,2,3]`）:

```text
digest = 23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8
```

これは `docs/poseidon2-bn254.md` の Noir/Barretenberg framing の値と一致する。

## 7. IPA プロファイルと実測

`examples/poseidon2_halo2_ipa.rs` は以下を使う。

- `halo2-axiom 0.5.3`（vendored、既存 KZG と同じコピー）
- BN254 G1 / scalar field `Fr`
- IPA `ParamsIPA::<G1Affine>::new(k)`（決定的 hash-to-curve、SRS 不要）
- BGH19 multi-open、Blake2b transcript
- 検証は `SingleStrategy`（`AccumulatorStrategy` は `OsRng` を要求するため
  wasm 非対応）。本回路は `wasm32-wasip1` でも実行済み
  （[`poseidon2-halo2-wasm.md`](poseidon2-halo2-wasm.md)）
- 証明用 RNG は fixture 専用の固定 `StdRng` seed（本番は `OsRng`）

実行:

```text
cd rustcrypto-ffi
cargo run --locked --release --example poseidon2_halo2_ipa
```

n=3、k=10 の実測（Ubuntu native、release、1 回の実行。時間は実行ごとに
変動する）:

```json
{
  "k": 10,
  "rows": 65,
  "instance_rows": 4,
  "advice_columns": 25,
  "selectors": 5,
  "gate_degree": 4,
  "vk_bytes": 1194,
  "pk_bytes": 2524654,
  "proof_bytes": 5728,
  "keygen_ms": 924.392,
  "prove_ms": 720.744,
  "verify_ms": 18.235,
  "digest": "23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8",
  "proof_verified": true,
  "wrong_digest_rejected": true,
  "tampered_proof_rejected": true
}
```

別実行では keygen 831 ms / prove 857 ms / verify 16.7 ms 程度だった。
`vk_bytes` / `pk_bytes` は `SerdeFormat::Processed` のシリアライズ長、
`proof_bytes` は transcript 長。proof は vendored prover が内部で
`thread_rng()` を使う箇所があるため byte-identical ではない。

## 8. セキュリティ上の注意

- **未監査**: 本 custom gate はデモ用であり、監査済みの汎用 Halo2
  frontend ではない。本番資産の証明にそのまま使わない。
- **Poseidon2 パラメータ**: 定数・行列・round 順序・sponge framing の
  来歴と値は `poseidon2-bn254.md` から変更していない。別 field・別幅・
  Horizen 系旧定数とは互換でない。
- **round 定数は fixed 列**: 検証鍵にコミットされるため prover は変更
  できないが、VK の pin / circuit id の承認は利用側の責務。
- **degree 分解**: `pow2` / `pow5` は witness だが、`s_round` が全 round 行で
  有効であり、`pow5 = u^5` と遷移の両方が制約される。テストで全 round の
  selector を個別に無効化して確認している。
- **公開入力 binding**: hash 回路は raw 入力と digest の両方を instance に
  拘束する。verifier は期待する公開入力を独立に渡すこと。
- **fixture RNG**: 例の固定 seed はテスト専用。本番の IPA blinding には
  OS CSPRNG を使う。
- **wasm**: native と `wasm32-wasip1` で keygen/prove/verify を実行済み
  （[`poseidon2-halo2-wasm.md`](poseidon2-halo2-wasm.md)）。browser Worker /
  ICP canister でのこの回路自体の prove は未実行。

## 9. 明示的な未達・ギャップ

- **Nim/C ABI の Poseidon2 Halo2 circuit id は登録済み**（2026-11 更新）。
  `rustcrypto_halo2_ipa_bn254_*` の `circuit_id = 2`
  （`HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1`）として、**3 入力固定**の
  `Poseidon2HashCircuit` を扱う。witness は 3 個の canonical BE `Fr`
  （96 バイト）、公開入力は 1 列 `[digest, input0, input1, input2]`、`k >= 7`。
  Nim 側は `Halo2IpaBn254CircuitPoseidon2Hash3V1` と
  `encodePoseidon2HashInstances` を提供する。fixture は
  `tests/fixtures/halo2_ipa_poseidon2_v1.hex`。
- **arity は 3 固定**。`Poseidon2HashCircuit` 自体は 0..=12 入力を扱えるが、
  C ABI に登録したのは 3 入力の 1 変種だけである。任意 arity を登録するには
  回路 id の追加と固定列レイアウトのレビューが必要。
- **Poseidon1 の Halo2 custom gate は比較用に実装済み**
  （[`poseidon1-halo2-gate.md`](poseidon1-halo2-gate.md)）。同一 k=10・同一 IPA
  での rows/VK/PK/proof 比較は [`benchmarks-branch85.md`](benchmarks-branch85.md)
  に記録。width 4・3 入力固定の比較デモであり、C ABI/Nim には未登録。
- **wasm/ICP 実行**: Poseidon2 回路自体は `wasm32-wasip1` で実行済み。
  browser Worker / ICP canister での Poseidon2 gate prove、および任意 arity の
  回路登録は未対応。canister verifier は circuit id 2 の VK/証明を検証できる
  （`halo2-ipa-params-cache` 併用可）。
- 汎用回路記述子・Noir frontend・VK 復元レジストリへの任意 Poseidon2 登録は
  未実装。
- Spartan+WHIR 側の Poseidon2 gadget、Poseidon1 との制約数・WASM
  instructions/cycles の実測比較は別タスク。
