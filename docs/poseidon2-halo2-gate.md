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

3 つの公開 API を提供している。

| 型 | 内容 | instance |
|---|---|---|
| `Poseidon2PermutationCircuit` | 1 permutation | `[input0..3, output0..3]` |
| `Poseidon2HashCircuit` | Noir/Barretenberg sponge（0..=12 入力） | `[digest, input0..input_{n-1}]` |
| `Poseidon2Chip` | 呼び出し側の既存セルに sponge / permutation を接続する再利用部品 | 触らない（呼び出し側が公開セルを選ぶ） |

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

### 再利用可能な `Poseidon2Chip`（秘密入力）

`Poseidon2HashCircuit` は raw 入力と digest をすべて instance に公開する
単体回路である。より大きな回路（Note / Merkle / 複合 statement）で秘密
preimage を扱うため、`Poseidon2Chip` を公開している。

```rust
let config = Poseidon2Chip::configure(meta);      // configure 時
let chip = Poseidon2Chip::new(config.clone());    // synthesize 時

// 呼び出し側が既に割り当て・制約したセルと値を渡す。
let inputs = [Poseidon2Input { cell, value }, ...];
let state = chip.hash(&mut region, base, &inputs)?; // 最終 state セル
let digest = state[0];                              // 必要なら自前で公開
```

契約:

- `Poseidon2Input { cell: Cell, value: Value<Fr> }` の `value` は `cell` に
  既に割り当てた値（keygen 時は `Value::unknown()`）と一致させる。
- Chip は各入力セルを absorb lane に `constrain_equal` で copy し、sponge /
  permutation を制約して **最終 state の 4 セル**を返す。状態遷移のセルは
  呼び出し側の region に割り当てられる。
- Chip は instance 列を一切触らない。**公開するセルは呼び出し側が選ぶ**。
  入力の全公開、digest の自動公開、host 計算 digest の無制約な受け渡しは
  行わない。
- `inputs.len()` は `0..=12` で、回路形状として固定する。同一 Chip を同一
  region で繰り返し呼び出せる（連鎖 hash、複数 hash、public/private 混在）。
- `without_witnesses` でも同じ layout になるため、keygen に使える。
- chip の `permutation` は 4 セルを受け取り、最終 state を返す。

### 未使用 lane の zero 制約（P0 修正）

sponge の各 block で、実入力が入らない **すべての rate lane** と
**capacity への加算値**（`absorbed..4`）を `constrain_constant(cell, 0)` で
zero に拘束する。

- capacity **state**（`prev[3]`）を zero にするのではない。加算値だけを 0 に
  する。これにより「capacity 状態を非ゼロに固定する」正当な用途を壊さず、
  任意の addend を選ぶ攻撃だけを防ぐ。
- block 0 の長さ IV（`[0, 0, 0, len << 64]`）は定数に束縛する。
- 2 block 目以降の `prev` は直前 permutation の最終 state セルに
  `constrain_equal` でコピーする。
- padding の未使用 rate lane も同じ zero 制約の対象である。

この制約がない場合、悪意ある prover は未使用 absorb lane に非ゼロ値を選び、
その値に合わせて state / `pow2` / `pow5` / 全 round / digest を再計算した
witness を作れる。`MockProver` の負例テストは、単に正規 prover helper が
入力を拒否するのではなく、**再計算済みの整合した witness でも制約が拒否
する**ことを確認する。

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

`cargo test --locked --lib poseidon2_halo2` の test 群（実装担当の報告。
本ドキュメント更新では再実行していない）。

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
- **P0 負例**: `every_unused_absorb_lane_is_constrained_to_zero` が全 block の
  未使用 rate lane / capacity 加算値の zero 制約を確認する。
  `malicious_digest_is_not_accepted_as_the_correct_function` は未使用 lane を
  非ゼロにした後、state / `pow2` / `pow5` / 全 round / digest を再計算した
  整合的な malicious witness を `MockProver` が拒否することを確認する。
  `inter_block_prev_copy_cannot_be_altered` と
  `length_iv_cannot_be_altered` が `prev` コピーと長さ IV の束縛を確認する。
- **Chip**: `chip_hash_can_publish_only_the_digest`、
  `chip_can_be_reused_in_one_region`、`chip_supports_chained_hashes`、
  `chip_supports_public_and_private_inputs`、
  `chip_digest_cannot_be_substituted`、
  `chip_permutation_matches_the_standalone_result`、
  `hash_without_witnesses_keygen_succeeds` が秘密入力・連鎖・複数 region・
  keygen を確認する。`synthesize` が `expect` ではなく
  `ok_or(Error::Synthesis)?` を返すことも確認対象である。

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

> 以下の実測値は **P0 制約修正前（V1 artifact）** の記録である。行数・列数・
> gate degree は同じだが、VK/PK は V2 で再生成されるため、鍵サイズや
> proof 長は再計測が必要である。数値を V2 の保証として引用しないこと。

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
- **Chip の公開範囲**: `Poseidon2Chip` は instance 列を触らない。秘密 preimage
  を扱う回路では、呼び出し側が公開すると決めたセル（例: digest）だけを
  `constrain_instance` する。host で計算した digest を無制約に渡さない。
- **未使用 lane の zero 制約**: 全 block の未使用 rate lane と capacity 加算
  値を 0 に拘束する。負例テストは再計算済みの malicious witness を拒否する。
  この修正で VK/PK が変わったため、Poseidon2 は V2 magic
  （`RCH2IPV2` / `RCH2IPP2`）を使う。旧 V1 Poseidon2 鍵は拒否される。
- **fixture RNG**: 例の固定 seed はテスト専用。本番の IPA blinding には
  OS CSPRNG を使う。
- **wasm**: native と `wasm32-wasip1` で keygen/prove/verify を V2 で実行済み
  （[`poseidon2-halo2-wasm.md`](poseidon2-halo2-wasm.md)）。browser Worker /
  ICP canister でのこの回路自体の prove は V2 では未実行。

## 9. 明示的な未達・ギャップ

- **Nim/C ABI の Poseidon2 Halo2 circuit id は登録済み**（2026-11 更新）。
  `rustcrypto_halo2_ipa_bn254_*` の `circuit_id = 2`
  （`HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1`）として、**3 入力固定**の
  `Poseidon2HashCircuit` を扱う。witness は 3 個の canonical BE `Fr`
  （96 バイト）、公開入力は 1 列 `[digest, input0, input1, input2]`、`k >= 7`。
  Nim 側は `Halo2IpaBn254CircuitPoseidon2Hash3V1` と
  `encodePoseidon2HashInstances` を提供する。**artifact は V2**
  （`RCH2IPV2` / `RCH2IPP2`）であり、旧 V1-magic の Poseidon2 VK/PK は受理
  しない。committed fixture
  `tests/fixtures/halo2_ipa_poseidon2_v1.hex` は V2 で再生成済みであり、
  旧 V1 は `halo2_ipa_poseidon2_legacy_v1.hex` として拒否テストに使う。
- **任意 arity `0..=12` も登録済み**。`HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE
  = 0x100` に対し `circuit_id = BASE + n`。witness は `32 * n` バイト
  （`n = 0` は 0 バイト、NULL ポインタ可）、公開入力は 1 列 `n + 1` 値
  `[digest, inputs...]`。最小 `k` は `2^k - 6 >= hash_circuit_rows(n)` を
  満たす最小値で、`n = 0..=3` は 7、`4..=9` は 8、`10..=12` は 9。Nim 側は
  `Halo2IpaBn254CircuitPoseidon2HashV1Base`、`preparePoseidon2Hash` /
  `provePoseidon2Hash`、`poseidon2HashCircuitId` / `poseidon2HashMinK` を
  提供する。こちらも V2 artifact であり、arity 12 fixture
  `tests/fixtures/halo2_ipa_poseidon2_arity12_v1.hex`
  （`circuit_id = 268`, `k = 9`）は V2 で再生成済みである。
- **`Poseidon2Chip` は実装済み（未監査）**: 秘密 preimage を既存セルから受け、
  copy constraint で sponge / permutation に接続する。Chip は instance 列を
  触らず、公開セルは呼び出し側が選ぶ。負例・連鎖・複数 region・keygen の
  Rust unit test は実装担当が報告。Nim/C ABI への Chip 直接公開は無い
  （Nim は単体 hash 回路のみ）。
- **外部回路の登録はコンパイル時 adapter として実装済み**:
  `halo2_ipa_registry.rs` の `ApprovedCircuit` / `CircuitProfile` と
  `halo2_ipa_export_circuit!` /
  `halo2_ipa_export_circuit_verifier!`。17 公開値の例は
  `examples/halo2-ipa-external-circuit/`。実行時 descriptor・任意コードの
  ロードは提供しない。wasm / browser / ICP での外部回路実行は未検証。
- **Poseidon1 の Halo2 custom gate は比較用に実装済み**
  （[`poseidon1-halo2-gate.md`](poseidon1-halo2-gate.md)）。同一 k=10・同一 IPA
  での rows/VK/PK/proof 比較は [`benchmarks-branch85.md`](benchmarks-branch85.md)
  に記録。width 4・3 入力固定の比較デモであり、C ABI/Nim には未登録。
- **wasm/ICP 実行（V2）**: Poseidon2 回路自体は V2 で native と
  `wasm32-wasip1` の prove/verify を実行済み
  （`ci/test_poseidon2_halo2_wasm.sh`）。browser Worker / ICP canister は
  旧 V1 時点の実績のみで、V2 の VK/PK では再実行が必要。任意 arity の
  canister 側 VK 登録・展開は未検証。
- 汎用回路記述子・Noir frontend・実行時の任意 Poseidon2 登録は未実装
  （登録はコンパイル時の型のみ）。
- Poseidon1 との制約数・WASM instructions/cycles の実測比較は別タスク
  （Halo2 rows/proof size の比較は実装済み）。
