# Branch 85 ベンチマーク: Poseidon1 vs Poseidon2 と汎用 Halo2 IPA

このドキュメントは、ブランチ 85 で追加した Poseidon2/BN254 と Halo2 IPA
について、**native release** で実測した結果と再現手順をまとめる。WASM の
命令数・cycle はここでは測っていない。ICP の canister instructions / memory /
cycle は [`ic-branch85.md`](ic-branch85.md) に、ブラウザ Worker の証明時間は
[`halo2-ipa.md`](halo2-ipa.md) に記録している。

対象実装:

- Poseidon2: `rustcrypto-ffi/src/poseidon2.rs` / `poseidon2_gadget.rs`
- Halo2 IPA: `rustcrypto-ffi/src/halo2_ipa.rs`（本ベンチは C ABI を使わず
  `halo2-axiom` を直接利用）
- ベンチ本体:
  - `rustcrypto-ffi/examples/poseidon_bench.rs`
  - `rustcrypto-ffi/examples/halo2_ipa_bench.rs`
- 実行スクリプト: `ci/benchmarks_branch85.sh`

## 1. 実行方法

```bash
# R1CS 形状 + native ハッシュ
cd /application/rustcrypto-ffi
cargo run --locked --release --example poseidon_bench

# 汎用 Halo2 IPA（既定で k=11/steps=1024 と k=15/steps=20000 の 2 サイズ）
cargo run --locked --release --example halo2_ipa_bench

# 任意サイズを 1 つだけ
cargo run --locked --release --example halo2_ipa_bench -- --steps 4096 --k 13

# 環境情報・JSON・wall time・peak RSS をまとめて取得
cd /application
bash ci/benchmarks_branch85.sh /tmp/bench-branch85
```

両 example は **JSON を stdout、人間向け表を stderr** に出す。スクリプトは
stdout を `poseidon-bench.json` / `ipa-bench.json` に保存し、`environment.txt`
と `rss.txt` も同じディレクトリに書く。

`rustfmt` 確認:

```bash
cd /application
rustfmt --edition 2024 --check \
  rustcrypto-ffi/examples/poseidon_bench.rs \
  rustcrypto-ffi/examples/halo2_ipa_bench.rs
```

## 2. 計測環境

`/tmp/bench-branch85/environment.txt` より:

| 項目 | 値 |
|---|---|
| rustc | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| cargo | `cargo 1.99.1 (5f94df478 2026-08-27)` |
| OS | Ubuntu 24.04 系コンテナ（`uname -a`: Linux 7.0.0-42-generic x86_64） |
| CPU 数 | 8 |
| ビルド | `--locked --release` |

Poseidon2 のプロファイル（example と JSON に固定値として出力）:

| 項目 | 値 |
|---|---|
| 体 | BN254 `Fr` |
| 状態幅 `t` | 4 |
| rate / capacity | 3 / 1 |
| S-box | `x^5` |
| full rounds `RF` | 8 |
| partial rounds `RP` | 56 |
| sponge | Noir / Barretenberg 互換（長さ IV、rate=3、末尾規則を含む） |

> 数値は 1 回の実行結果である。native 時間は同一マシン内でも数割変動する。
> 絶対値よりも同一実行内の相対比較として読むこと。

## 3. Poseidon1 vs Poseidon2（R1CS と native ハッシュ）

### 3.1 方法

R1CS は `ark-relations` 0.5.1 の `ConstraintSystem::new_ref()` で構築した。
入力は全 arity で

```rust
FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u64)))
```

とし、Poseidon1 は `rust_crypto_ffi::groth16_prover::poseidon_gadget`、
Poseidon2 は `rust_crypto_ffi::poseidon2_gadget::hash` を使った。行列統計は
既定の `SynthesisMode::Prove { construct_matrices: true }` のまま
`cs.finalize()` → `cs.to_matrices()` で取得し、`cs.is_satisfied()` が `true`
であることも確認している。

- arity 0 は Poseidon2 のみ対応（Poseidon1 は「unsupported」）。
- arity 2 を Merkle node 相当として `use: "merkle_node"` と記録。
- **出力を公開入力に束縛していない**（ハッシュ回路そのものの形状を見るため）。
  したがって `instance_variables = 1` は R1CS の定数 `1` ワイヤのみである。

native 時間:

- Poseidon1: `light_poseidon::Poseidon::<Fr>::new_circom(n)` +
  `PoseidonHasher::hash`。
- Poseidon2: `rustcrypto_poseidon2_bn254_hash` C ABI。入力 32-byte
  big-endian 列はループ外で 1 回だけ作り、**C ABI の marshal を含む**時間を
  測っている。
- warmup は `max(16, iterations/20)`。本計測は arity 0–3 が 2000 回、
  arity 8–9 が 500 回。

### 3.2 実測結果（`/tmp/bench-branch85/poseidon-bench.json`）

| hash | arity | constraints | witness vars | instance vars | A nnz | B nnz | C nnz | total nnz | ns/op |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Poseidon1 | 0 | — | — | — | — | — | — | — | — |
| Poseidon2 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 21,914.5 |
| Poseidon1 | 1 | 341 | 342 | 1 | 780 | 483 | 213 | 1,476 | 20,801.1 |
| Poseidon2 | 1 | 264 | 265 | 1 | 2,368 | 4,472 | 264 | 7,104 | 21,754.8 |
| Poseidon1 | 2 | 435 | 437 | 1 | 1,271 | 595 | 240 | 2,106 | 38,621.1 |
| Poseidon2 | 2 | 264 | 266 | 1 | 2,372 | 4,480 | 264 | 7,116 | 18,106.3 |
| Poseidon1 | 3 | 517 | 520 | 1 | 1,852 | 691 | 261 | 2,804 | 49,911.3 |
| Poseidon2 | 3 | 264 | 267 | 1 | 2,376 | 4,488 | 264 | 7,128 | 17,921.6 |
| Poseidon1 | 8 | 1,041 | 1,049 | 1 | 7,493 | 1,309 | 402 | 9,204 | 225,333.8 |
| Poseidon2 | 8 | 792 | 800 | 1 | 7,156 | 13,520 | 792 | 21,468 | 60,162.4 |
| Poseidon1 | 9 | 1,097 | 1,106 | 1 | 8,636 | 1,375 | 417 | 10,428 | 276,226.1 |
| Poseidon2 | 9 | 792 | 801 | 1 | 7,160 | 13,528 | 792 | 21,480 | 60,310.5 |

`constraints` / `witness vars` / `instance vars` / `A,B,C nnz` は
`ark_relations::r1cs::ConstraintMatrices` の値。`total nnz = A + B + C`。
arity 0 の Poseidon2 は状態がすべて定数になるため制約 0（異常ではない）。

### 3.3 解釈

- 制約数は Poseidon2 が少ない。arity 2 で 264 vs 435（約 39% 減）、
  arity 8/9 で 792 vs 1,041/1,097（約 24–28% 減）。
- 一方、行列の非ゼロ係数（total nnz）は Poseidon2 が多い。arity 2 で
  7,116 vs 2,106（約 3.4 倍）、arity 8 で 21,468 vs 9,204（約 2.3 倍）。
  外部線形層が密で、R1CS では「制約行は減るが 1 行あたりの係数が増える」
  トレードオフになる。
- native ハッシュは今回の環境では Poseidon2 が速い（arity 2 で約 0.47 倍、
  arity 8/9 で約 0.22–0.27 倍の時間）。ただし Poseidon2 の値は C ABI 呼び出しを
  含み、単一実行のノイズも大きい。Poseidon1 の `hash` は入力 `Vec` を
  再利用する呼び出し形である。
- **Groth16/R1CS には Halo2 の row / k / padding が存在しない**。そのため
  JSON では `padding: null` とし、「R1CS/Groth16 では Halo2 形式の padded
  row domain を持たない」と明記している。Poseidon1 の Halo2 custom gate は
  本ブランチ未実装なので、Halo2 行数や proof size の比較はできない。

## 4. 汎用 Halo2 IPA 形状ベンチマーク

### 4.1 方法

`halo2-axiom` 0.5.3 を直接使い、C ABI / circuit registry を経由せずに
prove/verify する。回路は合成（synthetic）で、`steps` で行数を制御する:

```text
advice[0]   = first
advice[r+1] = advice[r] * advice[r] + 1     (r = 0 .. steps-1)
```

- advice 1 列、instance 1 列、selector 1 個。
- ゲートは `enabled * (cur^2 + 1 - next)`。
- 先頭と末尾の advice セルを `layouter.constrain_instance` で instance 行
  0/1 に束縛する（公開入力 2 個）。
- `ParamsIPA::<G1Affine>::new(k)`、`keygen_vk`、`keygen_pk`、`create_proof`
  （`StdRng::from_seed([0x85; 32])`）、`verify_proof`（`SingleStrategy`）を
  使用。`AccumulatorStrategy` は `OsRng` を呼ぶため使っていない。
- `MockProver` で制約充足と行数上限を確認したうえで、実際の keygen/prove/
  verify 時間を測る。
- `k` は既定で `steps=1024 → k=11`、`steps=20000 → k=15`。blinding 行を
  考慮した usable rows は `n - (blinding_factors + 1)`。

`vk_bytes` / `pk_bytes` は `SerdeFormat::Processed` のシリアライズ長、
`proof_bytes` は IPA transcript の raw bytes（v1 C ABI envelope ではない）。

### 4.2 実測結果（`/tmp/bench-branch85/ipa-bench.json`）

| steps | k | n | blinding | usable rows | advice rows | gate rows | constraints | MockProver |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1,024 | 11 | 2,048 | 5 | 2,042 | 1,025 | 1,024 | 1,024 | OK |
| 20,000 | 15 | 32,768 | 5 | 32,762 | 20,001 | 20,000 | 20,000 | OK |

| steps | k | vk bytes | pk bytes | proof bytes | params ms | keygen ms | prove ms | verify ms | verified | wrong instance rejected |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 1,024 | 11 | 106 | 589,982 | 1,504 | 1,196.9 | 69.2 | 457.8 | 29.5 | true | true |
| 20,000 | 15 | 106 | 9,437,342 | 1,760 | 16,283.6 | 326.0 | 3,124.7 | 104.8 | true | true |

wall time / peak RSS（`rss.txt`）:

| ベンチ | wall time | peak RSS |
|---|---:|---:|
| poseidon-bench | 0.932 s | 11,356 KiB |
| ipa-bench（2 サイズ合計） | 21.847 s | 82,644 KiB |

> このコンテナには GNU `/usr/bin/time` が無いため、スクリプトは
> `/proc/<pid>/status` の `VmHWM` を**外側から**サンプリングした。
> `/usr/bin/time -v` がある環境ではスクリプトがそちらを優先し、`rss.txt` の
> `rss_source` に取得元を明記する。RSS はベンチプロセス自身には測らせていない。

### 4.3 解釈

- `ParamsIPA::new(k)` が k=15 で約 16 秒かかり、この形状では支配的。
  params は k から決定的に再生成でき、wire format には含めない設計だが、
  検証側でも k に応じた再生成コストがかかる。
- keygen は k=11 で約 69 ms、k=15 で約 326 ms。prove は約 0.46 s /
  3.12 s、verify は約 30 ms / 105 ms。20k 行でも prove は数秒台で完了した。
- proof は 1.5–1.8 KB、VK は 106 B、PK は 0.59 MB / 9.44 MB。PK は k に
  対して大きく、保存・配布コストは別途評価が必要。
- `wrong_instance_rejected = true` を確認済み。誤った公開入力では検証が
  失敗する。

## 5. 明示的な限界

1. **Halo2 IPA の回路はアプリケーション等価ではない。** `ChainCircuit` は
   `next = cur^2 + 1` を繰り返すだけの形状ベンチであり、Merkle path、
   128-bit range proof、shielded note、資産回路などではない。行数・k・
   prove/verify コストの目安を与えるが、実アプリの制約数や proof size を
   代表しない。
2. **Poseidon1 の Halo2 custom gate は未実装。** 本ブランチには Poseidon1 の
   Halo2 gate が無いため、Halo2 の rows/k/lookup、Halo2 proof size、
   Poseidon1 vs Poseidon2 の Halo2 証明コストを比較できない。R1CS の
   制約数・nnz と native ハッシュ時間のみ比較している。
3. **Poseidon1 vs Poseidon2 の proof size 比較は apples-to-apples ではない。**
   Poseidon2 側の Halo2 gate は `docs/poseidon2-halo2-gate.md` に実装済みだが、
   同一回路・同一 PCS で Poseidon1 と比較するには Poseidon1 の Halo2 gate が
   必要であり、本ドキュメントの範囲外。
4. **WASM instructions / cycles は本ベンチでは未計測。** ここに載せたのは
   native release の時間と RSS のみ。WASM の実行時間・cycle・ICP
   instructions は [`ic-branch85.md`](ic-branch85.md) と
   [`halo2-ipa.md`](halo2-ipa.md) に別途記録している（推測値は載せない）。
5. **R1CS に Halo2 の row/padding は無い。** `constraints` は R1CS の
   制約数、`witness_variables` は witness 数であり、Halo2 の `k` や
   padded rows ではない。JSON では該当フィールドを `null` としている。
6. **Poseidon2 の native 時間は C ABI を含む。** 入力バイト列の生成は
   ループ外だが、`extern "C"` 呼び出しと出力書き込みを含む。Poseidon1 は
   Rust API 直呼びである。
7. **単一環境・単一実行の値である。** CPU、rustc、halo2-axiom のビルド、
   同時実行プロセスの影響を受ける。再現時は同じコマンドと同じ
   `--locked` を使い、絶対値は環境ごとに取り直すこと。

## 6. 関連する WASM / ICP 実測

本ドキュメントの native ベンチとは別に、以下を実行済みである。

| 項目 | 結果 | 参照 |
|---|---|---|
| Browser Web Worker prove（k=8、cubic v1） | prepare 約 1.9–4.1 s、prove 約 2.6–4.9 s、verify 約 1.6–2.2 s、wasm 3,697,155 B、`crossOriginIsolated=false` | `docs/halo2-ipa.md` |
| ICP Poseidon2 hash `[1,2,3]` | status 0、866,665 instructions、18 pages（1,179,648 B） | `docs/ic-branch85.md` |
| ICP Halo2 IPA verify（k=8、cubic v1） | status 0、18,226,458,332 instructions、53 pages（3,473,408 B）。params 再生成が支配的 | `docs/ic-branch85.md` |

ICP の値はローカル PocketIC の update call であり、mainnet の cycle quote
ではない。wasm32-wasip1 / wasm32-unknown-unknown の KAT・fixture smoke は
`ci/test_poseidon2_wasm.sh` と `ci/test_halo2_ipa_wasm.sh` で実行している。
8. **proof bytes は再現しない可能性がある。** この vendored
   `halo2-axiom` fork は vanishing argument の乱数多項式を内部で
   `thread_rng` から取るため、同一 seed でも proof のバイト列は一致しない
   ことがある（検証結果には影響しない）。
9. **VK/PK の信頼は呼び出し側の責務。** 本ベンチは鍵の pinning や
   circuit digest の承認を行わない。実運用では承認済み VK をハッシュ等で
   pin する必要がある（`docs/halo2-ipa.md` 参照）。

## 6. 成果物

`bash ci/benchmarks_branch85.sh /tmp/bench-branch85` が生成するもの:

- `environment.txt`: rustc/cargo/uname/nproc など
- `poseidon-bench.json`: Poseidon1/2 の R1CS 形状と native ns/op
- `ipa-bench.json`: Halo2 IPA の k/steps/rows/サイズ/時間/検証結果
- `rss.txt`: wall time と peak RSS（取得元付き）

JSON の主なフィールド:

- Poseidon: `results[].{hash,arity,use,supported,constraints,
  witness_variables,instance_variables,a_nnz,b_nnz,c_nnz,total_nnz,
  native_iterations,native_ns_per_op,padding,padding_note}`
- IPA: `results[].{steps,k,n,blinding_factors,usable_rows,gate_rows,
  advice_rows,constraints,rows_used_fraction,mock_prover_verified,
  vk_bytes,pk_bytes,proof_bytes,params_ms,keygen_ms,prove_ms,verify_ms,
  verified,wrong_instance_rejected}`
