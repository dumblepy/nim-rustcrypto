# 外部 Halo2 IPA 回路 (ChainCircuit) — wasm / Browser Worker 実証

このドキュメントは、`rustcrypto-ffi` のソースを書き換えずにアプリ定義の
複合回路を登録し、`wasm32-unknown-unknown` と Browser Web Worker で
prepare / prove / verify する手順と実測結果をまとめる。対象は
`examples/halo2-ipa-external-circuit` の `ChainCircuit`（circuit id
`0x10001`、公開値 17 個）である。

- 未監査・非保証である。資産用途の安全性をこの文書だけで宣言しない。
- ICP canister 側の外部回路 verifier は **別タスク**であり、本ドキュメントの
  成果には含めない。
- 暗号処理は再実装していない。wasm adapter は
  `rustcrypto-ffi/src/halo2_ipa_registry.rs` の型付き API
  （`prepare::<C>` / `prove::<C>` / `verify::<C>`）を呼ぶだけである。

## 1. 外部登録の契約

外部 crate は回路型を **コンパイル時に** 登録する。実行時の回路 descriptor、
コードロード、未承認 VK の任意実行は存在しない。

`ApprovedCircuit` の実装が満たすべき条件:

- `Circuit<Fr, Params = ()>`、`Default`、`Clone`、`'static`。
- `type FloorPlanner = SimpleFloorPlanner`。
- `without_witnesses()` が全 witnessed instance と同じ layout
  （同じ advice セル・region・行・selector）を返す。
- layout は witness の値で行数・列数・selector を変えない。
- 行数は `2^k - 6` 以下。
- 公開すると約束した instance セルを `synthesize` 内の
  `layouter.constrain_instance(...)` で witness に束縛する。
- `from_witness(&[u8])` は `profile().witness_len` バイトだけを decode し、
  index 前に `RUSTCRYPTO_ERR_INVALID_LENGTH` /
  `RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT` を返す。

`CircuitProfile` が回路ごとに固定するもの:

- `circuit_id`（`>= 0x1_0000`。組み込み `1`, `2`, `0x100 + n` と衝突しない）、
  `circuit_version`
- witness 長、公開 instance 列ごとの値数
- `k` の範囲
- VK / PK / proof の上限

`ChainCircuit` の profile は次のとおり。

| 項目 | 値 |
|---|---|
| circuit id | `0x10001` |
| circuit version | `1` |
| witness | 16 個の `Fr`（512 bytes、`acc` 連鎖の秘密入力） |
| 公開 instance | 1 列 17 値 `[acc_1, .., acc_15, input_0, input_15]` |
| `k` | `6..=12`（fixture / browser は最小の `6`） |
| VK / PK / proof 上限 | 64 KiB / 8 MiB / 2 MiB |

`ChainCircuit` は `acc_i = acc_{i-1}^2 + input_i` を 16 step 連鎖し、
custom gate `q * (acc_prev^2 + input - acc)` で拘束する。さらに
`accumulator[0]` と `input[0]` を region 内の copy constraint
（`region.constrain_equal`）で結び、公開 instance の `input_0` が連鎖の
開始値 `acc_0` に一致することを強制する。この制約がないと、prover は
`input_0` を公開したまま `acc_0` を任意値から始められ、公開値が連鎖に
束縛されない。`LinearCircuit` も同じ copy constraint を持つ。公開値は
`chain_public_values()` が返す 17 値である。

### verify-only ビルド

外部 crate には `verify-only` feature がある。

```toml
verify-only = ["rustcrypto-ffi/halo2-ipa-verify-only"]
```

- 既定ビルド: `chain_adapter` / `linear_adapter` に
  prepare / prove / verify / validate を export する。
- `--features verify-only`: `halo2_ipa_export_circuit_verifier!` だけを使い、
  verify / VK validate / proof validate / instances validate のみを export
  する。`prepare` / `prove` は生成せず、`rustcrypto-ffi` 側も prover /
  keygen コードをリンクしない。

```bash
cargo check --manifest-path examples/halo2-ipa-external-circuit/Cargo.toml
cargo check --manifest-path examples/halo2-ipa-external-circuit/Cargo.toml \
  --features verify-only
```

`verify-only` の `staticlib` を `nm` で確認すると、`chain_adapter` /
`linear_adapter` / `linear_verifier` の `*_verify` / `*_vk_validate` /
`*_proof_validate` / `*_instances_validate` だけが定義され、
`*_prepare` / `*_prove` は存在しない。


## 2. pin 必須項目

prove / verify の前に、アプリケーションは次を固定し、artifact の差し替えを
検出する。

| 項目 | 取得元 | 用途 |
|---|---|---|
| `circuit_id` | `CircuitProfile::circuit_id` | V2 key envelope の id と一致を強制 |
| `circuit_version` | `CircuitProfile::circuit_version` | アプリ側の回路改訂 pin |
| schema | `witness_len` / `instance_column_lengths` | witness 長と公開値形状の一致 |
| `k` | profile の `min_k..=max_k` から 1 つ | params と VK の再生成条件 |
| VK digest | `vk_digest(vk)`（SHA-256） | 承認済み VK の pin |
| params digest | `params_digest(k)` | 透明 IPA params の pin |
| PK digest（任意） | `pk_digest(pk)` | prover 配布物の同一性確認 |

`k = 6` の `ChainCircuit` の fixture は次で固定されている。

```text
VK SHA-256  = d1d88261a86fa182c8e290a446d6ae6ac0e4f7923f9df6997aee33ef42f73e29
params SHA-256 (k=6) = dd135f0b6c67256601672862b88216ca00eda22708b82e1be851264824c73326
```

旧 VK（soundness 修正前）の digest は
`b2638b6e406a221e904223b400067b880a055995a937687eb6e601471d128d3c`
であり、`acc_0 = input_0` 制約の追加により VK が変わった。旧 fixture /
旧 VK を新しい回路の artifact として受理しないよう、アプリ側の pin を
更新する必要がある。

VK digest を固定しない場合、攻撃者が別回路の VK を渡す可能性がある。
`verify::<C>` は VK の構造・`circuit_id`・`k` を検査するが、その VK が
アプリケーションの意図する回路かまでは保証しない。

## 3. fixture

生成器: `examples/halo2-ipa-external-circuit/examples/generate_fixture.rs`

```bash
cargo run --release --example generate_fixture \
  --manifest-path examples/halo2-ipa-external-circuit/Cargo.toml
```

既定の出力は `tests/fixtures/halo2_ipa_external_chain_v1.hex`、既定の
`k` は profile 最小値 `6`。引数で `[output.hex] [k]` を上書きできる。
private input は `1..=16`、witness はその canonical 32-byte BE `Fr` 列、
instance は `chain_public_values()` の 17 値である。

fixture の形式（1 行 1 項目、hex）:

```text
VK=<V2 VK envelope>
PK=<V2 PK envelope>
PROOF=<V1 proof envelope>
INSTANCES=<V1 instances envelope>
WITNESS=<16 * 32 bytes>
```

生成時は公開 API の `prepare` → `prove_with_rng`（固定テスト seed
`[0x87; 32]`）→ `verify` を通し、検証に成功したものだけを書き出す。固定
seed は fixture / test 専用であり、production では OS / browser CSPRNG を
使う。vendored `halo2-axiom` は vanishing argument の一部を内部で
`rand::thread_rng()` からサンプルするため、`VK` / `PK` / `INSTANCES` /
`WITNESS` は再現するが `PROOF` のバイト列は再実行で一致しない。

native の回帰テスト:

```bash
cargo test --manifest-path examples/halo2-ipa-external-circuit/Cargo.toml
```

## 4. wasm adapter

crate: `examples/halo2-ipa-external-circuit-wasm`（`cdylib`）

`halo2-ipa-external-circuit` を path 依存し、registry の型付き API を
そのまま呼ぶ。回路・鍵・proof の実装は持たない。

公開する wasm-bindgen 関数:

| 関数 | 内容 |
|---|---|
| `abi_version()` | adapter ABI（`1`） |
| `circuit_id()` | `0x10001` |
| `circuit_version()` | `1` |
| `instance_values()` | `17` |
| `instance_columns()` | `1` |
| `witness_values()` / `witness_bytes()` | `16` / `512` |
| `min_k()` / `max_k()` | `6` / `12` |
| `max_proof_len()` | 上限値 |
| `prepare(k)` | `prepare::<ChainCircuit>` → `vk_len u32 BE \| vk \| pk` |
| `prove(pk, witness, instances)` | `prove::<ChainCircuit>`。witness `Vec` は `Zeroizing` で消去 |
| `verify(vk, proof, instances)` | `verify::<ChainCircuit>`。成功 `true`、暗号検証失敗 `false`、malformed / 別回路 / 別鍵は `Err` |
| `vk_sha256(vk)` | VK pin 用 SHA-256 |

`prepare` の framing は既存 browser adapter と同じ
`vk_len u32 BE | vk | pk`。`prove` は browser の `OsRng`（`getrandom` の
`js` feature）を使う。`wasm32-unknown-unknown` は threads / atomics を
必要としない。`panic = "abort"` だが、registry は length・canonical Fr・
trailing bytes・circuit id を index 前に検査するため、malformed 入力は
trap ではなく status error を返す（後述の負例で確認）。

ビルド:

```bash
cargo build --release \
  --manifest-path examples/halo2-ipa-external-circuit-wasm/Cargo.toml \
  --target wasm32-unknown-unknown

wasm-bindgen \
  target/wasm32-unknown-unknown/release/halo2_ipa_external_circuit_wasm.wasm \
  --target web \
  --out-dir web/halo2-ipa-external-circuit/pkg \
  --out-name halo2_ipa_external_circuit_wasm
```

`CARGO_TARGET_DIR` を変えた場合は wasm のパスもその下になる。

## 5. Browser Worker smoke

実装: `web/halo2-ipa-external-circuit/{index.html,page.mjs,worker.mjs,smoke.mjs}`

- plain HTTP origin。COOP / COEP を付けず、`crossOriginIsolated === false`、
  `SharedArrayBuffer` なしで動く。
- Worker が wasm を所有し、`prepare` と `prove` を実行する。main thread が
  `verify` する。
- 17 個の公開値を JS で `chain_public_values` と同一に計算して instance を
  構築する。
- 負例: 誤った公開値、改ざん proof、circuit id を `0x10002` に付け替えた VK、
  破損 VK。すべて拒否される。
- Node は独立した wasm instance で worker の proof と committed fixture の
  両方を再検証する。worker の VK が fixture の VK と一致することも確認する。
- malformed 入力（短い / trailing / 非 canonical な witness・instances、
  切り詰めた VK）が `RuntimeError: unreachable` にならず、adapter の
  status error になることを確認する。

実行:

```bash
ZKP_RUST_WASM_TARGETS_INSTALLED=1 \
  bash ci/test_halo2_ipa_external_wasm.sh /tmp/opencode/halo2-external-wasm
```

前提: `wasm-bindgen` CLI `0.2.129`、`web/groth16-prover/node_modules` の
Playwright と Chromium。スクリプトは wasm adapter をビルドし、
`wasm-bindgen --target web` を実行してから smoke を走らせる。build 成功だけ
では pass にしない。

### 実測結果（2026-11、1 環境の参考値）

`ci/test_halo2_ipa_external_wasm.sh` が exit 0 で完了したときの値。

| 項目 | 値 |
|---|---|
| circuit id / version | `65537` (`0x10001`) / `1` |
| `k` | `6` |
| 公開値 | 17（1 列、instance blob 560 bytes） |
| witness | 16 値（512 bytes） |
| VK / PK | 158 bytes / 22,746 bytes |
| proof | 1,452 bytes |
| `prepare`（Worker） | 約 0.60 s |
| `prove`（Worker） | 約 1.11 s |
| `verify`（main thread） | 約 0.51 s |
| Node 再検証（worker proof） | 約 0.45 s |
| Node 再検証（fixture） | 約 0.44 s |
| wasm（wasm-bindgen 後） | 9,908,579 bytes |
| Chromium | 158.0.8127.18（headless） |
| Node | v24.22.1 |
| `crossOriginIsolated` | `false` |
| `SharedArrayBuffer` | 利用不可 |
| witness zeroize | 確認済み |

数値はマシン・Chromium バージョン・`k` に依存する。性能保証ではない。

## 6. 負例

native（`cargo test`、12 passed）:

- 17 公開値の prepare / prove / verify roundtrip
- 正直 witness が `ChainCircuit` / `LinearCircuit` の制約を満たすこと
- **旧 malicious witness の拒否**: 公開 `input_0 = 1` に対して
  `acc_0 = 7` から連鎖を計算し、`acc_1..acc_15` をその連鎖に合わせて公開
  しても、`acc_0 = input_0` の copy constraint で MockProver が拒否する
  （両回路）
- 公開 `input_0` だけを変更した instance の拒否（両回路）
- 誤った expected public instances
- 改ざん proof、V1 magic への付け替え
- 誤った circuit id、別回路（`LinearCircuit`）の VK / proof
- 非 canonical witness / instance、trailing byte、過大長、値数・列数違い
- VK digest pin の再現性
- verifier-only adapter の受理・別回路 proof の拒否
- `k` 下限未満、NULL pointer、切り詰め / trailing key

browser / Node（smoke）:

- 誤った公開値 → `ok = false`
- 改ざん proof → 拒否
- circuit id `0x10002` への付け替え VK → 拒否
- 破損 VK → 拒否
- 短い / trailing / 非 canonical witness
- 短い / trailing / 非 canonical instances
- 切り詰めた VK
- 上記 malformed 入力で trap しないこと

## 7. 残課題

- **ICP canister の外部回路 verifier は別タスク**。本ドキュメントでは
  wasm / Browser Worker までしか実証しておらず、ICP / PocketIC 実行は
  未実施である。
- 外部回路の Nim 静的リンクと C ABI consumer の実運用配布物は未整備。
- 同一 artifact / proof の ICP との相互運用、release 配布物の sha 固定、
  codec fuzz / DoS 試験、独立レビューは未完了。
- fixture の `PROOF` は vendored `halo2-axiom` 内部の `thread_rng` により
  バイト再現しない。`VK` / `PK` / `INSTANCES` / `WITNESS` は再現する。
- `ChainCircuit` は API と wasm 経路のデモであり、資産固有ロジックや
  セキュリティ保証を含まない。未監査である。
