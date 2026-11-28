# ICP canister: Halo2 IPA verify-only / Poseidon2 hash (branch 85)

生バイトの raw IC update エンドポイントとして、次の 2 つの canister を追加した。

| canister | crate | method | 役割 |
|---|---|---|---|
| Halo2 IPA/BN254 verifier | `examples/halo2-ipa-ic-verifier` | `canister_update verify` | ビルド時にピン留めした VK で v1 proof を検証 |
| Poseidon2/BN254 hash | `examples/poseidon2-ic-hash` | `canister_update hash` | 0..=12 個の `Fr` を Noir/Barretenberg sponge でハッシュ |

どちらも Candid ではなく、IC の raw update エンドポイント（`ic0.msg_arg_data_*` /
`msg_reply_*`）を使う。呼び出し側は生のバイト列を渡し、生のバイト列を受け取る。
任意の VK、witness、params、prover、RNG を公開するエンドポイントは無い。

---

## 1. Halo2 IPA verifier canister

### 1.1 リクエスト

```text
arg = v1 proof bytes || v1 instances bytes
```

- `v1 proof bytes` は `rustcrypto-ffi/src/halo2_ipa.rs` の
  `"RCH2IPF1" | proof_len u32 BE | transcript`。
- `v1 instances bytes` は
  `"RCH2IPI1" | column_count u32 BE | column_count * (value_count u32 BE | values)`。
  cubic（id 1）は 1 列 1 値、Poseidon2 hash3（id 2）は 1 列 4 値。この
  canister が pin している VK は cubic（id 1）である。
- 分割位置は proof エンベロープの `proof_len` から決める。エンベロープ全体の
  長さが `5 MiB + 12 bytes` を超える場合は、バイト列をコピーする前に拒否する。
  `proof_len > 4 MiB`、`proof_len == 0`、`instances_len == 0`、暗号文の切り詰め・
  末尾余剰は `halo2_ipa.rs` 側でも拒否する。
- IC の ingress message 上限は 2 MiB なので、5 MiB の canister 側上限は通常の
  update call では到達しない。防御的多重化として残し、上限超過時は
  `msg_arg_data_copy` を呼ばずに `INVALID_LENGTH` (9) を返すことを
  `web/ic-branch85/ic-smoke.cjs` の mock `ic0` で検証している。

### 1.2 リプライ

```text
i32 status LE || u64 verifier instructions LE || u32 wasm memory pages LE   (16 bytes)
```

- `status == 0` のときだけ検証成功。それ以外は `status.rs` の負でないエラー
  コード（例: 8 = verification failed、9 = invalid length、20 = invalid field
  element、23 = invalid verifying key、25 = invalid circuit data）。
- `verifier instructions` は `ic0.performance_counter(0)` の検証呼び出し前後の
  差分。プロトコル手数料ではなく canister 内の実行命令数。
- `memory pages` は `core::arch::wasm32::memory_size(0)`（1 page = 64 KiB）。

### 1.3 VK のピン留め

`const APPROVED_VK: &[u8] = include_bytes!(env!("HALO2_IPA_APPROVED_VK"));`

ビルド時に `tests/fixtures/halo2_ipa_bn254_v1.hex` の `VK` を抽出したファイルを
環境変数で渡す。canister は **この VK 以外を受け取らない**。VK の差し替えは
コード変更・再ビルド・レビューを要求する。canister のレジストリ自体は
`circuit_id = 1`（`y = x^3 + x + 5`）と `circuit_id = 2`（3 入力 Poseidon2
hash）の両方をデコードできるが、pin した VK は id 1 のみである。

### 1.4 verify-only feature

`rustcrypto-ffi` に `halo2-ipa-verify-only` feature を追加した。この feature を
有効にすると `src/halo2_ipa.rs` から次がビルド対象外になる。

- prover 専用 import: `OsRng`、`RngCore`、`create_proof`、`keygen_pk`、
  `keygen_vk`、`Blake2bWrite`、`ProverIPA`、`TranscriptWriterBuffer`、
  `ProvingKey`
- prover / keygen 関数: `key_material`、`generate_key_material_v1`、
  `prove_with_rng_impl`、`prove_with_rng_v1`、`prepare_impl`、`prove_impl`、
  PK パーサと PK 検証
- C ABI シンボル: `rustcrypto_halo2_ipa_bn254_prepare`、
  `rustcrypto_halo2_ipa_bn254_prove`、`rustcrypto_halo2_ipa_bn254_pk_validate`

残るのは verify / validate と `CubicCircuitV1` の `Circuit` 実装
（`VerifyingKey::read` が必要とする）だけ。既定ビルドの挙動・シンボルは変えない。
`cargo test --locked --lib halo2_ipa` は既定 feature で従来どおり 11 件成功する。

`halo2-axiom` は未使用の `AccumulatorStrategy` 内で `rand_core::OsRng` を
参照するため、wasm32-unknown-unknown では `getrandom` の `custom` feature と
fail-closed なスタブ（`Error::UNSUPPORTED`）を登録している。検証経路は
`SingleStrategy` のみを使い、このスタブは呼ばれない。したがって最終 wasm の
import は `ic0` の 5 関数だけであり、`__wbindgen` / `getrandom` / Web Crypto の
import は無い。`__getrandom_custom` は export されるが、外部 import ではない。

### 1.5 IPA params cache feature（cold / warm）

`rustcrypto-ffi` の optional feature `halo2-ipa-params-cache` を追加した。
`halo2_ipa.rs` の `params_for(k)` が、無効時は `ParamsIPA::new(k)` を毎回
生成し、有効時は **thread-local の単一スロット** に `(k, ParamsIPA)` を保持
して同一 `k` の 2 回目以降を clone で再利用する。

- **cold call**: canister インスタンスで最初の検証。`hash_to_curve` による
  k=8 の 256 点生成と Lagrange 変換を含む。実測の budget 判定はこの値で行う。
- **warm call**: 同じ canister インスタンスでの 2 回目以降。params を clone
  するだけで再生成しない。
- キャッシュは **普通の heap メモリ** であり、canister の状態ではない。
  upgrade / reinstall で失われ、upgrade をまたいで共有されない。stable
  memory へ永続化する実装ではない。
- **trusted SRS のキャッシュではない**。`ParamsIPA` は `k` から決定的に
  導出される透明なパラメータであり、キャッシュしても信頼前提は変わらない。
- 単一スロットなので、異なる `k` を交互に検証すると毎回再生成になる
  （VK は k を 1 つに pin する運用を想定）。
- wasm import は引き続き `ic0` のみ。追加依存は無い。

---

## 2. Poseidon2 hash canister

### 2.1 リクエスト / リプライ

```text
arg   = count * 32 bytes（canonical BN254 Fr の 32-byte big-endian、count = 0..=12）
reply = i32 status LE || u64 instructions LE || u32 pages LE || digest (32 bytes)  (48 bytes)
```

- 空入力（0 個）は許可され、Noir/Barretenberg sponge の空入力規則に従う。
- `13 * 32 = 416` bytes を超える長さ、32 の倍数でない長さ、非 canonical な
  `Fr`（法以上）は割り当て前に拒否する。
- 既知値: `[1, 2, 3]` →
  `23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8`。
- RNG・ファイル・スレッド・時計を使用しない。`poseidon2.rs` は
  `status` / `aead_common` / `bn254` の 3 モジュールだけに依存し、Halo2 を
  リンクしない。

---

## 3. ビルドと実行

```bash
# 成果物ディレクトリを指定（省略時は mktemp）
bash ci/test_ic_branch85.sh /tmp/ic-branch85
```

スクリプトの処理:

1. `tests/fixtures/halo2_ipa_bn254_v1.hex` から `vk.bin` / `proof.bin` /
   `instances.bin` / `witness.bin` を抽出
   （`web/ic-branch85/extract-fixture.cjs`）。
2. `wasm32-unknown-unknown` release で両 canister をビルド。
   IPA は `--features halo2-ipa-verify-only,halo2-ipa-params-cache` と
   `HALO2_IPA_APPROVED_VK=<artifacts>/vk.bin` を指定。
3. PocketIC を起動し、2 canister を install して cycles を追加。
4. IPA `verify` に `proof || instances` を渡して status 0、命令数、ページ数を
   取得する。続けて同じ引数でもう一度呼び、cold / warm の命令数を記録する。
   proof 1 バイト改変・instance 1 バイト改変・不正エンベロープ・
   5 MiB 超（mock `ic0`）がすべて非 0 になることを確認。
5. Poseidon2 `hash` に `[1,2,3]` を渡して既知 digest と一致することを確認。
   長さ不正・非 canonical・13 個が非 0 になることを確認。
6. `ic-measurements.json` に cold/warm 命令数、ページ数、wasm サイズ、import、
   関数数、cycles を書き出す。

手動ビルド例:

```bash
cd /application
export CARGO_TARGET_DIR=/application/rustcrypto-ffi/target
HALO2_IPA_APPROVED_VK=/tmp/ic-branch85/vk.bin \
  cargo build --locked --release \
    --features halo2-ipa-verify-only,halo2-ipa-params-cache \
    --manifest-path examples/halo2-ipa-ic-verifier/Cargo.toml \
    --target wasm32-unknown-unknown
cargo build --locked --release \
  --manifest-path examples/poseidon2-ic-hash/Cargo.toml \
  --target wasm32-unknown-unknown
node web/ic-branch85/ic-smoke.cjs /tmp/ic-branch85 \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/halo2_ipa_ic_verifier.wasm" \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/poseidon2_ic_hash.wasm"
```

`@dfinity/pic` は `web/groth16-prover/node_modules` を `createRequire` で再利用する
（PocketIC server バイナリも同梱）。`web/ic-branch85` 側に `npm install` は不要。

---

## 4. 実測（ローカル PocketIC）

測定環境: Node `v24.22.1`、`@dfinity/pic` 0.25.0、`opt-level = 3`、fat LTO、
`codegen-units = 1`、`strip = "symbols"`。fixture は k=8、proof 1164 bytes、
instances 48 bytes。

| 項目 | Halo2 IPA verify (cold) | Halo2 IPA verify (warm) | Poseidon2 hash [1,2,3] |
|---|---:|---:|---:|
| status | 0 | 0 | 0 |
| `performance_counter` 差分 (instructions) | 18,226,479,635 | 568,422,557 | 866,665 |
| wasm memory | 53 pages / 3,473,408 bytes | 53 pages / 3,473,408 bytes | 18 pages / 1,179,648 bytes |
| PocketIC update cycles（参考） | 18,235,848,863 | — | 7,996,578 |
| wasm size | 2,809,674 bytes | 同左 | 149,430 bytes |
| wasm functions（import + defined） | 5 + 452 = 457 | 同左 | 5 + 73 = 78 |
| wasm imports | `ic0` 5 関数のみ | 同左 | `ic0` 5 関数のみ |

`cold` は canister インスタンスでの最初の検証、`warm` は同じインスタンスでの
2 回目である。`halo2-ipa-params-cache` により warm は params を再生成せず、
命令数が約 32 分の 1 になっている（18.2B → 0.57B）。`updateCyclesDebited` は
cold 呼び出しの値のみを示す。warm の cycles は個別には記録していない。

IPA の import は `msg_arg_data_size`、`msg_arg_data_copy`、
`performance_counter`、`msg_reply_data_append`、`msg_reply` のみ。
`__wbindgen`、`getrandom`、`crypto` などの import は無い。

### 解釈上の注意

- cold の IPA 命令数は **`ParamsIPA::new(k)` の決定的な生成（`hash_to_curve`
  による k=8 の 256 点生成と Lagrange 変換）が支配的**で、IPA 最終 MSM 自体は
  小さい。warm はその生成を thread-local キャッシュの clone で置き換える。
- warm の再利用は **canister インスタンス単位** であり、upgrade / reinstall で
  キャッシュは失われる。stable memory へ永続化するものではない。また単一
  スロットなので `k` が変わると cold に戻る。
- `updateCyclesDebited` は PocketIC の update call 全体の cycles で、ingress fee
  と実行 fee を含む。**mainnet の cycle quote でも、検証器単体の tariff でもない。**
- 命令数・cycles は PocketIC / IC のバージョン、ホスト、乱数（実行時）で多少
  変動する。拘束力のある値ではなく、再現可能な smoke の上限確認である。
  予算アサーションは cold call の instructions に対して行う。
- 予算アサーションは IPA が instructions < 30,000,000,000・memory < 512 MiB、
  Poseidon2 が instructions < 10,000,000・memory < 64 MiB。実測に対して現実的な
  上限だが、暗号学的な安全性の主張ではない。
- VK の SHA-256（fixture 抽出時）:
  `4b622f52e34feb5307d5156e7fe3d6be2b7cc8a14cb426548545b03ddadc8b5e`。
- この実行の wasm SHA-256（ツールチェーン・profile 依存）:
  IPA `b827a5f73e8be59fdf50f5bf82c4943f7c5a3174d8f5a5060fadfcff21c43270`、
  Poseidon2 `1df97972bb9e08457c0b1f9d4b2a0cf400d71bd6f236bd1360e5f61cadc0701a`。

---

## 5. 再現性

- fixture は `tests/fixtures/halo2_ipa_bn254_v1.hex` に固定。
- 両 example crate に `Cargo.lock` を commit し、`--locked` でビルドする。
- `halo2-axiom` は `rustcrypto-ffi/third_party/halo2-axiom-0.5.3` を
  `[patch.crates-io]` で参照（`multicore` 既定 off の vendored copy）。
- PocketIC server は `@dfinity/pic` 同梱のバイナリを使う。
- 実行ごとに `ic-measurements.json` を成果物ディレクトリへ出力する。

---

## 6. 明示的な未対応・ギャップ

- `dfx` による本番 canister のデプロイ手順・canister ID・controller 設定は
  未提供。PocketIC 上の install と update call のみを検証している。
- mainnet での cycles / instruction 実測は行っていない。本ドキュメントの数値は
  ローカル PocketIC のものであり、本番の cycle quote ではない。
- ブラウザから canister を呼ぶ UI は無い（`web/ic-branch85` は Node の
  smoke/measurement スクリプトのみ）。
- Candid インターフェース、認証、課金、ステート管理、upgrade hook は無い。
  本 canister は「検証結果を返すだけ」で状態を変更しない。
- **IPA params cache**: `halo2-ipa-params-cache` により同一 canister インスタンス
  内の warm call は params を再生成しない。ただし単一 thread-local スロットの
  heap キャッシュであり、upgrade / reinstall で失われ、stable memory や
  複数 `k` の永続キャッシュではない。cold call のコストは残る。
- mainnet での cycles / instruction 実測は行っていない。本ドキュメントの数値は
  ローカル PocketIC のものであり、本番の cycle quote ではない。mainnet の
  cycle 見積もりは引き続き未計測である。
- 本番資産用途の監査済み保証は範囲外。VK のピン留めと回路の承認は利用側の
  レビュー責務である。
