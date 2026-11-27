# Halo2 IPA transparent proof (BN254 / IPA-BGH19 / Blake2b)

Module: `rustcrypto/algorithm/halo2_ipa` (marker type `Halo2IpaBn254`)
Rust core: `rustcrypto-ffi/src/halo2_ipa.rs`

> **固定プロファイル（v1）。** Halo2 は単一の証明形式ではない。本モジュールは
> 以下のプロファイルだけを受け付ける。KZG/SHPLONK プロファイル（`halo2`）、
> Zcash `halo2_proofs` の Pasta/IPA、Poseidon transcript、EVM/Keccak transcript、
> gnark PLONK は異なる形式であり拒否する。

## プロファイル（v1）

| 項目 | 値 |
|---|---|
| 実装 | `halo2-axiom` 0.5.3（vendored。KZG プロファイルと同じコピー） |
| 曲線 / 体 | BN254、`G1Affine`、スカラー体 `Fr` |
| 多項式コミットメント | IPA（`ParamsIPA`, `IPACommitmentScheme`） |
| マルチオープン | BGH19（`ProverIPA` / `VerifierIPA`） |
| Fiat-Shamir | halo2 `Blake2bRead` / `Blake2bWrite` |
| プロトコル符号化 | 本モジュール独自のバイナリ列（bincode 不使用） |
| トラステッドセットアップ | **不要**（transparent） |

### トラステッドセットアップなし

`ParamsIPA::new(k)` が `hash_to_curve("Halo2-Parameters")` により生成元集合を
決定的に導出する。SRS セレモニーも、呼び出し側が用意する生成元も存在しない。
パラメータは `k` から再生成できるため、**v1 の wire format には含めない**。

検証時は VK ヘッダの `k` から `ParamsIPA::new(k)` を再生成する。生成には
乱数・ファイル・時計・ネットワークを使わない。

## 回路レジストリと VK ピン留め

`VerifyingKey::read` / `ProvingKey::read` は具体的な `Circuit` 型を要求するため、
本モジュールは `u32` の **承認済み回路レジストリ** を持つ。実装済みは次の 1 件のみ。

| `circuit_id` | 定数 | 回路 |
|---:|---|---|
| 1 | `HALO2_IPA_BN254_CIRCUIT_CUBIC_V1` | advice 1 列・instance 1 列・selector 1 個。ゲート `x^3 + x + 5 - y == 0`。witness `x`、公開入力 `y`（1 列 1 値） |

- 回路の追加は **Rust ソース変更 + レビュー** を必須とする。入力バイト列から
  任意の回路コードをロードすることはない。
- 本モジュールが行うのは構造検証と証明検証だけである。**どの VK を信頼するか
  （回路・バージョンへのピン留め）はアプリケーションの責任**。VK のハッシュを
  固定するなどを推奨する。
- `circuit_id` が未知の場合は `INVALID_CIRCUIT_DATA`（`prepare` では
  `INVALID_PARAMETER`）を返す。

## API

### C ABI

```c
int rustcrypto_halo2_ipa_bn254_prepare(
    uint32_t circuit_id, uint32_t k,
    uint8_t *vk_out, size_t vk_cap, size_t *vk_len,
    uint8_t *pk_out, size_t pk_cap, size_t *pk_len);

int rustcrypto_halo2_ipa_bn254_prove(
    const uint8_t *pk_ptr, size_t pk_len,
    const uint8_t *witness_ptr, size_t witness_len,
    const uint8_t *instances_ptr, size_t instances_len,
    uint8_t *proof_out, size_t proof_cap, size_t *proof_len);

int rustcrypto_halo2_ipa_bn254_verify(
    const uint8_t *vk_ptr, size_t vk_len,
    const uint8_t *proof_ptr, size_t proof_len,
    const uint8_t *instances_ptr, size_t instances_len);

int rustcrypto_halo2_ipa_bn254_vk_validate(const uint8_t *vk, size_t len);
int rustcrypto_halo2_ipa_bn254_pk_validate(const uint8_t *pk, size_t len);
int rustcrypto_halo2_ipa_bn254_proof_validate(const uint8_t *proof, size_t len);
int rustcrypto_halo2_ipa_bn254_instances_validate(const uint8_t *instances, size_t len);
```

- `prepare`: `k` と `circuit_id` を検証し、決定的に params を導出して VK/PK を
  keygen し、v1 形式で書き出す。乱数は使わない。
- `prove`: PK をレジストリ回路でパースし、witness（32 バイト canonical BE `Fr`）
  と公開入力（1 列 1 値）を読み、`y == x^3 + x + 5` を検査してから OS CSPRNG
  （`rand_core::OsRng`）で証明する。公開入力と witness が食い違う場合は証明を
  生成せずエラーを返す。
- `verify`: VK をレジストリ回路でパースし、`k` から params を再生成し、公開
  入力を検査し、proof transcript を **末尾バイトまで消費** したことを確認して
  `SingleStrategy`（乱数を要求しない単一証明検証）で判定する。
- `*_validate`: 安価な構造検証。VK/PK はレジストリ回路によるデコードまで行う。
  proof は v1 エンベロープ（magic・長さ・末尾バイト）を、instances は全要素の
  canonical `Fr` まで検査する。

### Nim の想定 API（type-first）

```nim
import rustcrypto/algorithm/halo2_ipa

let (vk, pk) = Halo2IpaBn254.prepare(Halo2IpaBn254CircuitCubicV1, 8)
let instances = Halo2IpaBn254.encodePublicInstances([y])  # y = x^3 + x + 5
let proof = Halo2IpaBn254.prove(pk, witnessBytes, instances)

if Halo2IpaBn254.verify(vk, proof, instances):
  echo "valid for this profile and key"
```

`prepare` は `(verifyingKey, provingKey)`、`prove` は `seq[byte]`、
`verify` は `bool` を返す想定。`validateVerifyingKey` /
`validateProvingKey` / `validateProof` / `validatePublicInstances` も同様に
`bool` を返す。Nim ラッパー本体は本 Rust コアの変更対象外である。

### エラーステータス

`RUSTCRYPTO_OK = 0` 以外はすべてエラー。主に使う値:

| 名前 | 値 | 意味 |
|---|---:|---|
| `RUSTCRYPTO_ERR_NULL_OUTPUT` | 1 | 出力ポインタ（または長さポインタ）が NULL |
| `RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT` | 2 | 出力バッファ不足（`*out_len` に必要サイズを設定） |
| `RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA` | 3 | 長さ > 0 なのにポインタが NULL |
| `RUSTCRYPTO_ERR_VERIFICATION_FAILED` | 8 | 構造は正しいが証明が不正 |
| `RUSTCRYPTO_ERR_INVALID_LENGTH` | 9 | 長さ不正・magic 不一致・末尾バイト |
| `RUSTCRYPTO_ERR_INVALID_PARAMETER` | 15 | 不正な `k` / `circuit_id`、witness と公開入力の不一致 |
| `RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT` | 20 | 非 canonical な `Fr` |
| `RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT` | 22 | proof の magic / 長さ / transcript 構造が不正 |
| `RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY` | 23 | VK の magic / 内部構造 / 内部 `k` が不正 |
| `RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT` | 24 | 列数・値数が回路と不一致 |
| `RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA` | 25 | PK または未知の `circuit_id` が不正 |
| `RUSTCRYPTO_ERR_PANIC` | -1 | `catch_unwind` が panic を捕捉（FFI 外へは出さない） |

## Wire format v1

すべて整数はビッグエンディアン。末尾の余分なバイトは拒否する。

### Verifying key

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCH2IPV1"` |
| 8 | 4 | `circuit_id`（現在は `1` のみ） |
| 12 | 4 | `k`（4..=16） |
| 16 | 4 | `vk_len`（1..=4 MiB） |
| 20 | `vk_len` | `halo2_axiom` の `SerdeFormat::Processed` による VK |

`vk_len` の範囲と実データ長が一致しない場合は `INVALID_LENGTH`。内部 VK の
version byte / `k` / selector フラグ / fixed commitment 数はデコード前に検査し、
ヘッダの `k` と内部 `k` が一致しなければ拒否する。

### Proving key

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCH2IPP1"` |
| 8 | 4 | `circuit_id` |
| 12 | 4 | `k` |
| 16 | 4 | `pk_len`（1..=64 MiB） |
| 20 | `pk_len` | `halo2_axiom` の `SerdeFormat::Processed` による PK |

PK は先頭に VK を含む。デコード前に内部の多項式長・ベクタ長を境界検査し、
悪意ある長さによる巨大アロケーションを防ぐ。PK 自体は信頼入力であり、
アプリケーションがピン留めする責任を持つ。

### Proof

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCH2IPF1"` |
| 8 | 4 | `proof_len`（1..=4 MiB） |
| 12 | `proof_len` | `Blake2bWrite` transcript の生バイト |

検証時は counting reader で読み、`proof_len` バイトを正確に消費したことを
要求する。余分なバイトは `INVALID_PROOF_FORMAT`。

### Public instances

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | magic `"RCH2IPI1"` |
| 8 | 4 | `column_count`（1..=8） |
| 12 | — | 各列: `value_count u32 BE` + `value_count * 32` バイトの `Fr` |

- 合計値数は 4096 以下。
- 各 `Fr` は BN254 `Fr` の **canonical ビッグエンディアン 32 バイト**。
  非 canonical（例: `0xff` × 32）は `INVALID_FIELD_ELEMENT`。
- 登録回路（cubic v1）は 1 列 1 値のみを受け付ける。それ以外は
  `INVALID_PUBLIC_INPUT_COUNT`。
- `column_count == 0` は拒否する。

### サイズ・`k` の上限

| 項目 | 上限 |
|---|---:|
| `k` | 4..=16 |
| VK ペイロード | 4 MiB |
| PK ペイロード | 64 MiB |
| proof transcript | 4 MiB |
| instance 列数 | 8 |
| instance 値数合計 | 4096 |

## Fixture とテスト

`rustcrypto-ffi/examples/halo2_ipa_fixture.rs` が k=8・`circuit_id=1`・
witness `x=3`（公開入力 `y=35`）の fixture を生成する。出力は
`tests/fixtures/halo2_ipa_bn254_v1.hex`（`VK=` / `PROOF=` / `INSTANCES=` /
`WITNESS=` 行）。

```text
cargo run --example halo2_ipa_fixture [output.hex]
```

- VK/PK は決定的に生成される。証明の blind には fixture 専用の固定 seed
  （`StdRng::from_seed([7u8; 32])`）を使う。ただし本リポジトリの vendored
  `halo2-axiom` は vanishing argument の乱数多項式を内部で
  `rand::thread_rng()` からサンプルするため、**`PROOF` 行は再生成時に
  バイト一致しない**。`VK` / `PK` / `INSTANCES` / `WITNESS` は再現可能。
  committed fixture は有効な証明として検証に使う。
- C ABI の `prove` は常に `OsRng` を使う。固定 seed は fixture 専用であり、
  本番経路では使わない。

`cargo test --lib halo2_ipa` は次を確認する（11 テスト）:

- `prepare` / `prove` / `verify` の k=8 ラウンドトリップ。
- committed fixture を C ABI 経由で検証（正常系・繰り返し呼び出し）。
- 公開入力の改ざん → `VERIFICATION_FAILED`。
- proof バイト改ざん → 非 OK（panic しない）。
- VK/PK/instances の切り詰め・末尾バイト・内部長の巨大化 → 具体的エラー。
- 非 canonical `Fr`、列数・値数の不一致。
- 不正 magic、未知 `circuit_id`、`k<4` / `k>16`、KZG magic の相互拒否。
- 空入力、NULL 入力、NULL 出力、短い出力バッファ。

### 観測値（k=8、この環境のデバッグビルド）

| 項目 | サイズ |
|---|---:|
| VK ペイロード | 106 バイト |
| VK（v1 エンコード） | 126 バイト |
| PK ペイロード | 73,886 バイト |
| PK（v1 エンコード） | 73,906 バイト |
| proof transcript | 1,152 バイト |
| proof（v1 エンコード） | 1,164 バイト |
| instances | 48 バイト |
| witness | 32 バイト |
| fixture ファイル | 2,771 バイト |

概算時間（デバッグビルド、この環境）: fixture 生成（keygen + prove + 1 回の
verify）で約 5.7 秒、検証 1 回は約 1.5 秒。これは小さなデモ回路の値であり、
一般的な R1CS フロントエンドの性能ではない。

WASM smoke（release、`ci/test_halo2_ipa_wasm.sh`）の出力サイズ:

| ターゲット | 成果物 | サイズ |
|---|---|---:|
| `wasm32-wasip1` | `halo2_ipa_verify.wasm` | 9,062,107 バイト |
| `wasm32-unknown-unknown` | `halo2_ipa_verify_web.wasm` | 9,421,082 バイト |
| `wasm32-unknown-unknown` | `librust_crypto_ffi.a` | 35,250,958 バイト |

`wasm32-unknown-unknown` は module を instantiate して verify に成功した。この
module は他モジュール由来の host 関数 import を持つが、smoke は全 import を
throw する stub に置き換えて実行しており、**verify 経路が RNG/host service を
呼ばない**ことを確認している。Poseidon2 の cdylib smoke は import 0 件である。
WASM の命令数・cycle・peak memory は未計測。

## セキュリティノート

- 検証側は乱数・ファイル I/O・時計・スレッド選択に依存しない。`k` から
  params を再生成するだけであり、`SingleStrategy` は RNG を呼ばない。
  `wasm32-unknown-unknown` の runtime smoke は全 host import を throw する
  stub で実行し、verify が RNG を呼ばないことを確認している。
- 証明側の blind は OS CSPRNG（`rand_core::OsRng`）を使う。fixture の固定
  seed はテスト専用。
- VK/PK は呼び出し側が与える信頼入力である。本ライブラリは構造検証と証明
  検証のみを行い、回路がアプリケーションの意図する命題を表すことまでは保証
  しない。承認済み VK のピン留めはアプリケーションの責任。
- `verify` は VK ヘッダの `k` から `ParamsIPA::new(k)` を毎回再生成する。
  `k <= 16` に制限しているが、`k` が大きいほど CPU/メモリコストが増える。
  信頼済み VK を pin し、繰り返し検証する利用側では `k` ごとの params を
  上位でキャッシュすることを推奨する。`vk_validate` は params を生成しない。
- 入力長・列数・値数・proof/PK の多項式長は decode/allocate 前に検査する。
  不正な PK の巨大 length で `Vec` を確保しないよう、独自の非割当スキャンを
  行う。
- `halo2-axiom` / `halo2curves` は本プロジェクトによる監査を受けていない。
- すべての C ABI 入口は `catch_unwind` で panic を捕捉し、`-1`
  （`RUSTCRYPTO_ERR_PANIC`）を返す。入力長・canonical 体要素・circuit_id・
  `k`・instance 形状・key 内部形状の検査はライブラリ呼び出し前に行う。
- `wasm32-unknown-unknown` / `wasm32-wasip1` の両方でビルドと verify の runtime
  smoke を実行済み。`panic = "abort"` のターゲットでは `catch_unwind` が機能
  しない点に注意。

## 未対応（明示）

- Poseidon2 の Halo2 カスタムゲート（別モジュールの Poseidon2 とは独立）。
- 任意の回路記述子 / Noir フロントエンド。回路は Rust のレジストリに
  コンパイル時登録されたものだけ。
- ICP canister 統合。
- **検証専用 feature / アーカイブ分離は未実装**。現状の wasm アーカイブは
  prover や他モジュール由来の `getrandom` / wasm-bindgen import を含み得る。
  実行時には verify がそれらを呼ばないことを throw-stub smoke で確認している
  が、canister の import 定義や dead-code elimination を最小化するには
  検証専用ビルドの追加が必要。
- ~1k / ~20k R1CS 相当の汎用ベンチ、browser Web Worker prove、ICP の
  instructions/cycle 計測。
- 一般的な R1CS フロントエンドとしての利用。本モジュールは小さなデモ回路
  （cubic v1）専用である。
