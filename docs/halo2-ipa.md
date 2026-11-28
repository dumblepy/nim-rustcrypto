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
本モジュールは `u32` の **承認済み回路レジストリ** を持つ。実装済みは次の 3 系統。

| `circuit_id` | 定数 | 回路 |
|---:|---|---|
| 1 | `HALO2_IPA_BN254_CIRCUIT_CUBIC_V1` | advice 1 列・instance 1 列・selector 1 個。ゲート `x^3 + x + 5 - y == 0`。witness `x`（32 バイト）、公開入力 `y`（1 列 1 値）。`4 <= k <= 16` |
| 2 | `HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH3_V1` | `poseidon2_halo2.rs` の固定 3 入力 Poseidon2 hash（互換用に維持）。witness は 3 個の canonical BE `Fr`（96 バイト）、公開入力は 1 列 `[digest, input0, input1, input2]`（4 値）。`7 <= k <= 16` |
| `0x100 + n`（`n = 0..=12`） | `HALO2_IPA_BN254_CIRCUIT_POSEIDON2_HASH_V1_BASE` | 同じ `Poseidon2HashCircuit` を **固定 `n` 入力** で登録した任意 arity 回路。witness は `n` 個の canonical BE `Fr`（`32 * n` バイト、`n = 0` は 0 バイト）、公開入力は 1 列 `n + 1` 値 `[digest, input0, .., input_{n-1}]`。最小 `k` は下記の行数規則で決まる |

`circuit_id` の符号化:

- `0x100 + 0` 〜 `0x100 + 12`（十進 `256`〜`268`）が任意 arity 回路。
- 旧来の `2` は **3 入力固定** の別 id として残す（既存 fixture / API を変更しない）。
- `poseidon2_arity(circuit_id)` は id `2` を `3`、`BASE + n` を `n`、それ以外を
  `None` として返す。

最小 `k` の規則（任意 arity）: `hash_circuit_rows(n)` は 1 permutation あたり
65 行（`65 * permutations`、permutation 数は rate 3 の sponge framing で決まる）。
Halo2 は blinding 用に `5 + 1 = 6` 行を予約するため、
`2^k - 6 >= hash_circuit_rows(n)` を満たす最小の `k` を採用する。実際には
arity `0..=3` は `k = 7`、`4..=9` は `k = 8`、`10..=12` は `k = 9` になる
（Rust の `poseidon2_arity_min_k` と Nim の `poseidon2HashMinK` が同じ規則を計算する）。

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
  keygen し、v1 形式で書き出す。乱数は使わない。`circuit_id = 2` と任意 arity
  (`BASE + n`) は 65 行の permutation レイアウトのため、それぞれ `k >= 7` と
  `2^k - 6 >= hash_circuit_rows(n)` を要求し、不足する `k` は
  `INVALID_PARAMETER` で拒否する。keygen は登録済み arity の
  `Poseidon2HashCircuit::new(&vec![Fr::from(0); arity])` を使う
  （`Default` の 0 入力では fixed 列が変わるため使わない）。`arity = 0` は
  空 vector で keygen する。
- `prove`: PK ヘッダの `circuit_id` を先に読み、回路ごとの witness 長
  （id 1 は 32 バイト、id 2 は 96 バイト、`BASE + n` は `32 * n` バイト）と
  公開入力を検査する。
  - id 1: `y == x^3 + x + 5`。
  - id 2 と `BASE + n`: witness の入力が公開入力 `input0..` と一致し、
    `digest == poseidon2_halo2::hash_output(&inputs)` であることを検査する。
  - `n = 0` の witness は 0 バイトで、**NULL ポインタと長さ 0 を受け付ける**
    （長さが非 0 なら拒否する）。

  公開入力と witness が食い違う場合は証明を生成せず `INVALID_PARAMETER`
  （形状不一致は `INVALID_PUBLIC_INPUT_COUNT`）を返す。証明は OS CSPRNG
  （`rand_core::OsRng`）で生成する。
- `verify`: VK をレジストリ回路でパースし、`circuit_id` に対応する公開入力
  形状（1 値、4 値、または `arity + 1` 値）を検査し、`k` から params を
  再生成（任意でキャッシュ）し、proof transcript を **末尾バイトまで消費**
  したことを確認して `SingleStrategy`（乱数を要求しない単一証明検証）で判定する。
- `*_validate`: 安価な構造検証。VK/PK はレジストリ回路によるデコードまで行う。
  proof は v1 エンベロープ（magic・長さ・末尾バイト）を、instances は全要素の
  canonical `Fr` と単一列形状（1..=13 値 = arity `0..=12` の `arity + 1`）を
  検査する。circuit id を受け取らないため、回路固有の値数一致は `verify` が
  行う。

### Nim の想定 API（type-first）

```nim
import rustcrypto/algorithm/halo2_ipa

# circuit 1: y = x^3 + x + 5
let (vk, pk) = Halo2IpaBn254.prepare(Halo2IpaBn254CircuitCubicV1, 8)
let instances = Halo2IpaBn254.encodePublicInstances([y])
let proof = Halo2IpaBn254.prove(pk, witnessBytes, instances)

# circuit 2: 3-input Poseidon2 hash (legacy, digest of inputs[0..2])
let (vk2, pk2) = Halo2IpaBn254.prepare(
  Halo2IpaBn254CircuitPoseidon2Hash3V1, 8
)
let instances2 = encodePoseidon2HashInstances([input0, input1, input2], digest)
let witness3 = input0 & input1 & input2   # 96 bytes
let proof2 = Halo2IpaBn254.prove(pk2, witness3, instances2)

# arbitrary arity 0..=12: circuit id = BASE + arity
let (vk4, pk4) = Halo2IpaBn254.preparePoseidon2Hash(4, 8)  # min k = 8
let instances4 = encodePoseidon2HashInstances(inputs4, digest4)
let proof4 = Halo2IpaBn254.provePoseidon2Hash(pk4, inputs4, digest4)

if Halo2IpaBn254.verify(vk4, proof4, instances4):
  echo "valid for this profile and key"
```

`prepare` は `(verifyingKey, provingKey)`、`prove` は `seq[byte]`、
`verify` は `bool` を返す想定。`prove` は PK ヘッダの circuit id から
witness 長を決める（id 1 = 32 バイト、id 2 = 96 バイト、`BASE + n` =
`32 * n` バイト）。`preparePoseidon2Hash` は `arity` と最小 `k` を検証し、
`provePoseidon2Hash` は入力の連結を witness、`[digest, inputs...]` を公開入力
として `prove` に渡す。`poseidon2HashCircuitId` / `poseidon2HashMinK` で
id と最小 `k` を取得できる。`validateVerifyingKey` / `validateProvingKey` /
`validateProof` / `validatePublicInstances` も同様に `bool` を返す。

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
| 8 | 4 | `circuit_id`（`1` = cubic v1、`2` = Poseidon2 hash3、`0x100 + n` = 任意 arity Poseidon2 hash） |
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
- 登録回路の instance 形状のみを受け付ける:
  - id 1（cubic）: 1 列 1 値。
  - id 2（Poseidon2 hash3）: 1 列 4 値 `[digest, input0, input1, input2]`。
  - `BASE + n`（任意 arity）: 1 列 `n + 1` 値
    `[digest, input0, .., input_{n-1}]`（`n = 0` は digest のみ）。

  それ以外は `INVALID_PUBLIC_INPUT_COUNT`。ただし circuit id を受け取らない
  `instances_validate` は、単一列で 1..=13 値（arity `0..=12` の `arity + 1`
  を包含）であれば OK を返し、回路固有の一致は `verify` が検査する。
- `column_count == 0` は拒否する。

### サイズ・`k` の上限

| 項目 | 上限 |
|---|---|
| `k` | 4..=16（id 2 は 7..=16、`BASE + n` は `0..=3` で 7、`4..=9` で 8、`10..=12` で 9 以上） |
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

`rustcrypto-ffi/examples/halo2_ipa_poseidon2_fixture.rs` が k=8・
`circuit_id=2`・入力 `[1, 2, 3]` の fixture を生成する。出力は
`tests/fixtures/halo2_ipa_poseidon2_v1.hex`。digest は
`23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8`。

```text
cargo run --locked --release --example halo2_ipa_poseidon2_fixture [output.hex]
```

第 2 引数に arity（`0..=12`）を渡すと任意 arity 回路（`BASE + arity`）を
最小 `k` で生成する。arity 12 の committed fixture は
`tests/fixtures/halo2_ipa_poseidon2_arity12_v1.hex`（`circuit_id = 268`、
`k = 9`、入力 `1..=12`、witness 384 バイト、instance 13 値）。

```text
cargo run --locked --release --example halo2_ipa_poseidon2_fixture \
  ../tests/fixtures/halo2_ipa_poseidon2_arity12_v1.hex 12
```

`cargo test --lib halo2_ipa` は次を確認する（19 テスト）:

- `prepare` / `prove` / `verify` の k=8 ラウンドトリップ（cubic と Poseidon2）。
- 両 committed fixture（cubic / id 2）を C ABI 経由で検証（正常系・繰り返し呼び出し）。
- 任意 arity `0, 1, 2, 3, 4, 6, 8, 9, 12` の最小 `k` での
  prepare / prove / verify、誤 digest の拒否、witness と公開入力の不一致の
  拒否、arity 0 の空 witness（NULL ポインタ）受理。
- `poseidon2_arity` / `poseidon2_arity_min_k` の id 符号化と最小 `k` 規則、
  `BASE + 13` の拒否。
- 公開入力の改ざん → `VERIFICATION_FAILED`。
- proof バイト改ざん → 非 OK（panic しない）。
- VK/PK/instances の切り詰め・末尾バイト・内部長の巨大化 → 具体的エラー。
- 非 canonical `Fr`、列数・値数の不一致、circuit 2 の 1 値/2 値/32 バイト
  witness の拒否。
- circuit 2 の `k < 7`、任意 arity の最小 `k` 未満 → `INVALID_PARAMETER`。
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

Poseidon2 hash3（k=8、`cargo run --locked --release --example
halo2_ipa_poseidon2_fixture`）の観測値:

| 項目 | サイズ |
|---|---:|
| VK ペイロード | 1,194 バイト |
| VK（v1 エンコード） | 1,214 バイト |
| PK ペイロード | 632,302 バイト |
| PK（v1 エンコード） | 632,322 バイト |
| proof transcript | 5,600 バイト |
| proof（v1 エンコード） | 5,612 バイト |
| instances | 144 バイト |
| witness | 96 バイト |
| fixture ファイル | 14,163 バイト |

WASM smoke（release、`ci/test_halo2_ipa_wasm.sh`）の出力サイズ:

| ターゲット | 成果物 | サイズ |
|---|---|---:|
| `wasm32-wasip1` | `halo2_ipa_verify.wasm` | 9,004,435 バイト |
| `wasm32-unknown-unknown` | `halo2_ipa_verify_web.wasm` | 9,363,925 バイト |
| `wasm32-unknown-unknown` | `librust_crypto_ffi.a` | 35,277,024 バイト |

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
- `verify` は VK ヘッダの `k` から `ParamsIPA::new(k)` を再生成する。
  `k <= 16` に制限しているが、`k` が大きいほど CPU/メモリコストが増える。
  optional feature `halo2-ipa-params-cache` を有効にすると、thread-local の
  単一スロットに `(k, ParamsIPA)` を保持し、同一 `k` の検証で clone を再利用
  する。これは **canister インスタンスごとの heap メモリ** であり、upgrade で
  失われ、trusted SRS のキャッシュではない（params は `k` から決定的に導出
  される）。既定（feature off）は毎回再生成する。信頼済み VK を pin し、
  繰り返し検証する利用側ではこの feature の利用を推奨する。
  `vk_validate` は params を生成しない。
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

- **Poseidon2 hash は circuit id 2（3 入力固定、互換用）と任意 arity
  `BASE + 0..=12` の両方が登録済み**。id 2 は witness 96 バイト、公開入力
  `[digest, input0, input1, input2]`、`k >= 7`。任意 arity は witness
  `32 * n` バイト、公開入力 `[digest, inputs...]`、最小 `k` は行数規則で
  7/8/9。Nim からは `Halo2IpaBn254CircuitPoseidon2Hash3V1` /
  `Halo2IpaBn254CircuitPoseidon2HashV1Base`、`preparePoseidon2Hash` /
  `provePoseidon2Hash` / `encodePoseidon2HashInstances` で利用できる。
  Poseidon1 gate はまだ circuit id を持たない。詳細は
  [`poseidon2-halo2-gate.md`](poseidon2-halo2-gate.md)。
- 任意の回路記述子 / Noir フロントエンド。回路は Rust のレジストリに
  コンパイル時登録されたものだけ。
- 一般的な R1CS フロントエンドとしての利用。本モジュールは小さなデモ回路
  （cubic v1 と Poseidon2 hash）専用である。
- Poseidon2 hash 回路自体の **wasm32-wasip1** 実行は完了
  （[`poseidon2-halo2-wasm.md`](poseidon2-halo2-wasm.md)）。browser Worker /
  ICP 上での Poseidon2 witness 生成・prove は未実装（canister の proof 検証は
  circuit id 2 に対応）。
- Poseidon1 の Halo2 custom gate は**比較用に実装済み**
  （[`poseidon1-halo2-gate.md`](poseidon1-halo2-gate.md)）。同一 k=10・同一
  IPA での rows/VK/PK/proof 比較は [`benchmarks-branch85.md`](benchmarks-branch85.md)
  に記録。width 4・3 入力固定で、C ABI/Nim には未登録。

## 実装済みになった項目

- **検証専用 feature**: `halo2-ipa-verify-only` で prover/keygen と
  `prepare`/`prove`/`pk_validate` シンボルを除外できる。ICP verifier canister
  はこの feature でビルドし、wasm import が `ic0` の 5 関数のみであることを
  確認済み。詳細は [`ic-branch85.md`](ic-branch85.md)。この feature は
  prover API を削除するため、fixture generator や Nim の `prepare`/`prove`
  を同時に使うビルドでは有効にしない。
- **IPA params cache feature**: `halo2-ipa-params-cache` で thread-local の
  単一 `ParamsIPA` を再利用できる。cold/warm の区別、canister インスタンス
  単位・upgrade で失われる点は [`ic-branch85.md`](ic-branch85.md) を参照。
- **Poseidon2 hash3 circuit (id 2)**: 3 入力固定の Poseidon2 sponge を
  `rustcrypto_halo2_ipa_bn254_*` と Nim から利用可能。committed fixture は
  `tests/fixtures/halo2_ipa_poseidon2_v1.hex`。
- **ICP canister**: VK をビルド時に pin した raw update verifier を PocketIC で
  実行済み。params 再生成を含む cold call の instructions、および cache 済み
  warm call の instructions は [`ic-branch85.md`](ic-branch85.md) を参照。
  memory は 53 pages 程度。
- **Browser Web Worker prove**: COOP/COEP なし・`crossOriginIsolated=false` の
  Chromium で Worker 内 prepare/prove を実行し、Node 側の独立 wasm でも検証。
  実測（k=8、cubic v1）: prepare 約 1.9–4.1 s、prove 約 2.6–4.9 s、
  verify 約 1.6–2.2 s、wasm 3,962,513 B（circuit id 2 登録後）、linear memory は
  prepare 約 3.9 MB / prove・verify 約 8.1 MB。`SharedArrayBuffer` は不使用。
- **ベンチ**: R1CS 形状・native 時間・IPA 1k/20k 相当の合成回路を実測。
  [`benchmarks-branch85.md`](benchmarks-branch85.md)。なお 20k 回路は
  アプリケーション等価ではなく形状ベンチである。
