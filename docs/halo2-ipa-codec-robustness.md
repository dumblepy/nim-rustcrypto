# Halo2 IPA C ABI / 汎用レジストリ codec 堅牢性テスト

対象ブランチ: `87-修正設計実装-halo2-ipaの制約健全性修正汎用circuit登録api秘密入力対応poseidon2-chip`

## 1. 目的

Halo2 IPA / BN254 の C ABI (`rustcrypto-ffi/src/halo2_ipa.rs`) と、
コンパイル時登録型の汎用アダプタ (`rustcrypto-ffi/src/halo2_ipa_registry.rs`) に対して、

- 不正・切り詰め・過大な VK / PK / proof / instances エンベロープ
- コミット済み fixture の決定的な単バイト改変・ランダム改変
- 回路リビジョン (V1 cubic / V2 Poseidon2) の取り違え
- 上限値 (VK 4 MiB / PK 64 MiB / proof 4 MiB / 8 列 / 4096 値)
- NULL / 長さ 0 / バッファより大きい長さを主張するヘッダ

を入力しても、**プロセスが停止せず、文書化されたステータスコードだけを返す**
ことを確認する。外部 fuzz crate は使わず、固定 seed の xorshift64 で再現可能に
している。

## 2. 実行方法

```bash
# 通常 (prover + verifier)
cd rustcrypto-ffi
cargo test --locked --test halo2_ipa_codec_robustness

# verifier-only feature (prover / keygen シンボルを含めない)
cargo test --locked --features halo2-ipa-verify-only \
  --test halo2_ipa_codec_robustness

# 両方をまとめて実行する CI スクリプト
bash ci/test_halo2_ipa_codec_robustness.sh
```

`ci/test_halo2_ipa_codec_robustness.sh` は既定で両方のパスを実行する。
verifier-only パスを省略したい場合は
`HALO2_IPA_CODEC_SKIP_VERIFY_ONLY=1` を設定する。

`halo2-ipa-verify-only` では prover / keygen を必要とするテストは
`#[cfg(not(feature = "halo2-ipa-verify-only"))]` でコンパイル対象から外れる。
そのため verifier-only 実行では 14 テスト中 3 テストが除外され、11 テストが走る。

## 3. テストマトリクス

テストファイル: `rustcrypto-ffi/tests/halo2_ipa_codec_robustness.rs`

### 3.1 組み込み C ABI

| テスト | 入力 | 期待 |
|---|---|---|
| `committed_fixtures_are_accepted` | `halo2_ipa_bn254_v1.hex` (V1 cubic)、`halo2_ipa_poseidon2_v1.hex` (V2 id 2)、`halo2_ipa_poseidon2_arity12_v1.hex` (V2 id `0x10c`) | validate と verify が `OK` |
| `every_truncation_is_total_and_documented` | cubic VK の全 prefix (0..len)、proof の全 prefix、instances の全 prefix。Poseidon2 は各フィールド境界と len-1。verify は各 1 代表長 | すべて文書化ステータス。`PANIC` なし |
| `header_corruption_is_rejected_with_documented_status` | 末尾 1 バイト、magic 破壊、未知 circuit id、V1/V2 magic と circuit id の不一致、k=0/3/17/`u32::MAX`、長さヘッダ 0 / 実長±1 / `u32::MAX`、列数 0/9/`u32::MAX`、値数 0/2/14/`u32::MAX` | 主に `INVALID_LENGTH(9)`, `INVALID_VERIFYING_KEY(23)`, `INVALID_CIRCUIT_DATA(25)`, `INVALID_PROOF_FORMAT(22)`, `INVALID_PUBLIC_INPUT_COUNT(24)` |
| `noncanonical_and_zero_buffers_are_documented` | 32 バイト値に `Fr` modulus ちょうど、modulus-1、`0xff..ff`。長さ 0/8/11/12/19/20/21/48/64 の全ゼロバッファ | modulus 以上は `INVALID_FIELD_ELEMENT(20)`、modulus-1 は `OK`。ゼロバッファは文書化ステータスのみ |
| `null_and_zero_length_pointers_are_documented` | 各エンベロープの NULL + 非ゼロ長、NULL + 長さ 0、有効ポインタ + 長さ 0 | NULL+データは `NULL_INPUT_WITH_DATA(3)`。長さ 0 は各関数の長さエラー (`9` / `22`) |
| `declared_bounds_are_enforced` | VK 長ヘッダ 4 MiB+1、proof 長ヘッダ 4 MiB+1、PK 長ヘッダ 64 MiB+1、列数 9、列あたり 2049 値×2、値数 `MAX+1`、値数がバッファより大きい blob | `INVALID_LENGTH(9)` / `INVALID_PROOF_FORMAT(22)` / `INVALID_PUBLIC_INPUT_COUNT(24)`。巨大メモリは確保しない |
| `cross_revision_artifacts_are_separated` | V1 cubic、V2 Poseidon2、V2 magic を付けた cubic、V1 magic を付けた Poseidon2、cubic VK + Poseidon2 proof | cubic V1 と V2 Poseidon2 は `OK`。V2 cubic と V1 Poseidon2 は `INVALID_VERIFYING_KEY(23)` |
| `deterministic_mutation_fuzz_never_panics` | cubic 600 回 + Poseidon2 V2 150 回。固定 seed。各回 1〜3 バイトを VK/proof/instances から選んで XOR。毎回 3 つの validate、256 回ごとに verify | すべて文書化ステータス。`PANIC` なし |
| `representative_single_byte_mutations_are_documented` | VK ヘッダ全 20 バイト、proof ヘッダ 8 バイト、instances ヘッダ 12 バイト、proof/VK/instance payload の代表オフセット | ヘッダ改変は非 `OK`。proof payload 改変は非 `OK`。payload 改変でも `PANIC` なし |

### 3.2 prover 側 (既定ビルドのみ)

| テスト | 入力 | 期待 |
|---|---|---|
| `pk_codec_and_prove_bounds_are_documented` | C ABI `prepare` で生成した cubic k=8 の VK/PK。PK の prefix / 末尾 / magic / circuit id / k / 長さヘッダ改変。prove へ切り詰め PK、V1 relabel PK、誤 circuit id、誤 k、長さ 63/64/16 バイト witness、`0xff` witness、2 値 instances、statement 不一致、NULL 出力・NULL `proof_len` | PK は `INVALID_LENGTH(9)` / `INVALID_CIRCUIT_DATA(25)`。prove は `INVALID_LENGTH(9)` / `INVALID_FIELD_ELEMENT(20)` / `INVALID_PUBLIC_INPUT_COUNT(24)` / `INVALID_PARAMETER(15)` / `NULL_OUTPUT(1)` |
| `arity12_witness_length_overflow_is_rejected` | arity 12 (`0x10c`) の k=9 鍵を 1 回だけ生成。witness を 13×32 バイト、383 バイト、先頭 `0xff` に変更 | `INVALID_LENGTH(9)` / `INVALID_FIELD_ELEMENT(20)`。prove は実行されない |

### 3.3 汎用レジストリ

`EqualityCircuit` (advice 1 本 = 公開 instance 1 個、witness 32 バイト) をテスト内で
`ApprovedCircuit` として実装する。回路 id は
`HALO2_IPA_EXTERNAL_CIRCUIT_ID_BASE + 0x21`、`k` は 4..=8。

| テスト | 内容 | 期待 |
|---|---|---|
| `registry_rejects_invalid_profiles` | `CircuitProfile::validate`: id が external base 未満、min_k < 4、max_k > 16、min_k > max_k、witness_len > 1 MiB、列 0 本 / 9 本、列長 0、合計値 > 4096、VK/PK/proof 上限 0 またはグローバル上限超え | すべて `INVALID_PARAMETER(15)`。妥当な profile は `Ok` |
| `registry_validate_rejects_malformed_envelopes` | `validate_vk` / `validate_instances` / `validate_proof` / `verify` に空・切り詰め・V1 magic・組み込み回路の VK・誤 circuit id・k=3/9・長さ 0 / 4 MiB+1・短い payload・2 列 / 2 値・非 canonical・末尾バイト・proof 長 0 / 4 MiB+1 を渡す | `INVALID_LENGTH(9)`, `INVALID_VERIFYING_KEY(23)`, `INVALID_CIRCUIT_DATA(25)`, `INVALID_PUBLIC_INPUT_COUNT(24)`, `INVALID_FIELD_ELEMENT(20)`, `INVALID_PROOF_FORMAT(22)` |
| `registry_roundtrip_and_mutations` (prover のみ) | `prepare::<EqualityCircuit>(8)` → `prove` → `verify` が `OK`。その後 VK/proof/instances の切り詰め、V1 relabel、誤 circuit id、k=3/9、ヘッダ全バイト改変、proof payload 改変、誤公開値、prove への切り詰め PK / V1 PK / 誤 id / 誤 k / 長さ 31・33・64 バイト witness / `0xff` witness / 2 値 instances / 非 canonical instances、`prepare` の k=3/9 | 文書化ステータスのみ。正しい proof は `OK`、誤公開値は `VERIFICATION_FAILED(8)` |

## 4. 返却ステータスの期待値

| コード | 名前 | このテストでの主な発生源 |
|---:|---|---|
| 0 | `RUSTCRYPTO_OK` | 正しい fixture / 正しい小回路 proof |
| 1 | `RUSTCRYPTO_ERR_NULL_OUTPUT` | `prepare` / `prove` の NULL 出力・NULL 長ポインタ |
| 2 | `RUSTCRYPTO_ERR_OUTPUT_TOO_SHORT` | `prepare` の 1 バイト出力バッファ |
| 3 | `RUSTCRYPTO_ERR_NULL_INPUT_WITH_DATA` | NULL ポインタ + 非ゼロ長 |
| 8 | `RUSTCRYPTO_ERR_VERIFICATION_FAILED` | 改変 proof / 誤公開値 |
| 9 | `RUSTCRYPTO_ERR_INVALID_LENGTH` | 長さ 0、過大 outer/inner 長、trailing、PK/VK 長不一致 |
| 15 | `RUSTCRYPTO_ERR_INVALID_PARAMETER` | 未登録 circuit id / 範囲外 k、statement 不一致、不正 profile |
| 20 | `RUSTCRYPTO_ERR_INVALID_FIELD_ELEMENT` | 非 canonical `Fr` (modulus 以上) |
| 22 | `RUSTCRYPTO_ERR_INVALID_PROOF_FORMAT` | proof magic / 長さ / transcript 不一致 |
| 23 | `RUSTCRYPTO_ERR_INVALID_VERIFYING_KEY` | VK magic と circuit revision の不一致、VK デコード失敗 |
| 24 | `RUSTCRYPTO_ERR_INVALID_PUBLIC_INPUT_COUNT` | 列数・値数・回路ごとの instance 形状不一致 |
| 25 | `RUSTCRYPTO_ERR_INVALID_CIRCUIT_DATA` | 未知 circuit id、PK magic / デコード失敗、回路非対応 |
| -1 | `RUSTCRYPTO_ERR_PANIC` | **発生してはならない**。全テストで明示的に拒否 |

## 5. カバレッジと設計上の注意

- **truncation は全 prefix** を cubic fixture について確認する。proof は 1152 バイト、
  VK は 126 バイト、instances は 48 バイトなので、全 prefix でも十分高速。
- **mutation は固定 seed** (`0x9E37_79B9_7F4A_7C15`, `0xD1B5_4A32_D192_ED03`) で
  再現可能。失敗時は iteration 番号がメッセージに出る。
- **verify の呼び出し回数は意図的に制限**している。`rustcrypto-ffi` の既定ビルドでは
  `verify` ごとに `ParamsIPA::new(k)` を再生成するため、mutation 全件で verify すると
  テスト時間が跳ね上がる。validate は毎回、verify は 256 回ごと＋代表ケースのみ。
- **巨大確保の回避**: VK 4 MiB / PK 64 MiB / proof 4 MiB の上限は、実際に巨大な
  バッファを確保せず、エンベロープ内の長さヘッダだけで確認する。
- **本物の proving/keygen は最小限**: cubic k=8 の `prepare` 1 回、arity 12 k=9 の
  `prepare` 1 回、テスト用小回路 k=8 の `prepare` + `prove` 1 回のみ。
  mutation ループ内では proving も keygen も行わない。

## 6. 既知の制限

1. `MAX_INSTANCE_VALUES = 4096` を超える instances は、外側の
   `MAX_INSTANCES_BLOB_LEN` も同時に超えるため、公開 C ABI では
   `INVALID_LENGTH(9)` が先に返る。内部の合計値チェック (24) は
   `validate_instances` のヘッダのみのケースで確認している。
2. このテストは **wasm / panic=abort** を実行しない。C ABI の `catch_unwind` は
   native の unwind ビルドでのみ検証される。wasm の trap 耐性は別の wasm smoke
   (`ci/test_halo2_ipa_wasm.sh` など) の範囲。
3. 外部クレートが登録する任意の `ApprovedCircuit` すべてを実行するものではない。
   レジストリの一般経路はテスト内の小さな `EqualityCircuit` で確認し、組み込み
   回路の codec はコミット済み fixture で確認する。
4. Poseidon2 の V2 fixture は id 2 と arity 12 のみ使用する。arity 0..=11 の
   全鍵生成は既存 unit test (`arbitrary_arity_prepare_prove_verify_roundtrip`) が
   担う。本テストは codec 堅牢性に限定する。
5. 乱数改変はバイト XOR が中心で、構造を保ったまま意味だけを変える網羅的な
   文法 fuzz ではない。ステータスコードの網羅と panic 不在を目的とする。
6. 本テストは未監査の実装に対する回帰・堅牢性試験であり、資産用途の安全性を
   保証しない。独立レビューが別途必要である。
