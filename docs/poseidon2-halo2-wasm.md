# Poseidon2 Halo2 custom gate の wasm32-wasip1 実行

Rust 実装:

- `rustcrypto-ffi/examples/poseidon2_halo2_wasm.rs` — native / wasm32-wasip1 共通の
  prove/verify 実行 smoke
- `ci/test_poseidon2_halo2_wasm.sh` — ビルド・native 実行・Node WASI 実行・計測
- `ci/poseidon2_halo2_wasm_smoke.mjs` — Node WASI ランナー
- `rustcrypto-ffi/src/poseidon2_halo2.rs` — 回路本体（本ドキュメントの対象外）
- `docs/poseidon2-halo2-gate.md` — 回路レイアウト・制約・KAT

本ドキュメントは **Poseidon2 Halo2 custom gate を wasm32-wasip1 上で実際に
実行した結果**だけを扱う。回路そのものの設計・KAT は
[`poseidon2-halo2-gate.md`](poseidon2-halo2-gate.md) を参照する。

## 1. 何を実行するか

`Poseidon2HashCircuit`（入力 `[1, 2, 3]`、Noir/Barretenberg sponge、1 permutation）
を BN254 / IPA で prove し、同じ wasm モジュール内で verify する。

- `ParamsIPA::<G1Affine>::new(10)`（決定的 hash-to-curve、SRS ceremony 不要）
- `keygen_vk` / `keygen_pk`
- `create_proof`（BGH19 multi-open、Blake2b transcript、`StdRng::from_seed([0x85; 32])`）
- `verify_proof`（`SingleStrategy`。`AccumulatorStrategy` は `OsRng` を要求するため使わない）
- 誤った digest（公開 instance の digest を +1）を拒否すること
- 改変した proof（末尾 1 byte を XOR）を拒否すること

ビルド成功ではなく、**wasm 内で keygen / prove / verify を最後まで実行**し、
負のケースも含めて結果を検査する。失敗時は非ゼロ終了する。

## 2. 実行コマンド

```bash
cd /application/rustcrypto-ffi
cargo run --locked --release --example poseidon2_halo2_wasm

cd /application
bash ci/test_poseidon2_halo2_wasm.sh /tmp/poseidon2-halo2-wasm
```

スクリプトは以下を行う。

1. `rustup target add wasm32-wasip1`（未導入時のみ）
2. `cargo build --locked --release --example poseidon2_halo2_wasm --target wasm32-wasip1`
3. native の `cargo run --locked --release --example poseidon2_halo2_wasm`
4. `node ci/poseidon2_halo2_wasm_smoke.mjs <wasm>`（WASI preview1、`returnOnExit: true`）
5. native / wasm の JSON を照合し、`environment.txt` と `measurements.json` を出力

`CARGO_TARGET_DIR` の既定値は `rustcrypto-ffi/target`。wasm-bindgen とネットワーク
アクセスは不要。

## 3. 実測値

> **V2 再計測済み**: 以下は P0 制約健全性修正後の V2 artifact
> （`RCH2IPV2` / `RCH2IPP2`）で再実行した記録である。KAT digest は V1 と
> 同じで、未使用 absorb lane の zero 制約により VK/PK は新しい revision に
> なっている。Poseidon2 は V2 のみをサポートし、V1 fixture / VK は保持しない。

環境:

- Ubuntu Linux x86_64
- rustc 1.99.1 / cargo 1.99.1
- Node.js v24.22.1（`node:wasi` は experimental、WASI `version: "preview1"`）
- wasm32-wasip1、release ビルド

回路・成果物:

| 項目 | 値 |
|---|---:|
| k | 10 |
| rows / permutations | 65 / 1 |
| instance rows | 4 |
| advice columns | 25 |
| selectors | 5 |
| gate degree | 4 |
| VK bytes（`SerdeFormat::Processed`） | 1,194 |
| PK bytes（`SerdeFormat::Processed`） | 2,524,654 |
| proof bytes（transcript） | 5,728 |
| wasm ファイルサイズ | 9,989,284 bytes |
| wasm SHA-256 | `d794216c782183179644289a5ebc539926a193dc70f74b1dbf275ca8fc21da9c` |

1 回の実行例（時間は実行ごとに変動する）:

| 処理 | native | wasm32-wasip1 |
|---|---:|---:|
| keygen（params + VK + PK） | 1,001.1 ms | 11,220.8 ms |
| prove | 826.1 ms | 5,426.7 ms |
| verify | 13.8 ms | 144.3 ms |
| プロセス全体の wall time | 未記録 | 17,670 ms |

wasm の wall time は Node 起動・WASI 初期化・`ParamsIPA::new(10)` を含む。
native の wall time は cargo の起動オーバーヘッドを含み、他タスクとのビルド
ロック待ちがあると数十秒まで伸びる。処理時間の比較には上の個別値を用いる。
wasm の keygen が特に遅いのは、決定的な hash-to-curve による params 生成が
wasm では高コストなため。prove は native の約 6 倍、verify は約 9 倍だった。

wasm ファイルサイズは crate 全体（他モジュールを含む）の release ビルド結果で
あり、無関係なコード変更でも数 KB 変動する。SHA-256 は上記計測時点のもの。

再現時の値は `measurements.json` に native / wasm 双方の JSON と wall time が
そのまま残る。

## 4. KAT

入力 `[1, 2, 3]`、Noir/Barretenberg framing の digest:

```text
23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8
```

native / wasm の双方で次を確認している。

```json
{
  "digest_ok": true,
  "verified": true,
  "wrong_rejected": true,
  "tampered_rejected": true
}
```

公開 instance は `[digest, 1, 2, 3]`。回路は raw 入力と digest の両方を
instance 列に拘束する。

## 5. 実装上の注意

- **wasm の prove は乱数を必要とする**: vendored `halo2-axiom` の vanishing
  prover が内部で `rand::thread_rng()` を使う。Node WASI は
  `random_get` を提供するため wasm32-wasip1 では動作する。prove 用の
  `StdRng` seed を固定しても、この内部乱数のため proof bytes は実行ごとに
  一致しない。proof 長と検証結果は一致する。
- **verify は乱数を要求しない**: `SingleStrategy` を使うため、検証経路は
  `OsRng` を呼ばない。
- **失敗時の終了コード**: `std::process::exit` を wasm で直接呼ばず、
  `fn main() -> Result<(), SmokeFailure>` の `Err` で終了コード 1 を返す。
- **JSON 出力**: 1 行の compact JSON。`target` は native なら `"native"`、
  wasm なら `"wasm"`（本 smoke は wasm32-wasip1）。Node ランナーは stdout を
  捕捉し、必須フィールドと `digest_ok` / `verified` / `wrong_rejected` /
  `tampered_rejected` がすべて `true` であることを検査する。
- **タイムアウト**: スクリプトの既定は 1,800 秒
  （`POSEIDON2_HALO2_WASM_TIMEOUT_SECONDS` で変更可能）。

## 6. 制限・未実施

- **このドキュメントの範囲は wasm32-wasip1**。wasm32-unknown-unknown の
  browser / Web Worker での prove は別途完了しており、circuit id 2 を
  **Poseidon2 V2 で** Chromium 上で prepare/prove/verify 済み（
  [`poseidon2-halo2-browser-icp.md`](poseidon2-halo2-browser-icp.md)）。
  ICP は circuit id 2 の **V2 VK を pin した** verify-only canister を PocketIC
  で実行済みで、canister 内 proving / keygen は未実装・未試行。
- **ブラウザ実行の詳細は別ドキュメント**: COOP/COEP なし・
  `crossOriginIsolated=false` の構成は
  [`poseidon2-halo2-browser-icp.md`](poseidon2-halo2-browser-icp.md) を参照。
- **決定論的 RNG はテスト専用**: `StdRng::from_seed([0x85; 32])` は fixture
  専用。本番の IPA blinding には OS CSPRNG を使うこと。
- **未監査のデモ回路**: `Poseidon2HashCircuit` は監査済みの汎用 Halo2
  frontend ではない。VK の pin、circuit id の承認、本番資産への適用は
  利用側の責務。
- **C ABI / Nim 統合済み**: 本回路は `rustcrypto_halo2_ipa_bn254_*` の
  circuit id レジストリに `circuit_id=2`（3 入力固定）と `0x100+n`
  （任意 arity、n=0..=12）として登録されている。鍵 artifact は **V2**
  （`RCH2IPV2` / `RCH2IPP2`）であり、旧 V1-magic の Poseidon2 VK/PK は拒否
  される。fixture は V2 のみで、wasm32-wasip1 の V2 実行も完了している。
- **Chip の wasm 実行は未検証**: `Poseidon2Chip` は Rust の回路部品であり、
  この smoke は単体 `Poseidon2HashCircuit` を実行する。Chip を使う複合回路の
  wasm 実行は別途検証が必要。
- **性能比較ではない**: k=10 は意図的な固定値であり、回路の最適化や
  Poseidon1 との比較を目的としない。wasm の実行時間はホスト CPU と Node の
  バージョンに依存する。
- **proof の byte 一致なし**: 上記の内部 `thread_rng()` のため、同じ入力でも
  proof bytes は毎回異なる。KAT は digest と検証結果で判定する。

## 7. 再現手順

```bash
# 1. 依存と target
rustup target add wasm32-wasip1
node --version   # node:wasi が使えること

# 2. native
cd /application/rustcrypto-ffi
cargo run --locked --release --example poseidon2_halo2_wasm

# 3. wasm を含む一括 smoke
cd /application
bash ci/test_poseidon2_halo2_wasm.sh /tmp/poseidon2-halo2-wasm

# 4. 記録の確認
cat /tmp/poseidon2-halo2-wasm/environment.txt
cat /tmp/poseidon2-halo2-wasm/measurements.json
```

成功時は最後に `Poseidon2 Halo2 wasm checks passed` が表示される。
wasm の prove が環境要因で失敗した場合は、成功扱いにせずスクリプトが
非ゼロ終了する。その場合は Node / WASI のバージョン、`random_get` の対応、
`CARGO_TARGET_DIR`、タイムアウト値を確認する。
