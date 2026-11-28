# Poseidon2 Halo2 IPA: browser Worker 証明と ICP 検証 canister（branch 85）

このドキュメントは、branch 85 の Poseidon2（BN254 Fr, width 4, 3 入力）Halo2
IPA 回路を **ブラウザの Web Worker で prove** し、**ICP canister で verify**
する経路の実装・実測・制約をまとめる。Halo2 IPA の profile は
`halo2-axiom 0.5.3 (vendored) / BN254 G1 / Fr / IPA(BGH19) / Blake2b` で、
trusted setup（SRS ceremony）を必要としない。

- 回路 id `2`: Noir/Barretenberg 互換 Poseidon2 sponge の 3 入力固定回路
- witness: 3 個の canonical 32-byte big-endian `Fr`（合計 96 bytes）
- 公開入力: `"RCH2IPI1" | column_count u32 BE (=1) | value_count u32 BE (=4) | digest | input0 | input1 | input2`
- `k = 8`（回路の最小 `k` は 7）
- 既知値（KAT）: 入力 `[1, 2, 3]` →
  `23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8`

cubic（id `1`, `y = x^3 + x + 5`, witness `x = 3`, 公開 `y = 35`）は既存の
経路を維持し、同じブラウザ smoke と CI で回帰確認する。

---

## 1. ブラウザ Web Worker で circuit 2 を prove する

### 1.1 実行構成

| ファイル | 役割 |
|---|---|
| `web/halo2-ipa-prover/index.html` | プレーンな HTML。`page.mjs` を module として読み込む |
| `web/halo2-ipa-prover/page.mjs` | メインスレッドのオーケストレーション。circuit 1 → 2 の順に prepare / prove / verify / 負例を実行 |
| `web/halo2-ipa-prover/worker.mjs` | wasm-bindgen アダプタを所有する module Worker。`prepare` / `prove` / `verify` を実行 |
| `web/halo2-ipa-prover/smoke.mjs` | COOP/COEP なしの HTTP origin を立て、headless Chromium を駆動。さらに Node の独立 wasm instance で両 proof を再検証 |
| `ci/test_halo2_ipa_web.sh` | `wasm32-unknown-unknown` build → `wasm-bindgen --target web` → smoke |

メインスレッドは wasm を import しない。`prepare`（keygen）と `prove` は
Worker 内で実行され、結果の `metrics.inWorker` が `true` であることを smoke が
確認する。PK と witness の `ArrayBuffer` は `postMessage` の transfer list で
Worker へ移し、Worker は Rust アダプタが witness をコピーした後に JS 側の
witness buffer をゼロ埋めする（`witnessZeroized`）。

### 1.2 両回路のフロー

1. Worker の `info` で ABI version `1`、既定 circuit id `1` を確認。
2. **circuit 1**: `prepare(1, 8)` → witness `Fr(3)`（32 bytes）→
   instances `[35]` → Worker で prove → verify `true`。
   公開値を 1 byte 改変した instance と、proof 末尾を 1 byte 改変した proof が
   ともに `false` になることを確認。
3. **circuit 2**: `prepare(2, 8)` → witness `Fr(1) || Fr(2) || Fr(3)`
   （96 bytes）→ instances `[digest, 1, 2, 3]`（144 bytes）→ Worker で prove
   → verify `true`。
   digest の 1 byte を改変した instance（`wrongDigest`）と、proof 末尾を
   1 byte 改変した proof がともに `false` になることを確認。
4. メインスレッドは circuit 1 の互換フィールド
   （`ok` / `worker` / `crossOriginIsolated` / `prepare` / `prove` / `verify` /
   `wrongInstance` / `tamperedProof` / `vk` / `proof` / `instances`）に加えて、
   `circuits.cubic` と `circuits.poseidon2` を `window.__halo2IpaResult` に
   公開する。各回路に VK/PK/proof/instances のサイズ、所要時間、wasm memory、
   Worker 実行フラグを含める。

`smoke.mjs` はブラウザ結果を受け取った後、同じ `pkg/halo2_ipa_prover_bg.wasm`
を Node の別 instance として初期化し、circuit 1 と circuit 2 の VK/proof/
instances を **ブラウザとは独立に** verify する。Node 側でも wrong digest と
tampered proof が `false`（malformed 入力は例外も拒否扱い）になることを確認する。

### 1.3 COOP/COEP と SharedArrayBuffer

smoke の HTTP サーバは `Cross-Origin-Opener-Policy` /
`Cross-Origin-Embedder-Policy` を返さない。したがって
`crossOriginIsolated === false`、`SharedArrayBuffer` は未定義である。prover は
single-thread の wasm として動作し、cross-origin isolation を要求しない。
smoke はこの 2 点を明示的に assert する。

### 1.4 実測（この環境）

測定環境: Linux x86_64、Node `v24.22.1`、Chromium `158.0.8127.18`、
`wasm-bindgen 0.2.129`、`wasm32-unknown-unknown` release。

| 項目 | circuit 1 (cubic) | circuit 2 (Poseidon2 hash3) |
|---|---:|---:|
| `prepare` (keygen) | 1,651.7 ms | 3,459.9 ms |
| `prove`（Worker 内） | 2,382.0 ms | 5,557.5 ms |
| `verify`（Worker 内） | 1,467.1 ms | 2,037.2 ms |
| VK | 126 bytes | 1,214 bytes |
| PK | 73,906 bytes | 632,322 bytes |
| proof | 1,164 bytes | 5,612 bytes |
| instances | 48 bytes | 144 bytes |
| prepare 後 wasm memory | 3,866,624 bytes | 8,126,464 bytes |
| prove 後 wasm memory | 8,126,464 bytes | 12,386,304 bytes |
| verify 後 wasm memory | 8,126,464 bytes | 12,386,304 bytes |
| Node 独立 verify | 2,883.0 ms | 1,783.1 ms |
| wrong instance / digest | `false` | `false` |
| tampered proof | `false` | `false` |
| witness zeroized | `true` | `true` |

- 配布する wasm（`pkg/halo2_ipa_prover_bg.wasm`）は **3,967,642 bytes**。
  cargo の生 wasm は 3,977,670 bytes。
- Node の verify 時間は初回の `ParamsIPA::new(8)`（決定的な params 生成）を
  含む。ブラウザ Worker の verify も同じ経路であり、params cache は使わない。
- 時間はホスト・Chromium・実行ごとのノイズを含む。暗号学的な性能保証ではない。
- 生データ: `/tmp/halo2-ipa-web-p2/halo2-ipa-web-measurements.json`
  （`node web/halo2-ipa-prover/smoke.mjs <artifact-dir>` が出力）。

---

## 2. ICP canister で circuit 2 を verify する

### 2.1 crate とビルド

`examples/halo2-ipa-poseidon2-ic-verifier` は既存の
`examples/halo2-ipa-ic-verifier` と同じ raw IC update アダプタで、pin する VK
だけが circuit 2 用である。

- package: `halo2-ipa-poseidon2-ic-verifier`
- lib / wasm: `halo2_ipa_poseidon2_ic_verifier.wasm`
- features: `halo2-ipa-verify-only,halo2-ipa-params-cache`
- dependency / `[patch.crates-io]` / getrandom の fail-closed stub は cubic
  canister と同一
- `const APPROVED_VK: &[u8] = include_bytes!(env!("HALO2_IPA_APPROVED_VK"));`

ビルド時に `tests/fixtures/halo2_ipa_poseidon2_v1.hex` の `VK` を抽出した
`poseidon2_vk.bin` を `HALO2_IPA_APPROVED_VK` で渡す。canister は VK ヘッダの
circuit id を decode するため、id 2 の proof だけを検証できる。任意の VK、
witness、params、prover、RNG を渡すエンドポイントは無い。

```bash
cd /application
HALO2_IPA_APPROVED_VK=/tmp/ic-branch85-p2/poseidon2_vk.bin \
  cargo build --locked --release \
    --features halo2-ipa-verify-only,halo2-ipa-params-cache \
    --manifest-path examples/halo2-ipa-poseidon2-ic-verifier/Cargo.toml \
    --target wasm32-unknown-unknown
```

### 2.2 リクエスト / リプライ

```text
arg   = v1 proof bytes || v1 instances bytes
reply = i32 status LE || u64 verifier instructions LE || u32 wasm memory pages LE
        (16 bytes)
```

- proof は `"RCH2IPF1" | proof_len u32 BE | transcript`。分割位置は
  `proof_len` から決め、`proof_len == 0`、`> 4 MiB`、切り詰め、末尾余剰は
  拒否する。
- circuit 2 の instances は
  `"RCH2IPI1" | 1 | 4 | digest | input0 | input1 | input2`。digest と 3 入力の
  一致、および digest が Poseidon2 sponge の出力であることを
  `halo2_ipa.rs` 側で確認する。
- `status == 0` のときだけ検証成功。改変 proof / 改変 instance は `8`
  （verification failed）、長さ不正は `9`、非 canonical `Fr` は `20`。
- 引数全体が `4 MiB + 1 MiB + 12 bytes` を超える場合は、バイト列を
  canister にコピーする前に `9` を返す。IC ingress の 2 MiB 上限より広い
  防御的多重化であり、mock `ic0` で `msg_arg_data_copy` が呼ばれないことを
  確認している。

### 2.3 実測（ローカル PocketIC）

> **artifact revision の注意**: 以下の実測は **P0 修正前の V1 Poseidon2
> artifact** による記録である。現行の Poseidon2 VK/PK は V2
> （`RCH2IPV2` / `RCH2IPP2`）で、committed fixture も V2 に再生成済み。
> canister の V2 VK 再 pin・再ビルド・PocketIC 再実行は未実施であり、
> 下記 instructions / cycles は V2 の値ではない。旧 V1 VK は現行実装が
> 拒否する。

測定環境: Node `v24.22.1`、`@dfinity/pic` 0.25.0、`opt-level = 3`、fat LTO、
`codegen-units = 1`、`strip = "symbols"`。fixture は k=8、proof 5,612 bytes、
instances 144 bytes、VK 1,214 bytes。

| 項目 | circuit 2 IPA verify (cold) | circuit 2 IPA verify (warm) |
|---|---:|---:|
| status | 0 | 0 |
| `performance_counter` 差分 (instructions) | 18,523,734,643 | 865,660,902 |
| wasm memory | 54 pages / 3,538,944 bytes | 54 pages / 3,538,944 bytes |
| PocketIC update cycles（参考） | 18,542,200,989 | — |
| wasm size | 2,810,841 bytes | 同左 |
| wasm functions（import + defined） | 5 + 451 = 456 | 同左 |
| wasm imports | `ic0` 5 関数のみ | 同左 |

- cold は canister instance での最初の検証。`ParamsIPA::new(8)` の決定的な
  params 生成（`hash_to_curve` による 256 点生成と Lagrange 変換）が支配的で、
  IPA の最終 MSM 自体は小さい。
- warm は `halo2-ipa-params-cache` による同一 instance 内の 2 回目。
  params を thread-local の単一スロットから clone するだけで、cold の約
  1/21 になる。ただし **heap のみのキャッシュ**であり、upgrade / reinstall
  で失われ、stable memory へ永続化しない。異なる `k` を交互に使うと cold に戻る。
- 1 回目と 2 回目の差は params 生成の有無による。`updateCyclesDebited` は
  cold 呼び出しの PocketIC update 全体（ingress + 実行）であり、mainnet の
  cycle quote でも検証器単体の tariff でもない。
- 改変 proof / 改変 instance はともに status `8`。5 MiB 超の引数は mock `ic0`
  で status `9` かつ `msg_arg_data_copy` 未呼び出し。
- wasm import は `msg_arg_data_size`、`msg_arg_data_copy`、
  `performance_counter`、`msg_reply_data_append`、`msg_reply` の `ic0` 5 関数
  のみ。`__wbindgen` / `getrandom` / Web Crypto の import は無い。
  `__getrandom_custom` は export されるが外部 import ではない。
- Poseidon2 VK の SHA-256:
  `c7569f8e59692d914d56f1a9e5f0aab5e786922c1cbfe8d0bc3c4a732854b4ce`。
  proof の SHA-256:
  `d6a2956b99163c59b098ad74eaddd3fb6316bbd69d9f212ec66bf9fac12df7c5`。
- 生データ: `/tmp/ic-branch85-p2/ic-measurements.json`
  （`bash ci/test_ic_branch85.sh /tmp/ic-branch85-p2` が出力）。

### 2.4 回帰確認

`ci/test_ic_branch85.sh` は同じ PocketIC instance で次をすべて実行する。

1. cubic IPA canister（pin は id 1 VK）: status 0、cold/warm 命令数・ページ数、
   proof/instance 改変の拒否、不正 envelope、5 MiB 超の事前拒否。
2. Poseidon2 IPA canister（pin は id 2 VK）: status 0、cold/warm 命令数・
   ページ数、proof/instance 改変の拒否、5 MiB 超の事前拒否。
3. Poseidon2 hash canister: `[1,2,3]` の KAT、長さ不正・非 canonical・
   13 入力の拒否。
4. 3 つの wasm の import がすべて `ic0` のみであること。

---

## 3. 明示的なギャップ

- **ICP canister は verify 専用**である。canister 内での proving / keygen は
  実装も試行もしていない。prove はブラウザ Worker（または native/WASI）で行う。
- **mainnet の cycles / instructions は未計測**。本ドキュメントの数値はローカル
  PocketIC のものであり、本番の cycle quote ではない。`dfx` による mainnet
  deploy、canister ID、controller 設定、Candid UI も未提供。
- ブラウザ検証は **headless Chromium** のみ。Firefox / Safari、実機
  スマートフォン、cross-origin isolation ありの構成は未検証。
- この browser / canister 経路が実行するのは **3 入力固定の circuit id 2**。
  C ABI/Nim には任意 arity `0..=12`（`0x100+n`）も登録済みだが、browser の
  page/worker とこの canister は id 2 のみを pin/実行する。任意 arity の
  browser / canister 展開は別途 VK の追加が必要。汎用回路記述子や Noir
  frontend も未実装。
- VK の pin はビルド時の `include_bytes!` であり、canister の upgrade なしに
  差し替えられない。VK・回路の承認は利用側のレビュー責務である。
- IPA params は `k` から決定的に再生成される透明なパラメータであり、
  trusted SRS ではない。warm cache は利便性のための heap キャッシュにすぎない。
- 本番資産用途の監査済み保証は範囲外。proof / VK / instances の長さ・
  canonical 性・部分群などは実装で検査するが、暗号学的な安全性の主張ではない。
- ブラウザの wasm は `getrandom` の `js` feature で CSPRNG を使う。Node の
  独立 verify は entropy を必要としない。ICP canister は getrandom の
  fail-closed stub を持ち、検証経路で entropy を呼ばない。
