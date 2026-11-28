# ADR 0085: Spartan+WHIR/BN254 の Phase 0 調査と blocked 判定

状態: **Blocked**（Phase 0 gate 未達。本ブランチで Spartan+WHIR の公開 API は出荷しない）

日付: 2026-11-27

関連: `docs/spartan-whir.md`、`docs/zkp-dependencies.md`、Branch 85 ルール
「Spartan+WHIR」「完了条件」、ADR 0070（Groth16 prover）

## Decision

本ブランチでは Spartan+WHIR の依存追加、Rust API、C ABI、Nim wrapper、WASM adapter を**行わない**。

- `rustcrypto-ffi` に Spartan+WHIR 用の crate / feature / module を追加しない。
- `SpartanWhirBn254` 等の marker type、`rustcrypto_spartan_whir_*` の C ABI、Nim の型付き API を作らない。
- 未実装の関数を `not_implemented` で公開することもしない。呼び出し可能な偽 API を置かない。
- 既存の KZG / Groth16 / PLONK / Plonky2 / Bulletproofs の API・wire format・VK は変更しない。
- Transparent profile は、本ブランチで実装中の Halo2 IPA/BN254 を第一候補として維持する。

**本ブランチに Spartan+WHIR の API は存在しない。** これは「実装したが無効化した」のではなく、Phase 0 の gate を満たす候補がなかったため、実装自体を行わないという判断である。

## Context

Branch 85 の目的は、Trusted Setup を要求せず、BN254 上で完全 ZK の prove/verify を行い、Native・Browser WASM・Nim/ICP で検証できる追加プロファイルを得ることである。完了条件には次が含まれる。

- transparent full-ZK prove/verify
- 公開入力 binding
- WASM 実行（`wasm32-unknown-unknown` / `wasm32-wasip1` / Browser / ICP）
- 128-bit 相当の security 設計
- VK pinning と DoS 上限
- 未解決事項を隠さず blocked と記録すること

候補として、`worldfnd/provekit`（BN254 / Spartan / WHIR）と `ethereum/spartan-whir`（KoalaBear / Spartan / WHIR / full-ZK / Spark）を調査した。調査は 2026-11-27 に GitHub API、raw source、`Cargo.toml` / `Cargo.lock`、crates.io API で行った。本リポジトリでの build / test / benchmark は行っていない。

## Options

### Option A: worldfnd/provekit を採用する

**判定: Blocked（不採用）**

- field は BN254（`ark-bn254` 0.6）で、Spartan + WHIR の実装がある。
- しかし `main` の `provekit/common/src/whir_r1cs.rs` は、hiding witness commitment と blinded sumcheck を実装しつつ、**「A hiding commitment alone is not full proof ZK — the alpha, public-input, and challenge evaluations are still sent in the clear.」**と明記している。完全 ZK ではない。
- native verifier は `transpose_r1cs_matrices` と `multiply_transposed_by_eq_alpha` を毎回実行し、R1CS の nnz / 制約数に比例するコストが残る。PCS 単体の漸近計算量では性能を保証できない。
- SPARK は `provekit/spark/SPARK.md` で "Proposed prototype workflow" とされ、native verify では使われない。SPARK の用途は recursive verifier（Groth16 wrapper）であり、Trusted Setup を再導入する。
- `rust-toolchain.toml` は nightly-2026-03-04。`skyscraper` / `ntt` が nightly feature を使い、`backend/bn254` がそれらに依存する。既存 workspace の stable 前提と一致しない。
- `ark-bn254` 0.6 は既存の 0.5 と二重依存になる。型の相互運用には変換層が必要。
- `provekit-backend-bn254` / `provekit-spark` / `provekit-wasm` は crates.io 未公開。`main` の proof / key format は変更され得ると README が明記している。
- `provekit-wasm` は atomics / `--shared-memory` / SharedArrayBuffer / wasm-bindgen-rayon を前提とし、ICP canister にそのまま持ち込めない。`provekit-verifier` は `rayon` を無条件依存に持つ。
- `Verify::verify(proof)` は proof 内の `public_inputs` を使い、期待公開入力を引数に取らない。`expectedPublicInputs` の契約を満たすにはラッパーが必要。
- 監査報告はリポジトリ内に確認できない。ライセンスは MIT だが、v1 README の「MIT / Apache 2.0」表記と `License.md` の MIT 本文が一致しない。

### Option B: ethereum/spartan-whir を採用する

**判定: Blocked（不採用）**

- full-ZK の DirectSparse / Spark が実装されており、公開入力 binding と relation digest 認証も設計されている。
- しかし field は KoalaBear（31-bit）で、BN254 ではない。BN254 の statement は非 native エミュレーションになり、drop-in ではない。
- `src/security.rs` は `DEFAULT_SECURITY_BITS = 100`、`MAX_SECURITY_BITS = 123`。128-bit を設定できない。コードに 128 への TODO があるが、現 revision では未達。
- LICENSE file がなく、`Cargo.toml` に license field がなく、GitHub API の license も null。法的に再利用・改変・配布の許諾がない。
- `src` / `Cargo.toml` / README に wasm 対応の記述がなく、target 設定、CI、fixture もない（`Cargo.lock` の `wasm-bindgen` は transitive）。native の `libloading` witness 生成に依存する。
- GitHub tag / release が 0 件、crates.io にも存在しない。安定版の配布物がない。
- 監査報告 / SECURITY.md を確認できない。

### Option C: WHIR 単体を Verifier にする

**判定: 不採用**

WHIR は PCS であり、R1CS の充足性・公開入力 binding を単体で検証する SNARK ではない。Branch 85 のルールも「WHIR 単体を Verifier にしない」と明記している。

### Option D: microsoft/Spartan を採用する

**判定: 不採用**

field は Curve25519 scalar で BN254 ではない。PCS は Spartan 独自で WHIR ではない。MIT license だが、本ブランチの BN254 + WHIR 要件を満たさない。

### Option E: 独自 port / fork を実装する

**判定: 不採用（Phase 0 では禁止）**

BN254 対応、完全 ZK、128-bit、WASM、codec 固定、監査を同時に満たす独自 port は、暗号設計・実装・レビューの範囲が Phase 0 を大きく超える。独立レビューなしの DIY 暗号は禁止する。将来の PoC でも、上流の承認済み実装を pin することを原則とし、独自暗号を新規に設計しない。

## Consequences

- 本ブランチの Spartan+WHIR 部分は **未実装 / blocked** として完了条件に記録される。透明プロファイルの実装は Halo2 IPA/BN254 が担う。
- `docs/spartan-whir.md` に候補比較、blocked 理由、次アクション、未確認事項を記録した。
- `docs/zkp-dependencies.md` に、Spartan+WHIR 候補を**追加していない**こと、および各候補の revision / license を記録した。
- 利用側は `SpartanWhirBn254` のような API を期待してはならない。既存の KZG/Groth16 と Halo2 IPA（実装中）を混同しない。
- Spartan+WHIR の性能・proof size・WASM 実行時間は本ブランチでは測定していない。未確認の数値を公式値として引用しない。
- 将来、上流が gate を満たした場合は、別 ADR を起票してから依存追加・実装を行う。本 ADR を自動的に「採用」へ書き換えない。

## Evidence

### 取得日と方法

- 取得日: 2026-11-27（UTC）
- 方法: GitHub API、`raw.githubusercontent.com`、`git ls-remote`、crates.io API
- 本リポジトリでの build / test / benchmark: **未実施**

### worldfnd/provekit

| 項目 | 値 |
|---|---|
| `main` HEAD | `893f6d5866d52124e12c4a90a71c0f4d625f083b`（2026-11-12） |
| `v1.0.3` tag | `00cbd7daba13e6ee1ee05d0b4a096a9ea0427ac4`（release 2026-10-27） |
| `v1.0.2` tag | `4ee40639fb8849aeeba37761fdda07f28367e81d` |
| license | MIT（`LICENSE.md`）。v1 README は MIT / Apache 2.0 と表示するが、`License.md` は MIT 本文のみ |
| edition / rust-version | edition 2021 / `rust-version = 1.85` |
| toolchain | nightly-2026-03-04（`rust-toolchain.toml`） |
| BN254 backend | `ark-bn254` 0.6.0 |
| WHIR | `worldfnd/whir` rev `d2b16529d0a4fad4f53d088281e9062898d35f5b`（Apache-2.0） |
| Noir | git tag `v1.0.0-beta.26`（Apache-2.0） |
| Mavros | git rev `c445d5dcfe70230b26faa19f7d62d7fa254b1bec`（Apache-2.0） |
| spongefish fork | `provekit-spongefish` 0.2.0（BSD-3-Clause） |
| crates.io | `provekit-common` / `provekit-prover` / `provekit-verifier` / `provekit-r1cs-compiler` は 1.0.3。`provekit-backend-bn254` / `provekit-spark` / `provekit-wasm` は未公開 |
| 監査 | リポジトリ内に報告書を確認できず（未確認） |

完全 ZK に関する上流の記述（`provekit/common/src/whir_r1cs.rs` 146–149 行付近）:

```text
/// - Sumcheck ZK is always on: the Spartan sumcheck rounds are masked by a
///   blinding polynomial `g`, committed separately in `whir_blinding`.
/// - Witness ZK follows the [`WitnessCommitmentMode`] the scheme was built
///   with, recorded in `whir_witness`: [`Mode::ZeroKnowledge`] (the default) is
///   hiding, [`Mode::Standard`] non-hiding. A hiding commitment alone is not
///   full proof ZK — the alpha, public-input, and challenge evaluations are
///   still sent in the clear.
```

検証コストに関する根拠:

- `provekit/verifier/src/whir_r1cs.rs` 119 行: `|| transpose_r1cs_matrices(r1cs),`
- 同 137 行: `let alphas = multiply_transposed_by_eq_alpha(...)`
- `provekit/common/src/utils/sumcheck.rs` 264–299 行: 転置と `eq_alpha` の計算・乗算

SPARK に関する根拠:

- `provekit/spark/SPARK.md` 7 行: `## Proposed prototype workflow`
- 同 102 行: `# 4. Natively verify the Noir proof. Native verification evaluates MLE directly. Spark proofs are useful only in the recursive verifier.`
- 同 122 行: `# TODO: 6. Recursively verify the Noir proof and SPARK.`

WASM に関する根拠:

- `tooling/provekit-wasm/Cargo.toml` 1–7 行: `-Z build-std=panic_abort,std`、`SharedArrayBuffer`、COOP/COEP の要求
- `.cargo/config.toml`: `wasm32-unknown-unknown` に `+atomics`、`--shared-memory`、`+simd128`、`+relaxed-simd`
- `provekit/verifier/Cargo.toml`: `rayon` を無条件依存

公開入力に関する根拠:

- `provekit/backend/bn254/src/verify.rs`: `Verify::verify(&mut self, proof: &ProvekitProof<Bn254Field>)` が `proof.public_inputs` を `verify_with_session` に渡す。期待公開入力は引数にない。
- ProveKit docs は、verifier が proof 同梱のコピーではなく信頼できる境界から期待値を得る必要があると注意している。

### ethereum/spartan-whir

| 項目 | 値 |
|---|---|
| `main` HEAD | `14d6da4211eda59e65cfd0af5e2dcd89d523edc3`（2026-10-22） |
| field | KoalaBear（31-bit）+ quartic/quintic extension。BN254 なし |
| PCS | Plonky3 WHIR（`Client-Side-Proving/Plonky3` rev `458ef546a251ab4d9d73c453d24a414334786ca0`） |
| full-ZK | DirectSparse / Spark ともに実装済み（README の対応表） |
| 参考文献 | eprint 2026/391（full-ZK constrained interleaved codes） |
| security | `DEFAULT_SECURITY_BITS = 100`、`MAX_SECURITY_BITS = 123`、128 への TODO |
| 証明サイズ | 1,838,906 bytes（compact、約 64k constraints、116-bit、Poseidon1 + Spark、2026-09-08。protocol-id 修正前） |
| verify 時間 | 55.938 ms（one-thread native、同上） |
| WASM | `src` / `Cargo.toml` / README に wasm 記述なし。target 設定 / CI / fixture なし（`Cargo.lock` の `wasm-bindgen` は transitive） |
| license | **なし**（LICENSE file なし、`Cargo.toml` license なし、GitHub API license null） |
| 配布 | GitHub tag / release 0、crates.io 未公開 |
| 監査 | SECURITY.md / 監査報告なし（未確認） |

`src/security.rs` の該当箇所:

```rust
pub const DEFAULT_SECURITY_BITS: u32 = 100;
/// Maximum target supported by the current eight-element KoalaBear Poseidon digest.
///
/// TODO: Raise this to 128 after widening the Poseidon Merkle digest and its
/// compression construction to provide at least 128 bits of collision security.
pub const MAX_SECURITY_BITS: u32 = 123;
```

公開入力 binding の根拠:

- README 122–125 行: `vk.authenticate()?; vk.verify(&expected_public_inputs, &proof)?;`
- README 140–144 行: domain separator が R1CS 行列の正規化 digest と公開入力を最初の challenge より前に吸収する。

proof codec の根拠:

- README 114–118 行: `SPC2` compact encoding、bincode fixed-int、trailing bytes 拒否、role 別 decode 上限。

### その他

| 候補 | revision | license | 判定 |
|---|---|---|---|
| WHIR 単体 | `worldfnd/whir` rev `d2b16529d0a4fad4f53d088281e9062898d35f5b` | Apache-2.0 | PCS のみ。Verifier 単体不可 |
| microsoft/Spartan | `d62b961f9497e3c07a921b6da1457cad467598d9`（2026-09-22、0.9.0） | MIT | Curve25519。BN254 / WHIR なし |
| Zcash halo2 IPA / Pasta | 未調査（本 ADR の対象外） | — | BN254 Fr 回路をそのまま扱えない。既存 Halo2 IPA プロファイルと競合 |

### 参照 URL

- ProveKit: https://github.com/worldfnd/provekit
  - `provekit/common/src/whir_r1cs.rs`: https://github.com/worldfnd/provekit/blob/main/provekit/common/src/whir_r1cs.rs
  - `provekit/verifier/src/whir_r1cs.rs`: https://github.com/worldfnd/provekit/blob/main/provekit/verifier/src/whir_r1cs.rs
  - `provekit/spark/SPARK.md`: https://github.com/worldfnd/provekit/blob/main/provekit/spark/SPARK.md
  - `provekit/backend/bn254/src/verify.rs`: https://github.com/worldfnd/provekit/blob/main/provekit/backend/bn254/src/verify.rs
  - `tooling/provekit-wasm/Cargo.toml`: https://github.com/worldfnd/provekit/blob/main/tooling/provekit-wasm/Cargo.toml
  - `.cargo/config.toml`: https://github.com/worldfnd/provekit/blob/main/.cargo/config.toml
  - `LICENSE.md`: https://github.com/worldfnd/provekit/blob/main/LICENSE.md
- ethereum/spartan-whir: https://github.com/ethereum/spartan-whir
  - `README.md`: https://github.com/ethereum/spartan-whir/blob/main/README.md
  - `src/security.rs`: https://github.com/ethereum/spartan-whir/blob/main/src/security.rs
  - `Cargo.toml`: https://github.com/ethereum/spartan-whir/blob/main/Cargo.toml
- Microsoft Spartan: https://github.com/microsoft/Spartan
- WHIR fork: https://github.com/worldfnd/whir
- Plonky3 fork: https://github.com/Client-Side-Proving/Plonky3
- Full-ZK 参考文献: https://eprint.iacr.org/2026/391
- R1CS relation binding の参考文献: https://eprint.iacr.org/2026/1838

## Follow-ups

Spartan+WHIR を将来採用する場合は、次のすべてを満たした別 ADR / PoC ブランチを起票する。1 つでも欠けたら blocked を維持する。

1. **完全 ZK**: witness commitment の hiding だけでなく、alpha / 公開入力 / challenge 評価が proof に平文で漏れないことを、上流の設計文書とコードで確認する。ProveKit の "not full proof ZK" 注記が解消されていること。
2. **BN254 end-to-end**: field エミュレーションではなく、BN254 Fr/G1 を native に扱う。既存 BN254 Fr との型変換、canonical 32-byte BE、回路 / R1CS の変換経路を固定する。
3. **128-bit security**: ZK の漏洩を含む総合 security を 128-bit 相当で設計し、上流の仮定と不足分を定量化する。123-bit 上限のような設計は受け入れない。
4. **WASM / ICP**: `wasm32-unknown-unknown`（atomics なし、single-thread）と `wasm32-wasip1` の build + verify を実行する。Browser Web Worker と PocketIC の正負 fixture を用意する。ビルド成功を実行成功とみなさない。
5. **依存分離**: verifier-only の crate / feature を構成し、Noir compiler / nargo / Mavros / prover / rayon が canister artifact に入らないことを確認する。`ark` の二重依存を許容する場合は、型変換と wasm size への影響を測る。
6. **toolchain**: 既存 workspace の stable toolchain で build できるか、nightly を隔離できるかを確認する。nightly 必須のままなら、既存 CI / release への影響を明記する。
7. **codec 固定**: proof / VK / PK に magic、version、canonical encoding、trailing bytes 拒否、長さ上限を定義し、外部仕様として固定する。上流 `main` の不安定な format をそのまま公開しない。
8. **公開入力 binding**: `verify(vk, proof, expected_public_inputs)` の形で期待値を必須にし、proof 内のコピーだけを信じない。順序・個数・型を VK / circuit digest に bind する。
9. **VK pinning**: 承認済み VK / VK hash / relation digest を pin する API を提供する。untrusted input から任意の VK を受け取らない。
10. **DoS 上限**: decode / allocate 前に proof / VK / PK / R1CS の最大サイズ、最大制約数、最大 nnz、最大 k を検査する。検証失敗で状態を変更しない。
11. **fixture / ベンチ**: 小規模 ~1k と ~20k R1CS の同等 statement で、正負 fixture、proof / VK / PK size、prove / verify wall time、peak RSS、WASM pages、ICP instructions / cycles を測る。R1CS 転置・`eq_alpha` 乗算を含む verify コストを PCS 単体と分けて報告する。
12. **監査 / 独立レビュー**: 暗号設計、Fiat–Shamir、ZK 漏洩、serialization、WASM 実行、依存 provenance を独立レビューする。DIY 暗号はレビュー完了まで本番経路に入れない。

### 再評価のトリガー

- ProveKit が BN254 で完全 ZK の profile を stable release として出し、proof / key format を固定したとき。
- ProveKit が verifier-only の wasm32-wasip1 / no-atomics 対応を出し、`expected_public_inputs` を API で必須にしたとき。
- spartan-whir が BN254 対応、128-bit security、license 明確化、WASM 対応、安定版配布のいずれかを達成したとき。
- 上流に独立監査報告が出たとき。

### 本ブランチでの完了状態

- [x] Phase 0 調査（ProveKit / spartan-whir / WHIR 単体 / Microsoft Spartan）
- [x] blocked 理由と evidence の記録（本 ADR と `docs/spartan-whir.md`）
- [x] 依存/license 表の更新（`docs/zkp-dependencies.md`）
- [x] Spartan+WHIR の依存・API・C ABI・Nim wrapper を追加しないことの明記
- [ ] 将来の PoC ブランチ（本ブランチの範囲外）
