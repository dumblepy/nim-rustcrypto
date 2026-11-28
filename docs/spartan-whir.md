# Spartan+WHIR / BN254 の Phase 0 調査（Branch 85）

- 調査日: 2026-11-27（UTC）
- 対象ブランチ: `85-設計実装-halo2-ipa-spartanwhirtrusted-setup不要とposeidon2-bn254をnimrust-ffiwasmに追加`
- 結論: **本ブランチでは Spartan+WHIR を採用しない（blocked）**。Spartan+WHIR の Rust API、C ABI、Nim wrapper、WASM adapter は追加しない。既存の KZG / Groth16 は変更しない。
- 本ドキュメントは Phase 0 の調査・判定資料であり、暗号実装の設計書ではない。ここに書かれた性能値・セキュリティ値は、断らない限り上流の公開情報または上流コードの定数であり、本リポジトリでの実測値ではない。

## 1. 目的

Trusted Setup（秘密の trapdoor / SRS ceremony）を要求せず、BN254 上で完全 ZK の prove/verify を行い、Native・Browser WASM・Nim からリンクした ICP 向け WASM で検証できる追加プロファイルの実現性を判断する。

達成したい条件は次のとおり。

- BN254 上で動くこと（既存の BN254 Fr / G1 と相互運用できること）
- 完全 ZK であること（witness だけでなく、proof から追加情報が漏れないこと）
- Trusted Setup を要求しないこと
- 128-bit 相当の security 設計値を持つこと
- 公開入力を Verifier が独立に受け取り、proof 内のコピーだけを信じないこと
- VK（検証鍵）を利用側が pin できること
- decode / allocate 前の上限検査を含む DoS 耐性があること
- `wasm32-unknown-unknown`（atomics なし）と `wasm32-wasip1` の双方で build / verify できること
- 監査または独立レビューの見通しがあること
- proof / VK / PK の wire format が固定され、version と magic を持つこと

## 2. 対象外

- 既存の Groth16 / KZG / PLONK / Plonky2 / Bulletproofs の置き換えや仕様変更
- 特定アプリケーションの回路、台帳、資産仕様、Note/Merkle 仕様
- 本番資産用途に対する監査済み保証
- Spartan+WHIR の独自実装、独自暗号パラメータ生成、独自 Fiat–Shamir の設計
- SPARK を省略した非完全 ZK モードの採用
- Groth16 wrapper など Trusted Setup に依存する圧縮経路の採用

## 3. 用語と前提

### 3.1 "SPARK" は同じ名前で別物

今回の調査では、`SPARK` が 2 つの異なる文脈で使われている。混同すると判定を誤るため、本ドキュメントでは次のように区別する。

| 文脈 | SPARK の意味 | ZK との関係 |
|---|---|---|
| ProveKit | R1CS 行列の評価を recursive verifier 側で圧縮するための sparse matrix evaluation（SPARK） | ZK 方式ではない。native verify では使われず、Groth16 recursive verifier 向けの prototype |
| ethereum/spartan-whir | ZK 行列 closing（`Spark` matrix closing） | full-ZK の構成要素。DirectSparse と Spark の両方が full-ZK で実装されている |

Branch 85 のルールにある「ProveKit は SPARK を省略する設計で、R1CS 評価等の検証負荷が残る」という記述は、**ProveKit の native verifier について現 revision でも妥当**である。ProveKit の `main` には SPARK の prototype crate が存在するが、SPARK.md 自身が "Proposed prototype workflow" と書いており、native verification は MLE を直接評価する。SPARK を使う経路は recursive verifier（Groth16 wrapper）であり、これは Trusted Setup を再導入するため本ブランチの制約に反する。

### 3.2 「完全 ZK」の判定基準

本ドキュメントでは、次のすべてを満たすものを「完全 ZK」と扱う。

- witness の多項式コミットメントが hiding である
- sumcheck の各 round が blinding されている
- Fiat–Shamir の challenge に依存する評価値（alpha 評価、公開入力評価、challenge 評価など）が proof に平文で漏れない
- 上記を上流の設計文書またはコードで確認できる

「witness commitment が hiding である」だけでは完全 ZK とみなさない。ProveKit 自身のコードコメントも、この意味で完全 ZK ではないと明記している（後述）。

## 4. 調査方法

- GitHub API / raw.githubusercontent.com / `git ls-remote` で、2026-11-27 時点の `main`、tag、`Cargo.toml`、`Cargo.lock`、`LICENSE`、README、主要 source を取得した。
- crates.io API で公開 crate の有無、license、`rust_version` を確認した。
- **本リポジトリでの build / test / benchmark は行っていない。** したがって、ビルド可否・実行時間・メモリ・WASM 実行の記述は、上流の主張または未確認事項として扱う。
- ネットワークで取得できなかった項目は「未確認」と明記した。

## 5. 候補比較

| 候補 | field | PCS | ZK 方式（SPARK 有無） | 証明サイズ | prover / verifier | WASM | license | revision / MSRV | 監査 | BN254 drop-in | 判定 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [worldfnd/provekit](https://github.com/worldfnd/provekit) `main` | BN254 Fr（`ark-bn254` 0.6） | WHIR（`worldfnd/whir` fork） | hiding witness commitment + blinded sumcheck。**完全 ZK ではない**とコードが明記。SPARK は recursive verifier 向け prototype | 公式の固定値は未確認 | `provekit-prover` / `provekit-verifier` + `provekit-backend-bn254`。Noir / Mavros frontend | `provekit-wasm` あり（browser/Node、atomics + SharedArrayBuffer + wasm-bindgen-rayon）。wasip1 / ICP は未検証 | MIT（`LICENSE.md`）。依存に Apache-2.0 / BSD-3-Clause を含む | `893f6d5866d52124e12c4a90a71c0f4d625f083b`（2026-11-12）。nightly-2026-03-04、workspace `rust-version = 1.85`、edition 2021 | リポジトリ内に監査報告を確認できず（未確認） | field は一致するが、frontend / R1CS / codec は非互換。`ark` 0.5 と 0.6 の二重依存 | **Blocked** |
| [ethereum/spartan-whir](https://github.com/ethereum/spartan-whir) `main` | KoalaBear（31-bit）+ quartic/quintic extension。BN254 なし | Plonky3 WHIR（fork `458ef546...`） | full-ZK DirectSparse / Spark 実装済み。no-ZK もあり（採用不可） | 1,838,906 bytes（compact、約 64k constraints、116-bit、Poseidon1 + Spark、2026-09-08 の値。protocol-id 修正前） | library + KoalaBear Circom frontend。witness は native library を `libloading` | **wasm 対応の証拠なし**（src / `Cargo.toml` / README に wasm 記述なし。target 設定 / CI / fixture なし。`Cargo.lock` の `wasm-bindgen` は transitive） | **license なし**（LICENSE file なし、`Cargo.toml` に license なし、GitHub API も null） | `14d6da4211eda59e65cfd0af5e2dcd89d523edc3`（2026-10-22）。edition 2021、`rust-version` なし、`rand` 0.10.2 | SECURITY / 監査報告なし（未確認） | 不可（BN254 への field 変更または非 native エミュレーションが必要。未測定） | **Blocked** |
| WHIR 単体（`whir` / `p3-whir`） | PCS の設定依存 | WHIR | PCS のみ。R1CS も公開入力 binding もない。SPARK なし | PCS 設定依存 | PCS のみ | 未確認 | Apache-2.0（`worldfnd/whir` fork） | ProveKit が `d2b16529d0a4fad4f53d088281e9062898d35f5b` を pin | 未確認 | N/A | **不採用**（Verifier 単体にできない） |
| [microsoft/Spartan](https://github.com/microsoft/Spartan) | Curve25519 scalar（BN254 ではない） | Spartan 独自（WHIR なし） | zkSNARK。SPARK なし | 未確認 | `spartan` crate | `wasm32` 向け `getrandom/js` 依存はあるが未検証 | MIT | `d62b961f9497e3c07a921b6da1457cad467598d9`（2026-09-22）、0.9.0、edition 2021 | 未確認 | 不可 | **不採用** |

### 5.1 比較表の注記

- **ProveKit の証明サイズ**: ProveKit の Performance ドキュメント（v1.0.2 を対象）は「headline number を出さない」と明記しており、回路形状・ホスト依存が大きい。本調査では対象回路（既存 BN254 R1CS 相当）の公式固定値を確認できなかった。PoC 時は必ず自前で測る必要がある。
- **ProveKit の security**: WHIR の protocol parameters は 128-bit（Johnson bound、rate 2、folding factor 3、10-bit PoW）を指定している。ただし、これは PCS / sumcheck の設計値であり、完全 ZK の漏洩を含む総合評価ではない。監査報告も未確認。
- **spartan-whir の security**: `src/security.rs` は `DEFAULT_SECURITY_BITS = 100`、`MAX_SECURITY_BITS = 123` で、128-bit を設定できない。コードには「Poseidon Merkle digest を広げた後で 128 に上げる」という TODO がある。116-bit は benchmark の選択値であり、128-bit ではない。
- **spartan-whir の証明サイズ**: 上記 1.84 MB は約 64k constraints の withdraw 回路、116-bit、Poseidon1、Spark の compact proof。小さい回路ではより小さくなる可能性があるが、本調査では他のサイズを確認していない。ICP の ingress / instruction 上限との適合は未検証。
- **WASM**: ProveKit の browser WASM は「実装がある」だけで、本リポジトリでのビルド・実行は未検証。spartan-whir は wasm 対応の証拠がない。

## 6. 候補ごとの評価

### 6.1 worldfnd/provekit

#### 6.1.1 構成

ProveKit は Noir プログラムを ACIR 経由で R1CS に落とし、Spartan 系の sumcheck と WHIR の PCS で proof を作る。`main` の workspace は 23 member で、`provekit/backend/bn254`、`provekit/prover`、`provekit/verifier`、`provekit/spark`、`tooling/provekit-wasm` などを含む。field は BN254 が主で、workspace には `provekit/backend/goldilocks` もあるが、本調査の対象は BN254 プロファイルである。

主要な依存 revision（`Cargo.toml`）:

| 依存 | revision / version | license |
|---|---|---|
| `ark-bn254` | 0.6.0 | MIT OR Apache-2.0 |
| `whir` | git `https://github.com/worldfnd/whir.git` rev `d2b16529d0a4fad4f53d088281e9062898d35f5b` | Apache-2.0 |
| Noir (`acir`, `bn254_blackbox_solver`, `nargo` など) | git tag `v1.0.0-beta.26` | Apache-2.0 |
| `mavros-vm` / `mavros-artifacts` | git rev `c445d5dcfe70230b26faa19f7d62d7fa254b1bec` | Apache-2.0 |
| `provekit-spongefish` | 0.2.0（worldfnd fork） | BSD-3-Clause |

toolchain は `rust-toolchain.toml` で `nightly-2026-03-04` に固定されている。`skyscraper/core`、`skyscraper/bn254-multiplier`、`ntt` は `#![feature(portable_simd)]` や `#![feature(vec_split_at_spare)]` を使っており、`backend/bn254` はこれらの workspace crate に依存する。したがって **BN254 backend のビルドには nightly が必要**で、既存リポジトリの stable 前提（`rustc 1.99.1`）とはツールチェーンが一致しない。

#### 6.1.2 完全 ZK ではない根拠

`provekit/common/src/whir_r1cs.rs` の doc comment は、witness commitment の hiding と sumcheck の blinding を説明した直後に、次のように明記している。

```text
/// - Sumcheck ZK is always on: the Spartan sumcheck rounds are masked by a
///   blinding polynomial `g`, committed separately in `whir_blinding`.
/// - Witness ZK follows the [`WitnessCommitmentMode`] the scheme was built
///   with, recorded in `whir_witness`: [`Mode::ZeroKnowledge`] (the default) is
///   hiding, [`Mode::Standard`] non-hiding. A hiding commitment alone is not
///   full proof ZK — the alpha, public-input, and challenge evaluations are
///   still sent in the clear.
```

（`provekit/common/src/whir_r1cs.rs` 146–149 行付近。強調は引用者。）

つまり `main` の既定 `--witness-mode zk` は「witness commitment が hiding」であるが、**alpha 評価・公開入力評価・challenge 評価が proof に平文で残る**。Branch 85 が要求する「完全 ZK」を満たさない。SPARK の有無はこの ZK 性の問題を解決しない。

また、stable とされる `v1.0.3` tag（`00cbd7daba13e6ee1ee05d0b4a096a9ea0427ac4`、release 2026-10-27）を確認すると、`provekit/common/src/whir_r1cs.rs` は 1,870 bytes で、`WitnessCommitmentMode` / hiding / SPARK の実装が見当たらない。`provekit/backend/bn254` も存在しない。**完全 ZK に近いコードは `main` の不安定な開発線にしかなく、stable tag には載っていない。**

#### 6.1.3 検証コストは R1CS のサイズに依存する

`provekit/verifier/src/whir_r1cs.rs` の検証処理は、sumcheck 検証と並行して `transpose_r1cs_matrices(r1cs)` を実行し、その後 `multiply_transposed_by_eq_alpha(...)` で A/B/C の転置行列と `eq(alpha, ·)` を掛ける。

- `provekit/verifier/src/whir_r1cs.rs` 119 行: `|| transpose_r1cs_matrices(r1cs),`
- 同 137 行: `let alphas = multiply_transposed_by_eq_alpha(...)`
- `provekit/common/src/utils/sumcheck.rs` 264–299 行: 転置と `eq_alpha` の計算・乗算

この処理は R1CS の非ゼロ要素数（nnz）と制約数に比例する。したがって「WHIR の PCS 単体の漸近計算量が小さい」ことは、Verifier 全体のコストが小さいことを意味しない。Branch 85 のルールが警告している「R1CS 評価等の検証負荷が残る」は、この実装について具体的事実である。

SPARK を使えばこの評価を recursive verifier 側へ移せるが、SPARK.md は次のように書いている。

- 7 行: `## Proposed prototype workflow`
- 102 行: `# 4. Natively verify the Noir proof. Native verification evaluates MLE directly. Spark proofs are useful only in the recursive verifier.`
- 122 行: `# TODO: 6. Recursively verify the Noir proof and SPARK.`

つまり SPARK は native verify のコストを下げるものではなく、Groth16 recursive verifier 用の prototype である。Groth16 wrapper は Trusted Setup を要求するため、本ブランチの「Trusted Setup 不要」に反する。

#### 6.1.4 公開入力 binding

`provekit/backend/bn254/src/verify.rs` の `Verify::verify(&mut self, proof: &ProvekitProof<Bn254Field>)` は、proof に埋め込まれた `proof.public_inputs` をそのまま `verify_with_session` に渡す。期待値との一致は呼出側の責務であり、API は `expected_public_inputs` を引数に取らない。

ProveKit の README / docs も「verifier は proof に同梱されたコピーではなく、信頼できるアプリケーション境界から期待値を得る必要がある」と注意している。Branch 85 の `verify(verifyingArtifact, proof, expectedPublicInputs)` 契約を満たすには、この比較を強制するラッパーが必要になる。**そのままでは「公開入力 binding を API で保証する」設計になっていない。**

#### 6.1.5 WASM / ICP

`tooling/provekit-wasm/Cargo.toml` の先頭コメントは、WASM build に `-Z build-std=panic_abort,std` を要求し、browser が `Cross-Origin-Opener-Policy: same-origin` と `Cross-Origin-Embedder-Policy: require-corp` を返す必要があると書いている。`.cargo/config.toml` の `wasm32-unknown-unknown` は `+atomics,+bulk-memory,+mutable-globals,+simd128,+relaxed-simd` と `--shared-memory` を有効にする。`wasm32-wasip1` も `+simd128,+relaxed-simd` を要求する。

- Browser / Node の `provekit-wasm` は「実装がある」が、本リポジトリでのビルド・実行は未検証。
- ICP canister は JS も SharedArrayBuffer も前提にできず、atomics なしの single-thread wasm が基本である。ProveKit の wasm 構成をそのまま canister に持ち込むことはできない。
- `provekit-verifier` は `rayon` を無条件依存に持つ（`provekit/verifier/Cargo.toml`）。no-atomics wasm での単一スレッド build が可能かは未確認。
- `provekit-wasm`、`provekit-backend-bn254`、`provekit-spark` は crates.io に公開されていない（2026-11-27 時点）。公開されているのは `provekit-common` / `provekit-prover` / `provekit-verifier` / `provekit-r1cs-compiler` の 1.0.3 系で、これは v1 系の古い構成であり、BN254 backend や hiding/SPARK を含まない。

#### 6.1.6 依存とライセンス

ProveKit 本体は MIT（`LICENSE.md`）。ただし v1 の README は「MIT / Apache 2.0」と表示しており、実際の `License.md` は MIT 本文のみである。**ライセンス表記の不一致**があるため、採用時は上流に確認が必要。

依存には Apache-2.0（WHIR fork、Noir、Mavros）と BSD-3-Clause（spongefish fork）が含まれる。いずれも permissive だが、Apache-2.0 の NOTICE 保持と BSD-3-Clause の attribution を release に含める必要がある。

#### 6.1.7 ProveKit のまとめ

- BN254 上で Spartan + WHIR を実装している点は前進。
- しかし **完全 ZK ではない**（上流コードが明記）。
- native verify は R1CS の転置・評価を行うため、検証コストが回路サイズに比例する。
- SPARK は recursive verifier 用 prototype で、native verify のコストを下げない。Groth16 wrapper は Trusted Setup を要求する。
- nightly 必須、`ark` 0.6 の二重依存、git 依存、未公開 backend、WASM の atomics/JS 前提、codec の不安定さ、監査未確認。
- **総合判定: Blocked。**

### 6.2 ethereum/spartan-whir

#### 6.2.1 構成と強み

`spartan-whir` は KoalaBear field 上の Spartan R1CS IOP と Plonky3 WHIR PCS を組み合わせた SNARK である。README の対応表では、no-ZK / full-ZK と DirectSparse / Spark の 4 通りすべてが「Implemented」とされている。full-ZK は "Zero-Knowledge IOPPs for Constrained Interleaved Codes"（eprint 2026/391）に基づく。

- field: KoalaBear（31-bit）+ quartic/quintic extension。BN254 は使っていない。
- PCS: Plonky3 WHIR（`Client-Side-Proving/Plonky3` fork、rev `458ef546a251ab4d9d73c453d24a414334786ca0`）。
- frontend: KoalaBear Circom fork。witness 生成は native C++ / `libloading`。
- full-ZK: DirectSparse と Spark の両方が実装済み。no-ZK mode もあるが、本ブランチでは採用不可。
- 公開入力 binding: `vk.verify(&expected_public_inputs, &proof)` の形で期待値を渡す。domain separator は R1CS 行列の正規化 digest を最初の Fiat–Shamir challenge より前に吸収する（README 140–144 行）。
- proof codec: `SPC2` compact encoding、bincode fixed-int、trailing bytes 拒否、role 別の decode 上限（README 114–118 行）。

設計面では、Branch 85 が求める「公開入力 binding」「VK の relation digest 認証」「proof codec の厳格さ」に比較的近い。

#### 6.2.2 Blocked 理由

1. **BN254 ではない。** KoalaBear 31-bit field であり、BN254 Fr/G1 をそのまま扱えない。BN254 の statement を証明するには、BN254 演算を KoalaBear 回路内で非 native エミュレーションする必要がある。254-bit の乗算・mod reduction・範囲検査を 31-bit limb で表現することになり、回路規模・証明時間・proof size が数桁増えると推定される（本調査では未測定）。「BN254 drop-in」ではない。
2. **128-bit を設定できない。** `src/security.rs`:
   - `DEFAULT_SECURITY_BITS = 100`
   - `MAX_SECURITY_BITS = 123`
   - `TODO: Raise this to 128 after widening the Poseidon Merkle digest ...`
   128-bit を設計値にできないため、Branch 85 の「security を下げて性能目標を達成しない」に反する。116-bit の benchmark は 128-bit ではない。
3. **license がない。** リポジトリに `LICENSE` / `COPYING` がなく、`Cargo.toml` に `license` field がなく、GitHub API の license も `null`。法的に再利用・改変・配布の許諾がないため、vendoring も依存追加もできない。
4. **WASM 対応の証拠がない。** `src` / `Cargo.toml` / README を検索して wasm の記述が 0 件（`Cargo.lock` には transitive な `wasm-bindgen` があるが、target 設定・CI・fixture はない）。native 専用の `libloading` witness 生成に依存する。ICP canister / browser での実行は未検証以前に、設計上の配慮が見当たらない。
5. **配布物がない。** GitHub tag / release が 0 件、crates.io にも `spartan-whir` は存在しない。特定 commit のソースを vendor するしかない。
6. **監査・運用実績が未確認。** SECURITY.md、監査報告、安定版の運用実績を確認できない。研究コードとしての性格が強い。

#### 6.2.3 spartan-whir のまとめ

- full-ZK と Spark を実装している点は技術的に興味深い。
- しかし BN254 非対応、128-bit 不可、license なし、WASM なし、配布物なし、監査未確認。
- **総合判定: Blocked。** 現時点で採用するには、field 移植・security 強化・license 明確化・WASM 移植・監査のすべてが必要で、Phase 0 の範囲を超える。

### 6.3 WHIR 単体

WHIR は PCS（polynomial commitment scheme）であり、R1CS の充足性や公開入力 binding を単体で検証する SNARK ではない。Branch 85 のルールも「WHIR 単体を Verifier にしない」と明記している。

ProveKit が使う `worldfnd/whir` fork は Apache-2.0 で、rev `d2b16529d0a4fad4f53d088281e9062898d35f5b` に pin されている。ただし、これは PCS の依存であり、Spartan の sumcheck、R1CS の関係、公開入力の binding を別途実装しなければ Verifier にならない。**単体採用は不採用。**

### 6.4 microsoft/Spartan

Microsoft Spartan は Trusted Setup 不要の zkSNARK だが、field は Curve25519 scalar で、PCS は Spartan 独自（WHIR ではない）。BN254 への drop-in ではなく、WHIR の利点（hash-based PCS、透明性、post-quantum 方向）も得られない。MIT license だが、本ブランチの候補としては不採用。

### 6.5 その他の選択肢

- crates.io 検索（2026-11-27）では `spartan2` 0.9.0（Microsoft Spartan2、`halo2curves` 系）、`ark-spartan-golden`、`slop-spartan` などが見つかるが、いずれも WHIR PCS を組み合わせたものではない。BN254 + Spartan + WHIR + full ZK + wasm32 を同時に満たす既製 crate は確認できなかった。`spartan2` は WHIR ではないため本候補の代替にならず、full-ZK / WASM の要件も本調査では確認していない。
- `plonky2` / `plonky3` 系: field は Goldilocks / KoalaBear 系で、BN254 ではない。既存の Plonky2 verifier は維持するが、Spartan+WHIR/BN254 の代替にはならない。
- Zcash `halo2_proofs` IPA / Pasta: BN254 Fr 回路をそのまま扱えず、VK 復元も circuit 型に依存する。既存の Halo2 IPA プロファイル（`halo2-axiom` BN254）と競合するため、別途の採用理由が必要。
- 独自 port / fork: 暗号の独自実装・独自パラメータ生成は、独立レビューなしでは禁止する。Phase 0 では採用しない。

## 7. 実現性判定（blocked 理由）

**BN254 + Spartan + WHIR + full ZK + wasm32 を同時に満たす既製の Rust crate は、2026-11-27 時点で確認できなかった。** ProveKit は BN254 / Spartan / WHIR を持つが完全 ZK ではなく、spartan-whir は full-ZK を持つが BN254 ではなく、どちらも WASM / ICP と 128-bit の gate を満たさない。以下に blocked 理由を列挙する。

| ID | Blocked 理由 | 根拠 | 影響 |
|---|---|---|---|
| B1 | BN254 drop-in がない | ProveKit は BN254 だが frontend / R1CS / codec が非互換。spartan-whir は KoalaBear のみ | 既存 BN254 R1CS をそのまま使えず、変換層または field エミュレーションが必要 |
| B2 | 完全 ZK 未達（ProveKit） | `whir_r1cs.rs` の doc comment が「hiding commitment alone is not full proof ZK」と明記 | Branch 85 の完全 ZK 条件を満たさない |
| B3 | 128-bit を設定できない（spartan-whir） | `MAX_SECURITY_BITS = 123`、既定 100、128 への TODO あり | security を下げずに性能目標を達成する方針に反する |
| B4 | license がない（spartan-whir） | LICENSE file なし、`Cargo.toml` license なし、GitHub API null | 依存追加・vendoring・再配布ができない |
| B5 | WASM / ICP 未対応 | ProveKit は atomics + SharedArrayBuffer + wasm-bindgen-rayon 前提。spartan-whir は wasm target 設定 / CI / fixture なし | Browser / Nim / ICP の実行要件を満たせない |
| B6 | toolchain / MSRV 不一致 | ProveKit `main` は nightly-2026-03-04、`skyscraper` / `ntt` が nightly feature を使用。`ark-bn254` 0.6 で既存 0.5 と二重依存 | 既存 workspace の stable build に統合できない |
| B7 | 依存が巨大・未公開 | ProveKit workspace 23 member、Noir / nargo / Mavros / WHIR fork。`provekit-backend-bn254` / `provekit-spark` / `provekit-wasm` は crates.io 未公開 | canister verifier に不要な prover / compiler 依存が入るリスク。監査・再現性の負担が大きい |
| B8 | proof / key codec が未固定 | ProveKit は `main` の proof/key format が変わり得ると明記。v1.0.3 と main で構成が別物 | wire format の magic/version/互換性を本リポジトリで固定できない |
| B9 | 検証コストが R1CS 依存 | ProveKit verifier が毎回 `transpose_r1cs_matrices` と `eq_alpha` 乗算を実行 | PCS 単体の漸近計算量では性能を保証できない。ICP の instruction / memory 予算に影響 |
| B10 | 監査未確認 | ProveKit / spartan-whir ともに監査報告を確認できない | 本番資産用途の前提を満たさない。Phase 0 で「監査済み」と主張できない |
| B11 | SPARK / recursive 経路が Trusted Setup 依存 | ProveKit の SPARK は recursive verifier 用 prototype。Groth16 wrapper は Trusted Setup 必須 | SPARK を使って検証コストを下げる経路は本ブランチの制約に反する |
| B12 | 公開入力 binding が API 保証でない（ProveKit） | `Verify::verify(proof)` が proof 内の `public_inputs` を使う。期待値比較は呼出側 | `expectedPublicInputs` を必須にするラッパーとテストが必要 |
| B13 | DoS 上限が未確認 | ProveKit の library-level decode/alloc 上限、spartan-whir の wasm 時上限を本リポジトリで検証していない | 無制限入力・CPU/メモリ DoS の gate を満たせない |

補足: 「完全 ZK に SPARK が必須で未実装」という想定は、**spartan-whir には当たらない**。spartan-whir は Spark を含む full-ZK を実装済みで、blocker は BN254 非対応・128-bit 不可・license なし・WASM なしである。ProveKit の SPARK は ZK 方式ではなく、完全 ZK 未達は「hiding commitment だけでは alpha / 公開入力 / challenge 評価が平文で残る」という別の理由による。

## 8. 採用しない場合の次アクション

本ブランチでは Spartan+WHIR の API を追加しない。以下は、将来の PoC ブランチを立てる場合の gate とレビュー観点である。

### 8.1 PoC ブランチの前提条件（すべて必須）

1. **完全 ZK の証明**: witness commitment の hiding だけでなく、alpha / 公開入力 / challenge 評価が proof に平文で漏れないことを、設計文書とコードで確認する。上流の "not full proof ZK" 注記が解消されていること。
2. **BN254 の end-to-end**: field エミュレーションではなく、BN254 Fr/G1 を native に扱う。既存の BN254 Fr との型変換・canonical 32-byte BE の境界を固定する。
3. **128-bit security**: ZK の漏洩を含む総合 security を 128-bit 相当で設計し、上流のパラメータ・仮定・不足分を定量化する。123-bit 上限のような設計は受け入れない。
4. **WASM の実証**: `wasm32-unknown-unknown`（atomics なし、single-thread）と `wasm32-wasip1` の両方で build し、verify fixture を実行する。Browser は Web Worker、ICP は Nim static link + PocketIC で確認する。ビルド成功を実行成功とみなさない。
5. **依存の分離**: verifier-only の crate / feature を構成し、Noir compiler / nargo / Mavros / prover / rayon の並列実行が canister artifact に入らないことを確認する。
6. **toolchain**: 既存 workspace の stable toolchain で build できるか、nightly を隔離できるかを確認する。`ark` の二重依存を許容する場合は、型変換と wasm size への影響を測る。
7. **codec の固定**: proof / VK / PK に magic、version、canonical encoding、trailing bytes 拒否、長さ上限を定義し、外部仕様として固定する。上流 `main` の不安定な format をそのまま公開しない。
8. **公開入力 binding**: `verify(vk, proof, expected_public_inputs)` の形で期待値を必須にし、proof 内のコピーだけを信じない。期待値の順序・個数・型を VK / circuit digest に bind する。
9. **VK pinning**: 利用側が承認済み VK（または VK hash / relation digest）を pin する API を提供する。任意の VK を untrusted input から受け取らない。
10. **DoS 上限**: decode / allocate 前に proof / VK / PK / R1CS の最大サイズ、最大制約数、最大 nnz、最大 k を検査する。検証失敗で状態変更しない。
11. **監査 / 独立レビュー**: 暗号設計、Fiat–Shamir、ZK 漏洩、serialization、WASM 実行、依存 provenance を独立レビューする。DIY 暗号の場合は特に、レビュー完了まで本番経路に入れない。

### 8.2 レビュー観点

- Fiat–Shamir transcript が relation / circuit digest / profile / 公開入力 / security config を最初の challenge より前に bind しているか。
- R1CS の生成・正規化・digest が決定的で、等価な sparse encoding の差で digest が変わらないか。
- 公開入力の個数・順序・canonical 性・mod reduction を検証しているか。
- proof の malleability、trailing bytes、余剰 field element、非 canonical point、subgroup 外 point を拒否するか。
- ZK の漏洩（alpha 評価、公開入力評価、challenge 評価、witness commitment の開示）を説明できるか。
- RNG は OS CSPRNG か。test-only deterministic RNG が本番経路に混入しないか。
- witness / seed / blinding の zeroize と log 禁止。
- verifier が I/O・clock・threads・OS RNG に依存しないか（canister 要件）。
- wasm trap / panic=abort で回復不能にならないか。
- 依存の license、NOTICE、revision、checksum、再現手順。

### 8.3 必要な fixture / ベンチ

- 小規模 ~1k R1CS と ~20k R1CS の同等 statement（複数の秘密 Merkle path、128-bit range などを含む）。
- 正しい proof、公開入力変更、witness 変更、VK 変更、circuit 変更、profile 変更の負例。
- 切断、末尾余剰、過大長、NULL、非 canonical Fr、不正点、不正 k / round、malformed bincode / postcard の fuzz。
- 同一 proof の繰り返し verify、並行 verify、verifier の再利用（ProveKit の `Verifier` は `take()` で消費されるため、reload / clone の挙動も確認）。
- Native / `wasm32-unknown-unknown` / `wasm32-wasip1` / Browser Web Worker / PocketIC の実行。
- prove / verify の wall time、peak RSS、WASM pages、proof / PK / VK size、cold / warm、ICP instructions / cycles。
- R1CS の転置・`eq_alpha` 乗算を含む verify コストを、PCS 単体と分けて報告する。

### 8.4 security / 公開入力 / VK / DoS の目標

- security: 128-bit 相当を設計値とし、上流の soundness / binding / ZK の仮定と不足分を定量的に記録する。性能目標のために security を下げない。
- 公開入力: Verifier が期待値を独立に受け取り、proof 内のコピーと一致することを必須にする。一致しない場合は検証失敗。
- VK: 承認済み VK / VK hash を pin する。VK の relation digest と circuit digest を検証する。
- DoS: proof / VK / PK / R1CS の上限を decode / allocate 前に適用する。検証失敗で状態を変更しない。canister では ingress / instruction / memory の上限を実測する。

## 9. 既存 Halo2 IPA との役割分担

| プロファイル | 状態（本ブランチ） | field / PCS | Trusted Setup | 証明サイズ | Verify コスト | 用途 |
|---|---|---|---|---|---|---|
| Groth16/BN254 | 既存・維持 | BN254 / Groth16 | 必要（回路固有 ceremony） | 小 | 小（pairing） | 既存アプリ |
| Halo2 KZG/BN254 | 既存・維持 | BN254 / KZG + SHPLONK | 必要（universal SRS） | 中 | 中（pairing + MSM） | 既存アプリ |
| Halo2 IPA/BN254 | **実装中**（API 契約・wire format は定義済み。Rust 実装は working tree に存在するが、本ドキュメントでは実行検証していない） | BN254 / IPA (BGH19) / Blake2b | 不要（`ParamsIPA::new(k)` の決定的生成） | 未測定（IPA は KZG より大きい傾向） | 最終 MSM を含む（本ブランチで実測未） | 透明プロファイルの第一候補 |
| Spartan+WHIR/BN254 | **未実装 / Blocked** | BN254 を目指すが、現候補は BN254 drop-in ではない | 不要（WHIR は hash-based） | 未確認（WHIR は大きい傾向） | R1CS 評価を含む。PCS 単体では保証できない | 将来の研究候補 |

- Halo2 IPA は、既存の `halo2-axiom` 0.5.3 vendored コピーを使う透明プロファイルとして実装を進める。VK 復元は具体 Circuit 型を要求するため、crate 内の承認済み circuit id レジストリ方式とし、任意コードを入力から実行しない。詳細は `docs/halo2-ipa.md`（実装タスク）と ADR を参照する。
- Spartan+WHIR は、Halo2 IPA の代替でも上位互換でもない。別 profile / 別 marker type / 別 wire format を持つ候補であり、採用する場合は `SpartanWhirBn254` のような独立した型名にする。既存の `Halo2IpaBn254` と混同しない。
- 本ブランチでは Spartan+WHIR の公開 API を追加しない。`Halo2IpaBn254` もまだ実装中であり、**どちらも「出荷済み」と主張しない**。
- 既存の KZG / Groth16 の API・wire format・VK を変更しない。profile 間の fallback（例: Spartan が失敗したら KZG で検証）を自動化しない。

## 10. 未確認事項

- ProveKit の対象回路（既存 BN254 R1CS 相当）での proof size / prove time / verify time / memory。公式の固定値は確認できていない。
- ProveKit の browser / Node WASM の実ビルド・実行、`wasm32-wasip1` / ICP での実行。
- ProveKit の完全 ZK 実装が `main` 以外の branch に存在するか、いつ merge されるか。`add_zk_to_*` 系 branch の内容は本調査で確認できていない。
- ProveKit の監査報告の有無・範囲・日付。docs は "ProveKit's audit" に言及するが、リポジトリ内に報告書がない。
- ProveKit の v1.0.3 tag と crates.io 1.0.3 の完全な対応関係、および v1.0.3 の proof / key format の安定性。
- ProveKit の `Verify::verify` が期待公開入力を受け取らない点を、利用側ラッパーでどう固定するか。
- spartan-whir の BN254 対応予定、WASM 対応予定、license の意図、監査予定。
- spartan-whir の 1.84 MB が他の回路サイズ・security 設定でどう変わるか。ICP の ingress / instruction 上限との適合。
- spartan-whir の `MAX_SECURITY_BITS = 123` が 128-bit に引き上げられる時期。
- 各候補の依存全体の license（本ドキュメントでは主要依存のみ確認）。
- 本リポジトリの `Halo2IpaBn254` 実装の完成度（本調査時点では API 契約と Rust 実装を確認。Native / WASM / Nim / ICP の実行検証と、実装タスクの完了状況は別途確認が必要）。

## 11. 参照

### worldfnd/provekit

- Repository: https://github.com/worldfnd/provekit
- `main` HEAD: `893f6d5866d52124e12c4a90a71c0f4d625f083b`（2026-11-12）
- `v1.0.3` tag: `00cbd7daba13e6ee1ee05d0b4a096a9ea0427ac4`（release 2026-10-27）
- `v1.0.2` tag: `4ee40639fb8849aeeba37761fdda07f28367e81d`
- `LICENSE.md`（MIT）: https://github.com/worldfnd/provekit/blob/main/LICENSE.md
- `Cargo.toml`（workspace / dependencies / toolchain）: https://github.com/worldfnd/provekit/blob/main/Cargo.toml
- `rust-toolchain.toml`: https://github.com/worldfnd/provekit/blob/main/rust-toolchain.toml
- `provekit/common/src/whir_r1cs.rs`（hiding / full ZK の注記）: https://github.com/worldfnd/provekit/blob/main/provekit/common/src/whir_r1cs.rs
- `provekit/verifier/src/whir_r1cs.rs`（R1CS 転置・評価）: https://github.com/worldfnd/provekit/blob/main/provekit/verifier/src/whir_r1cs.rs
- `provekit/spark/SPARK.md`（prototype / native verify）: https://github.com/worldfnd/provekit/blob/main/provekit/spark/SPARK.md
- `provekit/backend/bn254/src/verify.rs`（公開入力の扱い）: https://github.com/worldfnd/provekit/blob/main/provekit/backend/bn254/src/verify.rs
- `tooling/provekit-wasm/Cargo.toml`（WASM build 前提）: https://github.com/worldfnd/provekit/blob/main/tooling/provekit-wasm/Cargo.toml
- `.cargo/config.toml`（atomics / shared-memory）: https://github.com/worldfnd/provekit/blob/main/.cargo/config.toml
- Docs "Security and trust model": https://github.com/worldfnd/provekit/blob/main/docs/src/content/docs/concepts/security-model.mdx
- Docs "Production checklist": https://github.com/worldfnd/provekit/blob/main/docs/src/content/docs/reference/production-checklist.mdx
- Blog: https://world.org/blog/engineering/provekit-privacy-for-the-real-world

### ethereum/spartan-whir

- Repository: https://github.com/ethereum/spartan-whir
- `main` HEAD: `14d6da4211eda59e65cfd0af5e2dcd89d523edc3`（2026-10-22）
- `Cargo.toml`: https://github.com/ethereum/spartan-whir/blob/main/Cargo.toml
- `README.md`（full-ZK / Spark / benchmarks / codec）: https://github.com/ethereum/spartan-whir/blob/main/README.md
- `src/security.rs`（`MAX_SECURITY_BITS = 123`）: https://github.com/ethereum/spartan-whir/blob/main/src/security.rs
- Plonky3 fork revision: `458ef546a251ab4d9d73c453d24a414334786ca0`（https://github.com/Client-Side-Proving/Plonky3）
- Full-ZK の参考文献: https://eprint.iacr.org/2026/391
- R1CS relation binding の参考文献: https://eprint.iacr.org/2026/1838

### その他

- microsoft/Spartan: https://github.com/microsoft/Spartan（HEAD `d62b961f9497e3c07a921b6da1457cad467598d9`、MIT）
- worldfnd/whir fork: https://github.com/worldfnd/whir（Apache-2.0、ProveKit pin `d2b16529d0a4fad4f53d088281e9062898d35f5b`）
- WizardOfMenlo/whir（WHIR 原実装）: https://github.com/WizardOfMenlo/whir
- crates.io: `provekit-prover` / `provekit-verifier` / `provekit-common` / `provekit-r1cs-compiler` は 1.0.3 が公開済み。`provekit-backend-bn254` / `provekit-spark` / `provekit-wasm` / `spartan-whir` は未公開（2026-11-27 確認）。
