# Halo2 IPA / Poseidon2 branch 87 内部セキュリティレビュー

- 対象ブランチ: `87-修正設計実装-halo2-ipaの制約健全性修正汎用circuit登録api秘密入力対応poseidon2-chip`
- 基準コミット: `b6977bd`（`eee6714` からの差分 + 未追跡ファイル）
- レビュー日: 2026-11-28
- レビュー種別: **実装者とは別の内部レビュー**。独立した外部監査ではない。
- 対象: `rustcrypto-ffi/src/poseidon2_halo2.rs`、`rustcrypto-ffi/src/poseidon2_chip.rs`、`rustcrypto-ffi/src/halo2_ipa.rs`、`rustcrypto-ffi/src/halo2_ipa_registry.rs`、`examples/halo2-ipa-external-circuit/**`、`examples/halo2-ipa-external-circuit-wasm/**`、`web/halo2-ipa-external-circuit/**`、`tests/fixtures/*`、`docs/*`、`rustcrypto-ffi/tests/halo2_ipa_codec_robustness.rs`。

> **重要**: 本文書は内部レビューであり、独立した第三者監査、暗号学的保証、資産用途の安全性認定ではない。指摘の「確認済み」はコード読解または本レビュー環境で実行した再現に基づくが、未実行の claim（特に browser / ICP / wasm の実測値）は実装担当の報告として扱う。

## 1. エグゼクティブサマリ

P0 の Poseidon2 sponge 制約不足（未使用 rate lane / capacity 加算値の zero 制約、長さ IV、block 間 `prev` コピー）は、コードと負例テストの両方で確認できた。**sponge 本体に残る未拘束 witness は見つからなかった**。Chip は instance 列を触らず、digest 公開は呼び出し側制御になっており、gadget の boolean / select / equality / u128 range も概ね健全である。

一方、以下の重大な問題を確認した。

1. **V2 magic は artifact の認可境界になっていない**。旧 V1 Poseidon2 VK の先頭 8 バイトを `RCH2IPV2` に書き換えるだけで、旧（脆弱）VK と旧 proof が `validate_vk=0` / `verify=0` で受理された。ブランチの「旧 artifact を新回路として受理しない」「脆弱な互換経路を残さない」という要求を満たしていない。
2. **外部回路の代表例 `ChainCircuit` / `LinearCircuit` が健全でない**。最初の accumulator `acc_0` が `input_0` に拘束されておらず、公開 `input_0` は chain のどの制約にも現れない。悪意ある prover は `acc_0 != input_0` の witness で 17 個の公開値を満たせる。MockProver で再現した。
3. その他、witness の zeroize 不在、vendored `SimpleFloorPlanner` による複数 region の暗黙オーバーラップ、非 equality 列を渡した場合の panic / wasm trap、ドキュメントの状態矛盾などを確認した。

| ID | 重大度 | 領域 | 状態 |
|---|---|---|---|
| F-1 | High（V2 magic を認可境界とみなす配備では Critical） | V1/V2 artifact revision | 確認済み（再現） |
| F-2 | High | 外部回路の例（Chain/Linear） | 確認済み（再現） |
| F-3 | Medium | witness zeroize / one-shot cache | コードで確認 |
| F-4 | Medium | region / row レイアウト | コードで確認 |
| F-5 | Medium | 非 equality 列 / panic=abort trap | コードで確認 |
| F-6 | Low | registry profile の key サイズ上限 | コードで確認 |
| F-7 | Low | `params_digest` の意味 | コードで確認 |
| F-8 | Low–Medium | ドキュメントの主張・状態矛盾 | 確認済み |
| F-9 | Low | 信頼しない VK の `k` による params 生成コスト | コードで確認 |
| F-10 | Info | macro の symbol/prefix 衝突 | コードで確認 |
| F-11 | Info | `Poseidon2Input` の value/cell 不一致・C ABI の重複出力 | コードで確認 |

## 2. 詳細な指摘

### F-1. V2 magic の付け替えで旧 V1 脆弱 artifact が受理される（High / 配備次第で Critical）

**状態: 確認済み（本レビュー環境で再現）**

対象:

- `rustcrypto-ffi/src/halo2_ipa.rs:554` `parse_vk`
- `rustcrypto-ffi/src/halo2_ipa.rs:1458` `verify_impl`
- `rustcrypto-ffi/src/halo2_ipa_registry.rs:310` `parse_v2_vk`
- 負例テスト `rustcrypto-ffi/tests/halo2_ipa_codec_robustness.rs:914` と `rustcrypto-ffi/src/halo2_ipa.rs:2401`

**シナリオ**

`parse_vk` は magic が V1/V2 のいずれかであること、circuit id と revision が一致することを検査するが、**VK payload が現在の回路（健全化後の `Poseidon2HashCircuit`）の VK であることを検査しない**。V2 magic を付けた payload は `VerifyingKey::read` でそのままデコードされ、`verify_proof` は与えられた VK（= 旧回路の VK）で旧 proof を検証する。

実際に以下を再現した。

1. 旧 V1 の Poseidon2 VK を読む（本リポジトリは V1 fixture を保持しないため、
   再現には P0 修正前のビルドで生成した artifact を別途用意する）。
2. 先頭 8 バイトだけを `RCH2IPV2` に置換する（payload は旧 V1 のまま）。
3. `rustcrypto_halo2_ipa_bn254_vk_validate` と `rustcrypto_halo2_ipa_bn254_verify` を呼ぶ。

結果:

```text
legacy VK validate = 23          # INVALID_VERIFYING_KEY
legacy verify      = 23          # INVALID_VERIFYING_KEY
relabelled V2 VK validate = 0    # OK
relabelled V2 verify      = 0    # OK（旧 proof が通る）
```

`parse_v2_vk`（外部 registry）も同じ構造で、V2 magic と `circuit_id == profile.circuit_id` だけを検査し、payload が `C` の現在の constraints に対応するかは検査しない。`CircuitProfile::circuit_version` は envelope に含まれず、`verify` でも照合されないため、revision の識別子としては機能しない。

**影響**

- 旧（未使用 absorb lane が未拘束の）Poseidon2 回路の VK/proof を、V2 magic を付けるだけで「健全化後の V2」として受理する。
- アプリケーションが V2 magic を artifact の認可境界として扱っている場合、資産用途の proof 検証で旧回路の弱い命題を受け入れる。**この場合は Critical**。
- アプリケーションが `vk_digest` を別経路で pin している場合は、その pin が最後の防御になる（docs も pin を要求している）。ただし「V1 magic を拒否しているから安全」という説明・テストは不正確。
- 既存の負例テストは「V1 magic のまま」の拒否しか見ておらず、V2 への relabel を検出しない。

**推奨修正**

- `verify` に、呼び出し側が指定した **承認済み VK digest（SHA-256）** を必須引数として渡し、`parse_vk` 後に照合する API を追加する。registry 側は `CircuitProfile` に `approved_vk_digest: Option<[u8;32]>` を持たせる、または `verify_with_pinned_vk<C>(approved_digest, ...)` を用意する。
- もしくは VK envelope に payload 全体の digest / circuit revision を追加し、既知の定数と比較する。magic だけでは認可境界にならないことを明記する。
- 旧 V1 payload はリポジトリから削除済みである。`poseidon2_uses_v2_magic_and_rejects_v1_relabel` と `cross_revision_artifacts_are_separated` で V1 magic の拒否を、`pinned_verify_accepts_approved_v2_poseidon2_and_cubic_fixtures` で digest pin が承認境界であることを確認する。
- docs の「V1/V2 の artifact に互換経路は無い」「旧 V1-magic 鍵 artifact は受理しない（脆弱な互換経路を残さない）」という表現を、VK digest pin が必須であることを含めて修正する。

### F-2. 外部回路の例 `ChainCircuit` / `LinearCircuit` の最初の accumulator が未拘束（High）

**状態: 確認済み（コード + MockProver 再現）**

対象:

- `examples/halo2-ipa-external-circuit/src/lib.rs:149`（`ChainCircuit::synthesize`）
- `examples/halo2-ipa-external-circuit/src/lib.rs:162`（`if row > 0` で gate を有効化）
- `examples/halo2-ipa-external-circuit/src/lib.rs:319`（`LinearCircuit::synthesize`）
- `examples/halo2-ipa-external-circuit/src/lib.rs:332`
- docs の主張: `docs/halo2-ipa-external-circuit.md:54`、`docs/halo2-ipa.md:410`

**シナリオ**

回路は `acc_i = acc_{i-1}^2 + input_i` を 16 step 拘束すると説明されているが、gate は `row > 0` でのみ有効で、`acc_0` と `input_0` を結ぶ制約がない。`accumulator_cells[0]` は host の `accumulators()[0] = inputs[0]` として代入されるだけであり、制約系には現れない。公開 instance は `[acc_1, .., acc_15, input_0, input_15]` なので、`input_0` は公開されるが chain のどの制約にも使われない。

`ChainCircuit` の公開 API は honest な `acc_0 = input_0` しか生成しないため、同じ gate・列・行配置を再現した一時回路（`/tmp/opencode`、リポジトリ外）で、`input_0 = 1`、`acc_0 = 7`、`acc_1 = 7^2 + input_1` として全 gate を満たす witness を MockProver に与えたところ、`Ok(())` で satisfied になった（`input_0` と `acc_1` の関係は成立しない）。`LinearCircuit` も同じ構造である。

**影響**

- 外部回路登録の代表例が、意図した命題より弱い命題を証明する。`input_0` は実質的に無拘束。
- この例をテンプレートとしてコピーしたアプリケーションは、同様の欠陥を資産回路に持ち込む。
- registry / adapter 自体の欠陥ではないが、ブランチの成果物（17 公開値の外部回路例）の健全性を損なう。

**推奨修正**

- `synthesize` 内で `region.constrain_equal(accumulator_cells[0], input_cells[0])` を追加する、または row 0 にも `acc_0 = input_0` を拘束する gate を置く。意図が「任意の `acc_0` から始まる chain」であれば、`input_0` を公開せず `acc_0` を公開する（どちらを公開するかを明示する）。
- `LinearCircuit` も同様に修正する。
- `adapter.rs` に「`acc_0 != input_0` の悪意ある witness を拒否する」負例を追加する。現在のテストは honest witness と instance の改変しか見ていない。
- docs の「16 step 連鎖」という記述を、最初の step の扱いを含めて修正する。

### F-3. one-shot prover cache の witness が zeroize されない（Medium）

**状態: コードで確認（テスト未実施）**

対象:

- `rustcrypto-ffi/src/halo2_ipa.rs:1148` `struct CachedProof`
- `rustcrypto-ffi/src/halo2_ipa.rs:1394` `CACHED_PROOF.with`
- `rustcrypto-ffi/src/halo2_ipa.rs:1422` `witness_bytes: witness_bytes.to_vec()`
- `rustcrypto-ffi/src/halo2_ipa.rs:1436` `*slot = None`
- `rustcrypto-ffi/src/halo2_ipa_registry.rs:607` `struct CachedProof`
- `rustcrypto-ffi/src/halo2_ipa_registry.rs:734`、`:753`、`:763`

**シナリオ**

`prove` は sizing / short-output の再試行のために `witness_bytes` を thread-local の `CachedProof` にコピーする。成功時に `*slot = None` で `Vec<u8>` を drop するが、`zeroize` を呼んでいない。`Vec` の drop はヒープ内容をゼロ化しないため、秘密の preimage / Note が解放後もヒープに残る。short output / NULL output / cancel / error で呼び出し側が再試行しない場合、witness は次の `prove` または thread 終了まで保持され、その後もゼロ化されずに drop される。

`zeroize` は `rustcrypto-ffi/Cargo.toml:54` に既に依存として存在するが、`halo2_ipa` / `halo2_ipa_registry` では使われていない。wasm adapter は `Vec` を `Zeroizing` で包んでいるが（`examples/halo2-ipa-external-circuit-wasm/src/lib.rs` の `prove`）、C ABI / registry の内部キャッシュは別である。

**影響**

- ブランチ要求の「zeroize・cancel/error/短い出力 buffer 再試行時の安全な破棄を検証」を満たさない。
- 長寿命の canister / browser worker / サーバで秘密 witness の残留リスクが増える。

**推奨修正**

- `CachedProof` に `Drop` を実装し、`witness_bytes.zeroize()` と `pk_bytes`（必要なら）を実行する。`Zeroizing<Vec<u8>>` を使う。
- 成功・short output・error の各経路で明示的に zeroize する。キャンセル用の C ABI（`..._cancel`）を追加するか、少なくとも cache を明示的に破棄する API を用意する。
- `prove_status` / `prove_impl` 内の一時コピーも zeroize する。
- cache の寿命と「sizing 後は必ず再呼び出しする」契約を docs に明記する。

### F-4. vendored `SimpleFloorPlanner` は全 region を row 0 に置くため、複数 region が暗黙にオーバーラップする（Medium）

**状態: コードで確認。docs の「複数 region テスト」主張は未確認**

対象:

- `rustcrypto-ffi/third_party/halo2-axiom-0.5.3/src/circuit/floor_planner/single_pass.rs:114`（`SingleChipLayouterRegion::new(self, 0.into())`）
- `rustcrypto-ffi/src/poseidon2_chip.rs:45`（モジュールコメント）
- `docs/poseidon2-halo2-gate.md:255`、`:372`（「複数 region」をテスト済みと主張）
- 実際のテスト: `rustcrypto-ffi/src/poseidon2_halo2.rs:2190` `chip_can_be_reused_in_one_region` など（すべて単一 region）

**シナリオ**

vendored floor planner は `assign_region` ごとに開始 row を 0 に固定する。したがって、外部回路の作者が自然に `layouter.assign_region` を 2 回呼び、それぞれで `Poseidon2Chip::hash` を使うと、同じ advice 列の同じ row を上書きする。最初の region の copy constraint は、上書き後のセルを参照することになり、回路は unsatisfiable になるか、意図しない witness 関係になる。

`Poseidon2Chip::hash` は `base` を呼び出し側が指定するが、`base` の重複や region 境界を検査しない。docs は「同一 region で繰り返し呼び出せる」と書いている一方、テスト一覧では「複数 region」を確認済みと書いており、実装と主張が一致していない。

**影響**

- 汎用 Chip / 外部回路の正しさ・liveness の危険。呼び出し側の単純なミスで回路が壊れる。
- 悪意ある prover が直接 exploit する種類の soundness ではないが、意図しない回路を生成し得る。
- 「複数 region テスト済み」という docs の主張は根拠がない。

**推奨修正**

- `Poseidon2Chip` / `ApprovedCircuit` の公開契約に「Chip 呼び出しは単一 `assign_region` にまとめるか、列・行が重複しないことを呼び出し側が保証する」と明記する。
- 可能なら floor planner を修正して region ごとに row を進める、または Chip が `base` の重複を検出できる API を提供する。
- 実際に複数 region を使うテストを追加するか、docs の「複数 region」記述を削除する。

### F-5. equality 無効列の Cell を渡すと `constrain_equal` が panic し、wasm `panic=abort` では trap する（Medium）

**状態: コードで確認（呼び出し側の契約違反）**

対象:

- `rustcrypto-ffi/src/poseidon2_halo2.rs:559` `Poseidon2Input`（equality 要件の記載なし）
- `rustcrypto-ffi/src/poseidon2_halo2.rs:968` `region.constrain_equal(input_cells[i], sources[i])`
- `rustcrypto-ffi/src/poseidon2_chip.rs:121` `GadgetValue`（equality 要件あり）
- `rustcrypto-ffi/src/poseidon2_chip.rs:315` `copy`
- `rustcrypto-ffi/third_party/halo2-axiom-0.5.3/src/plonk/keygen.rs:128`（`copy` の `unwrap_or_else(|err| panic!("{err:?}"))`）

**シナリオ**

`GadgetValue` には「column must have equality enabled」と書かれているが、`Poseidon2Input` には同等の注意がない。呼び出し側が equality を有効化していない自由 advice 列の Cell を Chip に渡すと、keygen 時の `permutation.copy` が `ColumnNotInPermutation` を返し、vendored halo2 が `panic!` する。native C ABI では `guard` が `RUSTCRYPTO_ERR_PANIC` に変換するが、wasm `panic=abort` では trap になる。

**影響**

- 外部回路作者の単純な API 誤用で keygen / proving が panic / trap する。
- 攻撃者が直接引き起こす入力ではないが、wasm の可用性に影響する。
- `Poseidon2Input` の公開 API 契約が不完全。

**推奨修正**

- `Poseidon2Input` の doc に「`cell` の列は equality 有効であること」を明記する。
- 可能なら Chip が受け取る Cell を、Chip が発行した Cell 型（または equality 保証付きのラッパー）に限定する。
- vendored `keygen.rs` の panic を `Error` に変換できるなら変換し、少なくとも docs に「Cell の列は equality 有効必須」と書く。

### F-6. registry の profile 上限が生成 key に適用されない（Low）

**状態: コードで確認**

対象:

- `rustcrypto-ffi/src/halo2_ipa_registry.rs:392` `key_material`
- `rustcrypto-ffi/src/halo2_ipa_registry.rs:627` `prepare_status`
- `rustcrypto-ffi/src/halo2_ipa_registry.rs:325`（VK の `profile.max_vk_len` 検査）
- `rustcrypto-ffi/src/halo2_ipa_registry.rs:357`（PK の `profile.max_pk_len` 検査）

**シナリオ**

`prepare` は keygen した VK/PK をそのまま返すが、`profile.max_vk_len` / `max_pk_len` を超えていないかを検査しない。profile の上限が実際の key より小さい場合、`prepare` は成功するが、その出力を `validate_vk` / `prove` / `verify` に渡すと `INVALID_LENGTH` で拒否される。profile の設定ミスが実行時まで表面化しない。

**影響**

- liveness / 設定の一貫性の問題。soundness ではない。
- 外部回路の profile を厳しくしすぎた場合に、自分の `prepare` 出力を自分で拒否する。

**推奨修正**

- `key_material` / `prepare_status` で生成 key の長さが profile 上限以下であることを検査し、超える場合は `INVALID_PARAMETER` を返す。
- または `CircuitProfile::validate` で「実際の key 長」を検査できるフックを設ける（`C::default()` の keygen は高コストなので、テスト用 helper でよい）。

### F-7. `params_digest` は params の内容 digest ではない（Low）

**状態: コードで確認**

対象: `rustcrypto-ffi/src/halo2_ipa_registry.rs:585`

`params_digest(k)` は `"RCH2IP-PARAMS-V2" || k` の SHA-256 であり、`ParamsIPA::new(k)` が生成する実際のパラメータ列の digest ではない。`ParamsIPA::new(k)` の実装や generator 導出が変わっても digest は同じ値になる。docs は「透明 IPA params の profile pin」と説明しており、完全に誤りではないが、「digest で params の差し替えを検出できる」と読める表現は誤解を招く。

**推奨修正**

- `params_profile_digest` などに改名する、または実際の params の serialized bytes を hash する（コスト高）。
- docs に「k とドメインの識別子であり、params 内容の暗号学的 digest ではない」と明記する。

### F-8. ドキュメントの主張と状態の矛盾（Low–Medium）

**状態: 確認済み**

- **V1/V2 互換性の過大な主張**
  - `docs/halo2-ipa.md:110`、`:638`、`docs/ic-branch85.md:146`、`README.md:37`、`:65` は「旧 V1-magic Poseidon2 artifact は受理しない」「V1/V2 に互換経路は無い」と書くが、F-1 の V2 relabel で旧 payload が受理される。magic 検査の説明としては正しいが、認可境界として読める表現は修正が必要。
- **「複数 region」テストの主張**
  - `docs/poseidon2-halo2-gate.md:255`、`:372` は Chip テストが「複数 region」を確認したと書くが、実際のテスト名・実装は単一 region（`chip_can_be_reused_in_one_region`）であり、F-4 のとおり複数 region は危険。
- **外部回路の chain 関係**
  - `docs/halo2-ipa-external-circuit.md:54`、`docs/halo2-ipa.md:410` は 16 step の `acc_i = acc_{i-1}^2 + input_i` を拘束すると書くが、F-2 のとおり最初の step が未拘束。
- **Browser / ICP の V2 状態の矛盾**
  - `docs/poseidon2-halo2-browser-icp.md:9–11`、`:246–248` は browser V2 再実行済み、`docs/ic-branch85.md:129–145`、`:177–184` は PocketIC V2 実行済みと書く。
  - 一方 `docs/poseidon2-halo2-gate.md:384–386` は「browser Worker / ICP canister は旧 V1 時点の実績のみで、V2 では再実行が必要」と書く。
  - `docs/halo2-ipa.md:675–684` も「browser Worker と ICP canister の Poseidon2 V2 経路は未再実行」と書く。
  - どれが最新か読者に判別できない。実測値を引用する前に、実行日・artifact hash・対象 wasm を一箇所に集約し、未実行のものは「未実行」と統一する。
- **軽微な数値**
  - `docs/halo2-ipa-codec-robustness.md:100` は cubic proof を 1152 バイトと書くが、fixture の proof envelope は 1164 バイト（transcript が 1152）。表現を「transcript」に直すか 1164 に修正する。

### F-9. 信頼しない VK の `k` で params を生成してから検証する（Low）

**状態: コードで確認**

対象: `rustcrypto-ffi/src/halo2_ipa.rs:1507`

`verify_impl` は VK header から `k` を読み、VK digest の pin より前に `params_for(k)` を呼ぶ。`k` は最大 16 に制限されているが、`k=16` の VK を繰り返し送ると毎回 `ParamsIPA::new(16)` を生成するコストを強制できる（`halo2-ipa-params-cache` 無効時）。信頼済み VK を pin する運用なら問題は小さいが、未認証の verify エンドポイントでは DoS 面になる。docs も `k` のコストに言及している。

**推奨修正**

- アプリケーション側で VK を pin し、`k` を固定する（docs の運用を必須化）。
- 可能なら `verify` の前に VK digest を照合する API を用意し、未承認 VK では params を生成しない。
- `halo2-ipa-params-cache` の利用を推奨する。

### F-10. macro の symbol / module 名衝突（Info）

対象: `rustcrypto-ffi/src/halo2_ipa_registry.rs:951`、`:1053`

`halo2_ipa_export_circuit!(C, prefix)` は `prefix` を module 名と `export_name` の接頭辞にそのまま使う。同じ crate 内で同じ prefix を 2 回使うと module 名が衝突してコンパイルエラーになる。異なる crate 間で同じ prefix を使うと、staticlib リンク時に重複 symbol になり得る。呼び出し側の責任だが、docs に「prefix は crate 全体で一意にする」と明記し、可能なら `module_path!()` などで symbol を自動的に名前空間化する。

### F-11. `Poseidon2Input` の value/cell 不一致、C ABI の重複出力（Info）

- `Poseidon2Input { cell, value }` の `value` が `cell` の実際の値と異なる場合、copy constraint により証明は失敗する（soundness ではなく liveness）。ただし API はエラーを返さず、回路が unsatisfiable になるだけなので、doc に「value は cell の値と一致必須。keygen は `Value::unknown()`」を明記する（既に一部記載あり）。
- `prepare_status` は `vk_out` / `pk_out` に `copy_nonoverlapping` を使う。呼び出し側が 2 つの出力バッファを重複させた場合は UB。C ABI の契約として「出力バッファは重複させない」と明記するか、重複を検出して `INVALID_PARAMETER` を返す。

## 3. 問題が見つからなかった領域（明示）

### 3.1 P0 sponge の健全性

- 未使用 rate lane と capacity 加算値は `assign_block` の `absorbed..4` で `constrain_constant(0)` される（`rustcrypto-ffi/src/poseidon2_halo2.rs:984–996`）。
- block 0 の `prev` は全 4 lane が `assign_advice_from_constant` で長さ IV に束縛される（`:998–1008`）。
- 2 block 目以降の `prev` は直前の最終 state に `constrain_equal` される（`:1018–1035`）。
- `pow2` / `pow5` は全 round row で `s_round` が拘束し、full/partial gate が次 state を拘束する（`:441–504`）。
- したがって、sponge の入力・state・round・digest を決める witness に未拘束の自由度は残っていない。permutation モードの absorb セルと最終 row の `pow2`/`pow5` は代入されるが、どの selector/gate からも使われない dead cell であり、命題に影響しない。
- 負例テスト `every_unused_absorb_lane_is_constrained_to_zero`（`:2005`）、`malicious_digest_is_not_accepted_as_the_correct_function`（`:2061`）、`inter_block_prev_copy_cannot_be_altered`（`:2102`）、`length_iv_cannot_be_altered`（`:2139`）は、host の `hash_output` を使わず、改変後に state/pow2/pow5/round/digest を再計算した witness を `RawHashCircuit` で直接割り当てている。host-side の事前チェックを bypass した負例になっており、意図どおり機能している。本レビューでも 22 テストが pass した。

### 3.2 Chip の digest / instance 公開

- `Poseidon2Chip::hash` は instance 列を一切触らず、最終 state の 4 セルを返す（`rustcrypto-ffi/src/poseidon2_halo2.rs:735`、`:779`）。`Poseidon2HashCircuit` だけが digest と raw 入力を instance に拘束する（`:1247–1263`）。
- `chip_hash_can_publish_only_the_digest`（`:2176`）、`chip_digest_cannot_be_substituted`（`:2241`）が、公開セルを呼び出し側が選ぶ契約と、host 計算 digest の無拘束な受け渡しが拒否されることを確認している。
- `Poseidon2Input` の `value`/`cell` 不一致は copy constraint で拒否される（`copy_helper_binds_the_assigned_cell`、`poseidon2_chip.rs`）。soundness の破れではない。

### 3.3 Gadget

- boolean: `b*(1-b)=0`（`poseidon2_chip.rs:207–212`）。
- select: `out = b + cond*(a-b)` と `cond*(1-cond)=0`（`:214–226`）。raw gate の負例 `select_gate_rejects_wrong_output_and_non_boolean_cond`（`:1662`）が pass。
- equality / zero: `diff=a-b`、`diff*inv=1-out`、`out*diff=0`、`out*(1-out)=0`（`:228–246`）。`diff=0` では `out=1`、`diff!=0` では `out=0` と `inv=1/diff` が強制され、inverse-based zero test は健全。`equality_gate_rejects_unsound_witnesses`（`:1576`）が pass。
- range: bit を boolean 拘束し、running accumulator gate `acc_next = acc_cur + bit*2^i` と初期 acc=0、最終 acc と value の copy で `value = Σ bit_i 2^i` を強制する（`:505–546`）。BN254 Fr では `2^128 < p` なので、`value >= 2^128`（`-1` を含む）は再構成できず拒否される。`u128_rejects_overflow`（`:1132`）、`range_check_rejects_field_wraparound`（`:1232`）が pass。
- `u128` の `a+b` は `a,b < 2^128` と `p > 2^254` により field wrap せず、sum の range check が overflow を拒否する。コメントと実装は一致している。

### 3.4 C ABI / codec

- `read_input` は `len == 0` / `len > max` / NULL+データを拒否する（`halo2_ipa.rs:494–506`）。
- `fr_from_be` は 32 バイト長と canonical 性を検査する（`:352–370`）。
- VK/PK/proof/instances の長さ・trailing bytes・列数・値数は decode 前に検査される。`parse_instances` は `offset == bytes.len()` を要求する（`:770–826`）。
- `parse_pk_with_circuit` は非割当スキャンで多項式長を制限してから `ProvingKey::read` する（`:641–700`）。
- `verify_impl` は transcript を最後まで消費したことを確認する（`:1529–1534`）。
- `ffi_*` は `guard`（`catch_unwind`）で panic を status に変換する。wasm `panic=abort` では `catch_unwind` が効かない点は docs に明記されている。
- `halo2_ipa_export_circuit_verifier!` は prover/keygen を含まない symbol だけを export する（`:1053–1101`）。
- codec robustness テスト 14 件（`cargo test --locked --test halo2_ipa_codec_robustness`）は本レビューでも pass した。ただし F-1 の V2 relabel はこのテストに含まれていない。

### 3.5 RNG / Node 側

- 組み込み C ABI と registry の `prove` は `OsRng` を使う（`halo2_ipa.rs:1394` 付近、`halo2_ipa_registry.rs:478`）。fixture の固定 seed は test / example 専用と明記されている。
- IC verifier は `wasm32` で getrandom を fail-closed stub にし、verify 経路で entropy を要求しない（`examples/halo2-ipa-poseidon2-ic-verifier/src/lib.rs`）。
- vendored halo2 が vanishing argument の一部に `thread_rng()` を使う点は docs に記載されており、CSPRNG ではあるが fixture proof の再現性がないことは正しく説明されている。

## 4. 本レビューで実行した確認

以下は本レビュー環境で実行した実測であり、実装担当の報告の単なる引用ではない。

```text
cd /application/rustcrypto-ffi
cargo test --locked --lib poseidon2_chip
  -> 24 passed

cargo test --locked --lib poseidon2_halo2
  -> 22 passed

cargo test --locked --lib -- poseidon2_uses_v2_magic_and_rejects_v1_relabel \
  cubic_keeps_v1_magic_and_rejects_v2 \
  poseidon2_fixture_is_revision_checked
  -> 3 passed

cargo test --locked --test halo2_ipa_codec_robustness
  -> 14 passed

cd /application
cargo test --locked --manifest-path examples/halo2-ipa-external-circuit/Cargo.toml
  -> adapter.rs 9 passed
```

追加の再現（リポジトリ外の `/tmp/opencode` に一時 crate を作成。実装ファイルは変更していない）:

1. **V2 relabel**: legacy V1 VK の magic を `RCH2IPV2` に変更すると `vk_validate=0`、`verify=0`。旧 proof が通る（F-1）。
2. **ChainCircuit の未拘束 acc_0**: 同一 gate/配置を再現した一時回路で、`input_0=1`、`acc_0=7` の malicious witness を MockProver で構成し、`verify() == Ok(())` を確認（F-2）。

未実行の claim（browser Worker / PocketIC / wasm の実測値、`ci/test_*` の全実行、259 件超の全 unit test）は、本文書では「実装担当の報告」または「未確認」として扱う。

## 5. 優先度付き remediation

### P0（資産用途の前に必須）

1. **F-1**: `verify` に承認済み VK digest の pin を必須化する API を追加し、旧 V1 payload + V2 magic を拒否するテストを追加する。docs の「互換経路なし」表現を修正する。
2. **F-2**: `ChainCircuit` / `LinearCircuit` で `acc_0 == input_0` を拘束し、malicious witness の負例を追加する。docs の 16 step 記述を修正する。

### P1（早期）

3. **F-3**: `CachedProof` の `Drop` / 成功・失敗経路で witness を zeroize する。cache の寿命と cancel 契約を明記する。
4. **F-4**: `Poseidon2Chip` / `ApprovedCircuit` の契約に「単一 region」または「行・列の非重複」を明記し、複数 region テストを追加するか docs の主張を削除する。

### P2

5. **F-5**: `Poseidon2Input` の equality 要件を明記し、可能なら列の妥当性を型で保証する。vendored `copy` の panic を `Error` に変換できるか検討する。
6. **F-6**: profile の key サイズ上限を `prepare` 生成物にも適用する。
7. **F-7**: `params_digest` を改名または実内容 digest に変更する。
8. **F-8**: ドキュメントの V2 状態・複数 region・chain 関係・proof 長を修正し、実行済み/未実行を一箇所に統一する。

### P3 / Info

9. **F-9**: 未認証 verify では VK pin / `k` 固定を必須にし、params 生成コストを制限する。
10. **F-10**: macro prefix の一意性を docs 化する。
11. **F-11**: `Poseidon2Input.value` の一致契約、C ABI 出力バッファの非重複契約を明記する。
12. テストギャップ: 最初の `prev` の lane 0..2 改変、block 1 の capacity lane 3 改変、実 IPA proof の malicious-witness 負例は未カバー。優先度は低いが、P0 の証拠を強くするために追加が望ましい。

## 6. 残存リスクと結論

- P0 の sponge 制約修正自体は、本レビューの範囲では健全であり、未使用 absorb lane / capacity 加算値 / 長さ IV / block 間 prev コピーに未拘束の自由度は残っていない。
- しかし、**V2 magic の relabel で旧脆弱 artifact が受理される**ため、ライブラリの revision 機構は artifact の認可境界として不十分である。VK digest pin を必須運用にしない限り、P0 修正の効果はアプリケーション層で無効化され得る。
- 外部回路の代表例 `ChainCircuit` / `LinearCircuit` は、現状のままでは意図した chain 命題を証明しない。テンプレートとして使用してはならない。
- witness の zeroize、複数 region の安全性、非 equality 列の panic は、資産用途の前に対処すべき運用・API 上のリスクである。
- 本レビューは **内部レビュー** であり、独立した外部監査ではない。暗号学的安全性、資産の保全、本番性能を保証するものではない。独立監査と、VK digest を含む配布物の pin を別途実施すること。

---

**明示**: これは実装チーム内の独立した立場からのレビューであり、第三者による独立セキュリティ監査ではない。本文書をもって本ブランチの資産用途の安全性・本番適合性を認定するものではない。

## 7. 追加レビュー後の対応状況（2026-11 追記）

レビュー後に以下を実装・再検証した。指摘番号は本文に対応する。

- **F-1 対応済み（緩和）**: complete VK envelope の SHA-256 を必須にする
  `rustcrypto_halo2_ipa_bn254_verify_pinned` /
  `..._vk_validate_pinned` と Nim `verifyPinned` /
  `validateVerifyingKeyPinned` を追加した。旧 V1 payload の magic を
  `RCH2IPV2` に書き換えた relabel VK は、承認済み V2 digest の pin により
  `INVALID_VERIFYING_KEY` で拒否される（`legacy_v1_poseidon2_v2_relabel_is_rejected_by_pinning`、
  Nim `poseidon2 pinned verification binds the approved V2 VK`）。
  既存の unpinned `verify` は互換のため残るが、caller VK を信頼する API で
  あり、承認境界にはならないことを docs/API comment に明記した。
- **F-2 対応済み**: `ChainCircuit` / `LinearCircuit` に
  `acc_0 == input_0` の copy constraint を追加し、旧 malicious witness
  （`input_0=1`, `acc_0=7`）が MockProver で拒否される負例を追加した。
  fixture/VK を再生成し、旧 fixture/proof が新 canister で拒否されることも
  PocketIC で確認した。
- **F-3 対応済み**: prover one-shot cache の `CachedProof` に `Drop` を実装し、
  witness/instances/PK bytes を zeroize する。
- **F-4 対応済み（docs）**: `SimpleFloorPlanner` の制約を明記し、複数 hash は
  単一 region 内の固定 row offset を使うこと、任意の複数 region 配置は
  未検証であることを docs に記載した。
- **F-6 対応済み**: registry `prepare` の生成 VK/PK に profile 上限を適用。
- **F-7 対応済み（docs）**: `params_digest` が params 内容の digest ではなく
  profile/version tag であることを明記。
- **F-8 対応済み（docs）**: browser/ICP の V2 実行状態、外部回路の
  wasm/Browser/ICP、複数 region、旧 V1 fixture の扱いを整理した。
- **F-5 / F-9 / F-10 / F-11 / テストギャップの一部は未対応または運用契約**:
  `Poseidon2Input` は equality-enabled 列のセルを渡す契約、macro prefix は
  一意にする契約、C ABI 出力バッファは入力と重複させない契約のままである。
  追加の型安全化・独立監査は別タスクとする。

対応後も、本レビューは内部レビューであり、第三者監査ではない。VK digest の
配布・承認・ローテーションはアプリケーションの責任である。
