# 外部 Halo2 IPA 回路 (ChainCircuit) — ICP verify-only canister

`examples/halo2-ipa-external-circuit` の `ChainCircuit`（circuit id `0x10001`、
公開値 17 個）を、ICP 上で **verify 専用** に検証する canister の設計・ビルド・
PocketIC 実測をまとめる。

- 未監査・非保証である。外部監査や mainnet 運用をこの文書は主張しない。
- 本 canister は proof を検証して status を返すだけで、状態を変更しない。
- proving / keygen / witness 入力 / 任意 VK / params / RNG は一切公開しない。

---

## 1. アーキテクチャ

| 項目 | 内容 |
|---|---|
| crate | `examples/halo2-ipa-external-circuit-ic-verifier` |
| package | `halo2-ipa-external-circuit-ic-verifier` |
| 成果物 | `halo2_ipa_external_circuit_ic_verifier.wasm` |
| circuit | `ChainCircuit`（id `0x10001`, version `1`） |
| method | raw update `canister_update verify` |
| 追加 export | `rustcrypto_halo2_ipa_external_chain_verify`（pinned VK のみを使う C ABI verifier） |
| imports | `ic0` の 5 関数のみ |
| threads / filesystem / clock / network | 使用しない |

### 1.1 Cargo path 依存（source copy / build.rs なし）

外部 example crate を **本物の Cargo path dependency** としてリンクする。
`build.rs` による source のコピー・書換え・`include!` は行わない。

```toml
[dependencies]
halo2-ipa-external-circuit = { path = "../halo2-ipa-external-circuit", features = ["verify-only"] }
rustcrypto-ffi = { path = "../../rustcrypto-ffi", features = ["halo2-ipa-verify-only"] }
```

- 外部 crate の `verify-only` feature は
  `halo2_ipa_export_circuit_verifier!` を展開し、
  `rustcrypto-ffi/halo2-ipa-verify-only` を feature unification で有効にする。
  `chain_adapter_prepare` / `chain_adapter_prove` は生成されない。
- canister がコンパイルする `ChainCircuit` は外部 crate 自身の型である。
  canister は `halo2_ipa_registry::verify::<ChainCircuit>` を直接呼ぶ。
- VK / proof / instances の wire format と status は `rustcrypto-ffi` の
  registry と `status.rs` をそのまま使う。

### 1.2 なぜ staticlib + 明示 link なのか

`rustcrypto-ffi` は多数の `#[no_mangle]` C ABI 関数を持つ rlib である。
これを `cdylib` としてビルドすると、rustc は依存 graph の **すべての**
`#[no_mangle]` シンボルに対して `--export=<symbol>` を linker に渡す。
その結果、canister が参照していなくても prover / 無関係な crypto の
object が残り、wasm に export される（実測で 7.99 MB、`_prove` を含む）。

そこで本 crate は `staticlib` を生成し、`link-canister.sh` が `wasm-ld`
で **2 シンボルだけを export** して `--gc-sections` を適用する。

```bash
bash examples/halo2-ipa-external-circuit-ic-verifier/link-canister.sh <out.wasm>
```

これは export 制御であり、source inclusion ではない。回路定義・registry・
verifier はすべて Cargo 依存の実コードである。

---

## 2. VK の pin とビルド

VK はビルド時に固定する。

```rust
const APPROVED_VK: &[u8] = include_bytes!(env!("HALO2_IPA_EXTERNAL_APPROVED_VK"));
```

`tests/fixtures/halo2_ipa_external_chain_v1.hex` の `VK` を抽出したファイルを
環境変数で渡す。canister はこの VK 以外を受け取らない。VK の差し替えには
コード変更・再ビルド・レビューが必要である。

```bash
cd /application
node web/ic-external-circuit/extract-fixture.cjs \
  tests/fixtures/halo2_ipa_external_chain_v1.hex /tmp/ic-external-chain

HALO2_IPA_EXTERNAL_APPROVED_VK=/tmp/ic-external-chain/vk.bin \
  cargo build --locked --release \
    --features halo2-ipa-verify-only,halo2-ipa-params-cache \
    --manifest-path examples/halo2-ipa-external-circuit-ic-verifier/Cargo.toml \
    --target wasm32-unknown-unknown

bash examples/halo2-ipa-external-circuit-ic-verifier/link-canister.sh \
  rustcrypto-ffi/target/wasm32-unknown-unknown/release/halo2_ipa_external_circuit_ic_verifier.wasm
```

`halo2-ipa-verify-only` は外部 crate の verifier-only adapter と
`rustcrypto-ffi` の prover / keygen 除外を有効にする。
`halo2-ipa-params-cache` は同一 canister instance 内の `ParamsIPA` を
thread-local 1 スロットに保持する（heap のみ、upgrade で消える。trusted SRS
ではない）。

### 2.1 シンボルと import の証拠

```bash
wasm=rustcrypto-ffi/target/wasm32-unknown-unknown/release/halo2_ipa_external_circuit_ic_verifier.wasm
/usr/lib/llvm-21/bin/llvm-nm "$wasm"
```

この run の `llvm-nm` 出力は **2 シンボルだけ**:

```text
0007990a T canister_update verify
00079a8b T rustcrypto_halo2_ipa_external_chain_verify
```

- `*_prepare` / `*_prove` / `_pk_validate` / `keygen` / `create_proof` は無い。
- 外部 adapter の `chain_adapter_*` / `linear_*` も export されない
  （`--gc-sections` で未参照のため）。
- wasm imports は `ic0.msg_arg_data_size`、`ic0.msg_arg_data_copy`、
  `ic0.performance_counter`、`ic0.msg_reply_data_append`、`ic0.msg_reply`
  の 5 関数のみ。
- `__getrandom_custom` も export されない。verify 経路は entropy を呼ばず、
  `getrandom` の js backend もリンクされない。

---

## 3. V2 envelope とリクエスト

### 3.1 暗号 artifact

```text
VK:        "RCH2IPV2" | circuit_id u32 BE | k u32 BE | vk_len u32 BE | vk
PK:        "RCH2IPP2" | circuit_id u32 BE | k u32 BE | pk_len u32 BE | pk
proof:     "RCH2IPF1" | proof_len u32 BE | transcript
instances: "RCH2IPI1" | column_count u32 BE |
           column_count * (value_count u32 BE | value_count * Fr(32 BE))
```

`ChainCircuit` fixture の実値:

| 項目 | 値 |
|---|---|
| VK magic | `RCH2IPV2` |
| circuit id / version | `0x10001` / `1` |
| `k` | `6` |
| VK | 158 bytes（payload 138 bytes） |
| proof | 1,452 bytes |
| instances | 560 bytes（1 列 17 値） |
| witness | 512 bytes（16 値） |
| 公開値 | `[acc_1, .., acc_15, input_0, input_15]` |

VK の SHA-256 は
`d1d88261a86fa182c8e290a446d6ae6ac0e4f7923f9df6997aee33ef42f73e29`。
proof の SHA-256（この fixture）は
`1d5ad2f2403fcdf500d4f52535f7c4e5481c09656b4a23e17e119dfc71e85a87`。

V1-magic の VK / PK（旧 Poseidon2 artifact を含む）は外部回路の VK として
受理しない。pinned VK の先頭 8 bytes が `RCH2IPV2` でない場合、canister は
`INVALID_VERIFYING_KEY` (23) を返す。proof は `RCH2IPF1` のみを受理する。

### 3.2 canister リクエスト

```text
arg = proof bytes || instances bytes
```

- proof と instances の分割は、先頭 12 bytes の proof envelope
  （magic + `proof_len`）から決める。
- `proof_len == 0`、`proof_len > 2 MiB`、proof が切り詰め、
  `instances_len == 0` / `> 131,116 bytes`（registry の上限）は
  `INVALID_LENGTH` (9)。
- 引数全体が `2 MiB + 131,116 + 12 bytes` を超える場合は、バイト列を
  `msg_arg_data_copy` する前に `INVALID_LENGTH` (9) を返す。
- proof magic が `RCH2IPF1` でない場合は `INVALID_PROOF_FORMAT` (22)。
- pinned VK の header（magic / circuit id / `k` / payload 長）は proof を
  読む前に検査する。

### 3.3 リプライ

```text
i32 status LE | u64 verifier instructions LE | u32 wasm memory pages LE   (16 bytes)
```

`status == 0` のときだけ検証成功。`verifier instructions` は
`ic0.performance_counter(0)` の verify 呼び出し前後の差分、
`memory pages` は `core::arch::wasm32::memory_size(0)`（1 page = 64 KiB）。

---

## 4. 負例

`web/ic-external-circuit/ic-smoke.cjs` は次の負例を PocketIC 上で実行する。

| 入力 | 結果 (この run) | 意味 |
|---|---:|---|
| 正規 proof + instances | `0` | 検証成功 |
| proof 最終 byte を改変 | `8` | verification failed |
| instances 最終 byte を改変 | `8` | expected 公開値と不一致 |
| `RCH2IPF1` + `proof_len = 0xffffffff` | `22` | 不正 envelope |
| `RCH2IPV1` で始まる artifact | `22` | V1-magic を proof として拒否 |
| VK envelope を request 先頭に置く | `22` | VK 差し替え不可 |
| 最終 instance を 32 bytes の `0xff` | `20` | 非 canonical `Fr` |
| 正規引数の末尾に 1 byte 追加 | `9` | trailing bytes |
| `2 MiB + 1 MiB + 13 bytes`（mock `ic0`） | `9`, copy 前拒否 | oversized |

回路 id は VK 入力ではなくビルド時定数なので、任意の circuit id を試す経路は
存在しない。pinned VK の header 検査で id 不一致を拒否する。witness / prover /
RNG / params の入力経路も無い。

### 4.1 旧（不健全）fixture の拒否

G1 の `acc_0 = input_0` 制約修正で VK / PK / proof が変わった。旧 C2 artifact
（旧 VK SHA-256 `b2638b6e406a221e904223b400067b880a055995a937687eb6e601471d128d3c`、
旧 proof 1,452 bytes）は、この canister では **status 8 で拒否**されることを
PocketIC で確認した。

- 旧 VK はビルド時 VK として pin されていない。canister に VK を渡す入力経路は
  無いため、旧 VK を使うことはできない。
- 旧 proof + instances をそのまま送ると、新しい VK の relation と一致せず
  `VERIFICATION_FAILED` (8) になる（実測）。
- 旧 VK の digest を新しい fixture の digest と取り違えることもない。
  現在 pin しているのは `d1d88261...` である。

---

## 5. 実行と実測

CI スクリプト:

```bash
cd /application
ZKP_RUST_WASM_TARGETS_INSTALLED=1 \
  bash ci/test_halo2_ipa_external_ic.sh /tmp/opencode/halo2-external-ic
```

処理内容:

1. fixture から `vk.bin` / `proof.bin` / `instances.bin` / `witness.bin` を抽出。
2. wasm32-unknown-unknown release で staticlib をビルド（VK pin、verify-only）。
3. `link-canister.sh` で 2 export の wasm を link。
4. `llvm-nm` で verifier symbol の存在、prover symbol の不在を確認。
5. PocketIC に install し、正常系 cold / warm と上記負例を実行。
6. `ic-measurements.json` に wasm、import、cold/warm 命令数、ページ数、
   cycles、負例 status を出力。

### 5.1 実測（2026-11、ローカル PocketIC）

測定環境: Node `v24.22.1`、`@dfinity/pic` 0.25.0、`rustc 1.99.1`、
`opt-level = 3`、fat LTO、`codegen-units = 1`、`strip = "symbols"`、
wasm-ld `-O3 --strip-all --gc-sections`。

| 項目 | cold | warm |
|---|---:|---:|
| status | 0 | 0 |
| `performance_counter` 差分 (instructions) | 3,710,811,005 | 321,001,055 |
| wasm memory | 50 pages / 3,276,800 bytes | 51 pages / 3,342,336 bytes |
| PocketIC update cycles（参考） | 3,721,781,974 | — |
| wasm size | 2,818,919 bytes | 同左 |
| wasm functions（import + defined） | 5 + 569 = 574 | 同左 |
| wasm imports | `ic0` 5 関数のみ | 同左 |
| wasm exports | `memory`, `canister_update verify`, `rustcrypto_halo2_ipa_external_chain_verify` | 同左 |

- cold は `ParamsIPA::new(6)` の決定的な params 生成を含む。
- warm は `halo2-ipa-params-cache` により params を clone するだけで、
  cold の約 1/11.6。キャッシュは同一 canister instance の heap のみで、
  upgrade / reinstall で失われる。単一 `k` スロットである。
- この run の wasm SHA-256:
  `11d73cf53a741020e9f46affadd9e9aa6d52750d46fcc081b78b25e40525b6d0`
  （toolchain / profile 依存）。
- 命令数・cycles は PocketIC / ホスト / 実行時乱数で変動する。性能保証では
  なく、smoke の上限確認である。予算は instructions < 30,000,000,000、
  memory < 512 MiB で判定している。

---

## 6. 制限・明示的な未対応

- **未監査・非保証**。外部監査、mainnet での cycle 実測、本番デプロイは
  行っていない。数値はローカル PocketIC の参考値であり mainnet の
  cycle quote ではない。
- `dfx` による canister ID / controller / upgrade hook / Candid /
  認証 / 課金 / ステート管理は未提供。raw update の install と verify のみ。
- canister は verify 専用で、proving / keygen を含まない。prover は
  browser / client 側の別経路である。
- pinned VK は `ChainCircuit` id `0x10001` / `k = 6` の 1 つだけである。
  `LinearCircuit` や別 `k` を検証するには別 canister のビルドが必要。
- VK の差し替えはコード変更と再ビルドを要求する。V1-magic key との互換経路は
  無い。
- 最終 wasm は `staticlib` を `link-canister.sh` で link する。`cdylib` を
  直接ビルドすると `rustcrypto-ffi` の全 `#[no_mangle]` が export されるため、
  CI / 配布手順は必ず link script を通す。
- 回路変更時は fixture の再生成と VK の再 pin が必要で、不一致は PocketIC
  smoke で検出される。
- params cache は heap の単一スロットで、upgrade をまたがない。cold call の
  コストは残る。
- ブラウザ UI は無い。`web/ic-external-circuit` は Node の smoke /
  measurement のみである。
- codec fuzz / DoS 試験、独立レビュー、release 配布物の sha 固定、
  Nim 静的リンクは未完了である。
