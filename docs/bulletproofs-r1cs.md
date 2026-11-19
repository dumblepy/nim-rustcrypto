# Bulletproofs R1CS / Ristretto255

## 採用 ADR

採用対象は PoC。Cargo の `bulletproofs-r1cs-poc` を明示した開発ビルドで公開する。本番リリースのゲートは汎用 R1CS の健全性、ゼロ知識性、実装監査、依存保守体制、対象ホストでの性能確認。

| 候補 | 判断 |
| --- | --- |
| zkcrypto/bulletproofs 5.0.0 (MIT) | `yoloproofs` は実験段階。公開版では Dalek 4 の `CtOption` と proof parser が非互換 |
| zkcrypto/bulletproofs 5.0.1 (MIT) | 修正を含む `04bce4e66013ff857ed462fd4206210544101461` を PoC に採用。Dalek 4.1.3 と Merlin 3.0.0 を固定 |
| tari_bulletproofs 4.4.1 (MIT) | 汎用 R1CS を持つ。Dalek fork・rand 0.7 系に依存。汎用 R1CS に対する外部監査と WASM 実績を確認できず |
| Tari Bulletproofs+ (BSD-3-Clause) | Quarkslab 監査付きの範囲証明。汎用 R1CS の Prover/Verifier が採用条件 |

暗号プロトコルへのローカルパッチはない。Dalek 4.1.3 は RUSTSEC-2024-0344、Cargo.lock の rand 0.8.6 は RUSTSEC-2026-0097 の修正版。上流の依存 `clear_on_drop` 0.2.5 にはメンテナンス終了の情報アドバイザリ RUSTSEC-2026-0283 がある。上流の Verifier は単一証明の内部検証式をまとめる際にも `thread_rng` を使う。呼び出し API に RNG は不要で、動作環境には OS/ブラウザの CSPRNG が必要。Verifier の計算量は乗算ゲート数に対し線形で増加する。範囲証明の測定値を汎用 R1CS に適用する根拠は確認できていない。

- [zkcrypto ソースと実験用機能の注意](https://github.com/zkcrypto/bulletproofs/tree/04bce4e66013ff857ed462fd4206210544101461)
- [R1CS parser 修正](https://github.com/zkcrypto/bulletproofs/pull/23)
- [Tari R1CS fork](https://docs.rs/crate/tari_bulletproofs/4.4.1/source/Cargo.toml.orig)
- [Tari Bulletproofs+ 監査資料](https://github.com/tari-project/bulletproofs-plus/tree/main/docs/quarkslab-audit)
- [Dalek の RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2024-0344.html)
- [clear_on_drop の RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0283.html)
- [rand の RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0097.html)

## v1 プロファイル

`bulletproofs-r1cs-ristretto255-v1` は一相 R1CS。スカラーは Ristretto255 の群位数 ℓ = 2²⁵² + 27742317777372353535851937790883648493 未満の 32 バイト little-endian。点は 32 バイトの正準 compressed Ristretto。外部コミットメントと proof に現れる点は、展開でき、かつ identity 以外であることを要求する。公開入力と witness は順序付きスカラー列で、整数としての意味は回路で決まる。

Pedersen の値生成器は Ristretto 基点。blinding 生成器はその圧縮表現を SHA3-512 に通した Ristretto hash-to-group。Bulletproofs の二つの生成器列は、SHAKE256 の入力 `GeneratorsChain || label` から 64 バイトずつ読み出して `RistrettoPoint::from_uniform_bytes` に渡す。ラベルはそれぞれ `G || LE32(0)` と `H || LE32(0)`。party 数は 1。回路に必要なゲート数を 2 の冪に切り上げて列の prefix を使う。最大 1024 ゲート。生成器は再計算できるため wire に含めない。[固定リビジョンの生成器実装](https://github.com/zkcrypto/bulletproofs/blob/04bce4e66013ff857ed462fd4206210544101461/src/generators.rs)

Merlin の初期ラベルはプロファイル名。以下を順に追加して上流 Prover/Verifier に渡す。Merlin が各メッセージの長さをフレーミングする。

| ラベル | 値 |
| --- | --- |
| `proof-system-version` | `append_u64(1)` |
| `circuit-id` | 承認済み回路の全バイト列の SHA-256 |
| `generator-profile-hash` | ASCII `zkcrypto-bulletproofs-v5.0.1/default-pedersen/chain-v1/n1024/parties1` の SHA-256 |
| `application-context` | 呼び出し側指定の最大 1024 バイト |
| `public-inputs` | 正準スカラーの連結。回路が個数を固定 |
| `commitment-count` | `append_u64` でコミットメント個数 |

上流の R1CS ドメイン分離に続き、順序付きコミットメントごとに `V` メッセージを追加する。ネットワーク、用途、セッションを識別したい呼び出し側は、曖昧性のない文脈エンコードを指定する。リプレイ防止に使うセッション ID は呼び出し側で発行と使用済み状態を管理する。異なる回路編成、生成器導出、transcript 変更には新しい回路 ID またはプロファイル番号が必要。

## 回路とガジェット

検証アプリが信頼済み設定や組み込みリソースから回路を選び、`CircuitDefinition::from_bytes` / `BulletproofsR1cs.loadCircuit` に渡す。証明が提供する ID は一致確認に使う。回路の処理順序はファイル順。

回路エンコードは `BPC1`、公開入力数、witness 数、commitment 数、行数の順。数値の幅はすべて LE u16。後続する各行は `A * B = C` の三つの線形結合で、それぞれ LE u16 の項数と、その個数分の `LE u16 変数番号 || 正準スカラー係数`。番号は昇順で重複せず、係数は非ゼロ。空結合は 0。番号 0 は定数 1、続いて公開入力と witness の順。先頭の指定個数の witness に Pedersen コミットメントを付ける。残りの witness は 2 個ずつ内部ゲートに割り当てる。各行を 1 乗算ゲートと出力等式に変換する。回路には 1 個以上の witness と 1 行以上の制約が必要で、commitment 数は witness 数以下。

| 項目 | 上限 |
| --- | ---: |
| 回路バイト数 | 262,144 |
| 公開入力 | 128 |
| witness | 1024 |
| commitment | 64 |
| 回路の行数 | 512 |
| 乗算ゲート | 1024 |
| proof 本体 | 1057 |
| proof envelope | 3147 |

`examples/support/bulletproofs_fixture.rs` に固定 statement/witness とガジェットの組み立て例がある。

- 等式は `A * 1 = B`。積は `A * B = C`。この二つはスカラー体上の関係。
- 32/64/128 ビット範囲では各ビットに `b * (b - 1) = 0`、値に `Σ 2ⁱbᵢ = value` を課す。
- bounded sum は両被加数と結果を個別に範囲拘束する。128 ビット以下の二項和は ℓ より小さいため、等式の整数解釈が保存される。整数の積を扱う場合は、積の上限が ℓ 未満になるよう両因子を拘束し、必要に応じて結果も範囲拘束する。
- 既存 Pedersen コミットメントの開示知識を証明する場合は、秘密 witness と元の非ゼロ blinding を渡す。検証者は独立に取得した順序付きコミットメントを `verify_with_commitments` / `verifyWithCommitments` に渡す。通常の `verify` は envelope のコミットメントを statement として検証する。
- 固定ハッシュ関数の Merkle ガジェットは未実装。

## Wire と FFI

envelope は `BPPF || version:u8=1 || profile:u8=1 || circuit-id:[32] || commitment-count:u16LE || proof-length:u16LE || proof-body || commitments`。順序付き公開入力は別バッファとして渡す。proof-body は上流の一相 `R1CSProof::to_bytes()` で、第 1 バイトは 0。長さは `1 + 32 × (13 + 2 × log₂(ceil_pow2(gates)))`。ヘッダは 42 バイト。回路・proof とも末尾の追加バイトを拒否する。単体の形式検証はエンコードを検査する。証明の検証では、公開入力とコミットメントが回路の要求する個数と一致することも確認する。

`rustcrypto_bulletproofs_r1cs_prove` の引数は circuit、public、witness、blindings、context の順にポインタと長さ、その後に出力ポインタと容量。空の blindings は CSPRNG を選択する。成功時に書き込んだバイト数、失敗時に負値を返す。呼び出し側が出力バッファを確保する。最大容量 3147 バイトで全回路を扱える。

`rustcrypto_bulletproofs_r1cs_verify` は circuit、public、context、proof の順にポインタと長さを取り、有効なら 1、数学的に無効または回路 ID が異なるなら 0、形式エラーなら負値を返す。`rustcrypto_bulletproofs_r1cs_validate` は対象を示す u32 とポインタ・長さを取り、成功時は 0。対象番号は 0 が proof、1 が公開入力、2 が commitments、3 が回路。C ABI では長さ・容量は `size_t`、戻り値は `int32_t`。

| 値 | 意味 |
| ---: | --- |
| -1 | 非正準形式、未知のバージョン、切り詰めなど |
| -2 | プロファイル上限超過 |
| -3 | 個数の不一致または不正な回路個数 |
| -4 | 制約を満たさない witness |
| -5 | blinding 生成時の CSPRNG エラー |
| -6 | 上流エラーまたは捕捉可能な panic |
| -7 | NULL、アドレス範囲のオーバーフロー、出力容量不足 |

入力が空なら NULL を許容する。呼び出し側が非空バッファを指すポインタの有効性と、宣言した長さの読み書きを保証する。Rust が参照を生成する前に NULL、長さ、アドレス演算を検査する。FFI 実行中に他スレッドからバッファを書き換えない。入力の witness と blindings の所有権は呼び出し側にあり、Rust 側のデコード済み witness と一時 blinding は best-effort で消去する。上流の内部一時領域やランタイムのコピーを含めた完全な消去は未検証。JS の `prove` と `proveWithBlindings` は返却時に引数の秘密バッファを消去する。WASM のトラップ時は Worker の `finally` で秘密配列を消去する。

## API の使用例

Rust の `CircuitDefinition` は回路バイト列を一度パースして再利用できる。公開入力、witness と proof の各スライスを対応する型に包んで呼び出す。

```rust
use rust_crypto_ffi::bulletproofs_r1cs::{CircuitDefinition, Proof, PublicInputs, Witness};

let circuit = CircuitDefinition::from_bytes(approved_circuit_bytes)?;
let proof = circuit.prove(PublicInputs(public_bytes), Witness(witness_bytes), context)?;
let valid = circuit.verify(PublicInputs(public_bytes), context, Proof(&proof))?;
```

Nim では公開入力・witness・開示用 blinding・コミットメントを個別の 32 バイト型で渡す。`loadProof` は受信した envelope を検査してから証明型に変換する。

```nim
import rustcrypto

let circuit = BulletproofsR1cs.loadCircuit(approvedCircuitBytes)
let proof = BulletproofsR1csProver.prove(circuit, publicInputs, witness, context)
let outgoing = proof.toBytes
let received = BulletproofsR1cs.loadProof(outgoing)
let valid = BulletproofsR1cs.verify(circuit, publicInputs, context, received)
```

JS は wasm-bindgen のモジュールを初期化し、各入力を `Uint8Array` で渡す。`prove` が返す envelope を `verify` へ渡せる。`proofCommitments` は構造検証済みの連結コミットメントを取得する。Worker では生成時に `{ circuit, publicInputs, witness, context }`、検証時に `{ circuit, publicInputs, context, proof }` を送信する。既存開示を使う生成では `blindings`、独立に取得したコミットメントを照合する検証では `expected` を追加する。Worker は `{ result, metrics }` または `{ error }` を返す。

## ビルドと測定

| 対象 | CI / サポート範囲 |
| --- | --- |
| Linux x86_64 | Rust、C ABI、Nim PoC |
| macOS arm64 | 既存ライブラリの CI。PoC 未検証 |
| wasm32-unknown-unknown | Node 24 と Chromium の module Worker。Web Crypto が利用できる secure context が必要 |
| wasm32-wasip1 | Node 24 の WASI Preview 1 で Rust Verifier を起動 |

テストには Rust stable、Clang の wasm32 対応版、Nim 2.2、Node 24、Python 3、wasm-bindgen-cli 0.2.129、既存 Web テストと同じ Playwright/Chromium が必要。`web/groth16-prover` で `npm ci` と `npx playwright install chromium` を実行し、リポジトリルートから `./ci/test_bulletproofs_r1cs.sh` を実行する。任意の第一引数は成果物の出力先。WASM、生成された証明、測定 JSON/CSV、peak RSS、測定環境を出力する。Cargo は `--locked` を使用し、試験用 Cargo target ディレクトリを分離する。Nim は `-d:rustcryptoBulletproofsR1csPoc -d:rustCryptoBulletproofsArchive=/.../librust_crypto_ffi.a` で同じ実験ビルドを選ぶ。

各ケースは warmup 1 回と測定 10 回の平均。生成器構築・proof エンコード/デコードを含む。generator_bytes は圧縮表現に換算したサイズ。payload_bytes は proof envelope と別送の公開入力を合わせたバイト数。アプリ文脈はホスト側で別途指定するため含めない。peak RSS は全ケースを回す native プロセスの値。WASM の測定は乗算ケースのスモーク試験 1 回で、linear memory・バイナリサイズ・SHA-256 を記録する。WASI 命令数は Node のホストから取得していない。

ブラウザで生成する際は、同じ origin から `worker.mjs` と wasm-bindgen の `pkg/` を配信し、CSP で `worker-src 'self'` と `script-src 'self' 'wasm-unsafe-eval'` を許可する。Worker へ witness/blindings の `ArrayBuffer` を transfer できる。時間制限はホスト側で Worker を終了して適用する。

### 統合試験での実測値

Ubuntu 26.04.1 LTS / Linux x86_64、AMD EPYC、Rust 1.99.1 の release ビルド。Native は warmup 1 回、測定 10 回。サイズの単位は byte、時間の単位は ms。

| ケース | 行数 | ゲート | proof 本体 | コミットメント | 公開入力 | payload | 生成器 | Prover | Verifier |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| range32 | 33 | 49 | 801 | 32 | 0 | 875 | 4160 | 18.079 | 4.649 |
| range64 | 65 | 97 | 865 | 32 | 0 | 939 | 8256 | 38.278 | 8.266 |
| range128 | 129 | 193 | 929 | 32 | 0 | 1003 | 16448 | 66.938 | 14.060 |
| sum32 | 100 | 149 | 929 | 64 | 0 | 1035 | 16448 | 65.678 | 14.662 |
| sum64 | 196 | 293 | 993 | 64 | 0 | 1099 | 32832 | 127.170 | 26.767 |
| multiplication | 2 | 2 | 481 | 64 | 64 | 651 | 192 | 1.699 | 0.726 |

Native の peak RSS は 12,288 KiB。WASM は同じ乗算回路のスモーク試験 1 回。WASI の時間は起動とファイル読込を含む。

| ホスト | Prover (ms) | Verifier (ms) | Linear memory (byte) | WASM (byte) |
| --- | ---: | ---: | ---: | ---: |
| Node v24.22.1 | 11.41 | 18.47 | 1,310,720 | 7,649,882 |
| Chromium Worker 158.0.8127.18 | 10.40 | 14.40 | 1,310,720 | 7,649,882 |
| Node WASI Preview 1 | — | 17.72 | 1,310,720 | 5,753,934 |

- Browser WASM SHA-256 `9351cc35ad8a8dc197ce690e9b81b45df2e6b87091ab7385953636be1dca3072`
- WASI WASM SHA-256 `5e3dd3f0cf34c045c791f188df09b489e48f0aa112e04b4d28633fdc9108270e`
