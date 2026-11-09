# Groth16/BN254 proof 生成

Nim native: `rustcrypto/algorithm/groth16_prover`。
Rust: `rust_crypto_ffi::groth16_prover`。
Browser/Node: `web/groth16-prover` の WebAssembly bridge。

```nim
import rustcrypto/algorithm/[bn254, groth16, groth16_prover]

var circuit = Groth16Bn254Prover.circuit(publicCount = 1, privateCount = 1)
let secret = circuit.privateInput(0)
let square = circuit.mul(secret, secret)
circuit.enforceEqual(square, circuit.publicInput(0))

# 開発用 single-party setup。本番では承認済み回路と監査済みの鍵配布を使う。
let keys = Groth16Bn254Prover.setup(circuit)
let nine = fromHexFr("0000000000000000000000000000000000000000000000000000000000000009")
let three = fromHexFr("0000000000000000000000000000000000000000000000000000000000000003")
let proof = Groth16Bn254Prover.prove(circuit, keys.provingKey, [nine], [three])
doAssert Groth16Bn254.verify(keys.verifyingKey, proof, [nine])
```

public/private input の順番はビルダーで指定した slot 順。
`add`, `mul`, `constant`, `enforceEqual`, `poseidon`, `select`, `enforceRange`,
`boundedSum`, `merkleRoot`, `prf` を組み合わせる。
すべての公開結果を `enforceEqual` で拘束する。ビルダーはアプリの承認方針を推測しない。
値保存では入力群と出力群を各々 `boundedSum(..., 64)` または 128 bit で計算して等値拘束する。
秘密値→公開 commitment/Nullifier には用途別 domain の `prf` を使い、出力を公開入力に拘束する。
この PRF は楕円曲線上の公開鍵生成 API ではない。

`setup` は caller-owned buffer に鍵を書き、`prove` は 256-byte proof を返す。
Nim は不正 witness、回路不一致、非正規 field、乱数失敗を `ValueError` として扱う。
上限は public/private 各 256、命令 1024、制約 32768、PK 16 MiB。
内部の一時 witness は消去する。呼出元が所有する witness 配列は
`Groth16Bn254Prover.clearWitness(witness)` で使い終わった直後に消去する。
この処理は volatile write を使うが、それ以前に作った別のコピーまでは消去しない。
C ABI の引数と callback は `ffi.nim`、フォーマットと信頼境界は
[ADR 70](adr/0070-groth16-prover.md) に定義している。

## ブラウザ・Node・WASI・ICP の実行

必要なもの: Rust と wasm32-unknown-unknown/wasm32-wasip1 target、wasm 対応 clang、
Node 22 以上、wasm-bindgen-cli **0.2.129**、Playwright の Chromium 実行依存。
`cargo install --locked wasm-bindgen-cli --version 0.2.129` で CLI を入れる。

リポジトリのルートで `./ci/test_groth16_web.sh` を実行する。
setup の成果物は毎回 mktemp に生成し、リポジトリや配布 archive に含めない。
独自回路の開発用 setup は、Rust 作業ディレクトリから
`cargo run --release --example groth16_prover_setup -- /tmp/keys /path/to/circuit.bin`
で行う。回路ファイルは Nim の `circuit.toBytes()` または Rust の `Circuit::to_bytes()` で出力する。
スクリプトは以下を実行する。

1. OS CSPRNG を使う開発用 setup。回路/PK/VK と SHA3-256 manifest を生成。
2. ブラウザ専用 WASM bridge をビルドし、Chromium で witness=3/public=9 の proof を生成。
3. 同じ入力でも proof が毎回変わること、不正 witness を拒否することを確認。
4. WASI に既存 Verifier をリンクした実行ファイルで、browser proof と Node proof を検証。
5. 承認済み VK をビルド時に固定した IC adapter を PocketIC にインストールし、
   browser proof の検証と公開入力改変の拒否を確認。命令数と update cycles の差を記録。

`index.html` を手動で使う場合は、`pkg/` と `artifacts/` を同じディレクトリの配下に置き、
localhost の HTTP サーバーで配信する。秘密 witness をサーバーに送る endpoint はない。
本番 UI は専用 Worker 内で実行し、終了時に Worker を破棄する構成を推奨する。
JS bridge 自体は setup・固定 seed・任意 VK 承認 API を公開しない。

IC サンプルは `examples/groth16-ic-verifier`。Verifier の既存ソースを直接参照し、
prover やランダム生成器を canister にリンクしない。
`GROTH16_APPROVED_VK=/absolute/path/vk.bin` をビルド時に必須とし、未指定ならビルドに失敗する。
update `verify` は **raw bytes** (`proof[256] || publicInputs[32*n]`) を受け取り、
`status i32 LE || instructions u64 LE || memoryPages u32 LE` を返す。
Candid/ICRC/送金 API ではなく、アプリ側で承認済み root、nullifier の一意性、
再実行防止、呼出元の権限、状態更新を別途実装するための最小例である。

## 検証と本番の境界

[実測と再現コマンド](groth16-prover-validation.md)、[ADR](adr/0070-groth16-prover.md) を参照。
単独 setup、未監査のビルダー、ライブラリ内部までの完全な秘密消去未保証を含む。
この追加だけで本番の Shielded UTXO 回路・ceremony が完成したとは扱わない。
