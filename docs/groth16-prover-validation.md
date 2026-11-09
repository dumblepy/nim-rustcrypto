# Groth16 prover 検証記録

2026-11-09、Linux x86_64 / Ubuntu 26.04.1、Rust release build、Nim 2.2.12、
Node 24.22.1、Chromium 158.0.8127.18、wasm-bindgen 0.2.129、PocketIC (`@dfinity/pic` 0.25.0)。
暗号監査や本番回路のベンチマークではない。

## テスト

- `cargo test --release`: 既存 unit tests 156 件成功。
- `cargo test --release --test groth16_prover`: 新規 integration tests 6 件成功。
- `nimble test -y`: 全テスト成功。新規 prover テストを `test_algorithm.nim` に登録。
- Nim prover 単独テスト: setup/prove/既存 Verifier、Poseidon commitment、異常入力、
  caller-owned witness 消去の 4 件成功。
- `ci/test_groth16_web.sh`: 一時 setup → Chromium/Node proof 生成 → WASI 検証 →
  PocketIC 検証を実行。browser bridge 分離後にも browser/Node/WASI/IC の実行を再確認。
- browser では誤 witness の拒否、同一 witness で異なる proof、Web Crypto 故障時の拒否、
  native setup/prove C ABI が browser WASM に存在しないことを確認。
- WASI/PocketIC は browser proof を受理し、公開入力を変更すると拒否。
- Rust は全 Poseidon arity 1..12 の複数ベクトルと既知ベクトル、public inputs の順序、
  異なる VK/回路、PK の長さ/個数爆弾、前方参照、乱数失敗、u64/u128 和の overflow、
  非正規 Fr、誤 PRF secret/context、Merkle direction=0/1/2 を確認。
  depth=32 の Merkle 回路がビルダーの上限内で構築・デシリアライズできることも確認。
  depth=32 全体の proof 生成時間は未測定。

## 小規模デモ実測

回路は `secret * secret = public`、secret=3 / public=9。
回路 42 bytes、PK 1102 bytes、VK 588 bytes、proof 256 bytes。
setup、ネットワーク取得、WASM 初期化を prove 時間に含めない。
各 1 回の観測値であり、p95 や異なる端末の保証ではない。

| 実行環境 | prove / verify 時間 | メモリ |
|---|---:|---|
| Rust native prove | 9.97 ms | 単独プロセス peak RSS 12092 KiB |
| Nim native prove | 10.61 ms | 単独プロセス peak RSS 12248 KiB |
| Chromium prove | 81.4 ms | WASM linear high water 1245184 bytes |
| Node prove | 80.84 ms | WASM linear high water 1245184 bytes / 単独プロセス peak RSS 80540 KiB |
| WASI verify (Node WASI) | 49.27 ms | WASM linear high water 1310720 bytes |
| ICP verify (PocketIC update) | 134004615 instructions | WASM linear high water 1245184 bytes |

Chromium のプロセスツリー RSS を 10 ms 間隔で合算した観測最大値は **385096 KiB**。
共有ページの重複と初期化・ページ表示を含むサンプリング値で、真の private peak memory ではない。
WASM linear high water もホストの peak RSS とは別の指標。

PocketIC update 前後の cycles 残高差は **141523373 cycles**。
これは検証本体に加え ingress/execution 等を含むローカル設定の消費で、mainnet の価格ではない。
測定用 canister は VK をビルド時に固定し、ユーザーから VK を受け付けない。

## 再現

Browser/Node/WASI/ICP はルートで `./ci/test_groth16_web.sh`。
測定値とランダム生成された開発用鍵は、最後に表示される一時ディレクトリに残す。
`measurements.json` と `ic-measurements.json` が機械可読の結果。
鍵と成果物を本番リリースにコピーしない。

native 測定は、Rust 作業ディレクトリで
`cargo build --release --example groth16_prover_bench` を実行した後、ルートで
`python3 ci/measure_process.py /tmp/native.json rustcrypto-ffi/target/release/examples/groth16_prover_bench /path/to/artifacts`。
Nim はルートで
`nim c -d:release --path:src -o:/tmp/nim-prover-bench ci/groth16_prover_bench.nim`、
`python3 ci/measure_process.py /tmp/nim.json /tmp/nim-prover-bench /path/to/artifacts`。

暫定 smoke 閾値は prove/verify 30 秒、WASM linear memory 256 MiB、
IC verifier 20 億 instructions。大きな回路、Worker の中断、モバイル、実 canister、
独立した MPC ceremony と完全な秘密消去の評価は本番アプリ側のリリース審査で行う。
[ADR の制約とレビュー条件](adr/0070-groth16-prover.md) を参照。
