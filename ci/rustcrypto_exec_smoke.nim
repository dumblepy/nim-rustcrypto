## CI 用: 各種 CPU / OS（またはクロスコンパイル先）で、rustcrypto を import した Nim が
## **実行に成功する**こと（FFI 静的リンク・ランタイム）を最小限で検証する。
## 中身は SHA-256 の既知ベクトル 1 件のみ。WASI 専用ではなく、ワークフロー側で
## `nim r`（ホスト実行）や `nim c`（例: wasm32-wasip1 + WASI SDK）など、検証したい
## 環境に合わせて起動方法を選ぶ。
import rustcrypto/algorithm/sha256

proc main() =
  doAssert sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

when isMainModule:
  main()
