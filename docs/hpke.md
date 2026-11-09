# HPKE 非対話公開鍵暗号化

`Hpke` は受取人の公開鍵だけで暗号化する RFC 9180 Base mode の単発 API。
受取人の秘密鍵や対話的な鍵共有は送信側に不要。アプリ固有の Note schema は含まない。
Base mode は送信者の本人性を認証しない。リプレイ防止と復号後の commitment 再計算・照合はアプリの責任。

## 固定プロファイルと wire format

| 項目 | 値 |
| --- | --- |
| モード | Base (`0x00`) |
| KEM | DHKEM(X25519, HKDF-SHA256), `0x0020` |
| KDF | HKDF-SHA256, `0x0001` |
| AEAD | ChaCha20-Poly1305, `0x0003` |
| 公開鍵 / 秘密鍵 | 各32バイト、RFC 7748 の raw encoding |
| 暗号文 | `enc[32] || ciphertext[plaintext.len] || tag[16]` |
| オーバーヘッド | 48バイト |
| 最大平文 | 16 MiB |
| 最大 info / AAD | 各1 MiB |

suite とプロファイルのバージョンはこの API に固定し、wire 自体には含めない。
保存時にアプリの envelope に `protocol_version` とプロファイル識別子を記録する。
異なるスイート・将来バージョンを推測して復号しない。
公開鍵と `enc` は little-endian の整数 `u < 2^255-19` に制限し、最上位ビットが立った値や非正規表現を拒否する。
これは RFC 7748 の緩い入力受理より厳格なプロファイル。
低位点は KEM の全ゼロ DH 出力検査により拒否する。
秘密鍵は RFC 7748 の clamping に従う32バイトで、ゼロを含む任意の32バイトは入力として有効だが、鍵生成には必ず CSPRNG を使う。

呼び出しごとに OS CSPRNG から新しい ephemeral key を生成し、新しい HPKE context の sequence number 0 で一度だけ暗号化する。
nonce は RFC 9180 の key schedule から導出され、wire に追加しない。
利用者が nonce、ephemeral key、sequence number を指定する API は提供しない。
KEM/KDF のラベルと suite ID によるドメイン分離は RFC 9180 の実装に委ねる。

## Nim

```nim
import rustcrypto/algorithm/hpke

var sk = Hpke.generateSecretKey()
let pk = Hpke.publicKey(sk)
let info = @[byte 0x6e, 0x6f, 0x74, 0x65] # アプリの用途を識別
let aad = @[byte 1, 2, 3] # 実際には下記フィールドの正規エンコード
let wire = Hpke.seal(pk, @[byte 10, 20], aad, info)
let plaintext = Hpke.open(sk, wire, aad, info)
Hpke.clearSecretKey(sk)
```

`import rustcrypto` からも利用できる。失敗時は秘密情報を含まない status の `ValueError` を送出する。
空の平文・AAD・info をサポートする。

`info` は例えば用途名・プロトコルバージョンから構成し、同じ受信鍵を使う別用途を分離する。
AAD には少なくとも `protocol_version, pool_id, asset_id, commitment, output_index` を入れる。
フィールド順序、整数の幅とエンディアン、可変長フィールドの長さをアプリで一意に定義する。
単なる可変長文字列の連結は避ける。info と AAD の両方で送受信側のバイト列が完全一致する必要がある。
AAD は暗号文に含まれず、秘匿もされない。保存・再構成方法を別途定義する。

## 鍵分離・バックアップ

支出鍵とは独立に `generateSecretKey` で受信用の鍵を作り、秘密鍵を安全なクライアント側の鍵保管領域にバックアップする。
本 API は支出鍵やマスターシードからの導出方式を定義しない。支出鍵の直接流用を避け、導出を追加するなら別途レビューされたドメイン分離仕様を定める。
受信秘密鍵を canister、サーバー、ログに渡さない。
鍵を失うと過去のメモを復号できない。受信秘密鍵の漏洩は保存済み暗号文の秘匿性にも影響する。
鍵ローテーション時は過去の鍵とプロファイルの対応をバックアップする。

Rust 側は x25519-dalek の `zeroize` feature を明示的に有効化し、秘密鍵・DH shared secret の upstream の zeroize-on-drop と、復号作業領域の `Zeroizing` を利用する。
`clearSecretKey` は渡された Nim バッファを最適化で除去されない方法で消去する。
Nim の値渡し・配列コピー、アプリが保持する平文、upstream 内部の全スタック一時値まで消去できる保証はない。
鍵のコピーを最小限にし、各コピーと復号後平文の寿命を管理する。

## C ABI

宣言は [hpke.h](hpke.h)。長さは `size_t`、戻り値は既存の RustCrypto status code。
全バッファは呼び出し元が所有する。Rust が確保した領域の所有権は返さない。
成功時の書き込み長は鍵32、seal `plaintext_len+48`、open `sealed_len-48`。
出力容量は必要量以上を渡せる。エラー時は出力を変更せず、認証前の平文を返さない。
空入力は NULL を許し、空平文への復号出力も NULL / 0 を許す。
seal/open/publicKey の入力と出力の重なりは許す。すべての非空バッファは指定長に対して有効でなければならない。
不正なアドレスそのものを検証することはできない。
サイズ検査と panic 捕捉を行うが、プロセスのメモリ不足による abort は捕捉対象外。
乱数取得失敗は `19`、認証失敗・誤鍵・異なる context は `11`、不正な公開鍵は `5`、その他の長さ・ポインタ検査は既存 status に従う。

## 依存実装の評価

[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) のプロトコルを独自実装せず、
[rust-hpke](https://github.com/rozbb/rust-hpke) `0.13.0`（MIT / Apache-2.0）を採用した。
採用バージョンの README は正式な監査を受けていないと明記し、Cloudflare による旧 `0.8` の内部レビューを紹介している。
この履歴は今回のバージョンや FFI 全体の監査を意味しない。
最新 `0.15.1` も評価対象としたが、x25519-dalek 3 / chacha20poly1305 0.11 / rand_core 0.10 への依存移行を伴うため、
既存の x25519-dalek 2 系周辺・ChaCha20-Poly1305 0.10 と合わせた `0.13` 系を使用する。
保守・更新状況は upstream で継続確認し、依存更新時は固定ベクトルと相互運用テストを再実行する。

## 検証と実行

独立ベクトルは [CFRG HPKE test-vectors.json](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json)
の `(mode, kem_id, kdf_id, aead_id) = (0,32,1,3)`、最初の暗号化レコード。
`tests/fixtures/hpke/base.json` に該当レコードを保存している。含まれる秘密値は公開テストデータであり実運用に使わない。
単発 API のため sequence number 1 以降のレコードは対象外。

```sh
cd /application/rustcrypto-ffi
cargo test --locked hpke --lib
cargo build --locked --release --lib
cd /application
cp rustcrypto-ffi/target/release/librust_crypto_ffi.a src/rustcrypto/vendor/rustcrypto-ffi/linux-x86_64/librust_crypto_ffi-linux-x86_64.a
nim c -r tests/algorithm/test_hpke.nim
bash ci/test_hpke_web.sh
```

Browser テストは別実装 [hpke-js](https://github.com/dajiaji/hpke-js) と実際の Chromium / Manifest V3 extension worker を使用し、
Nim/Rust → JS、JS → Nim/Rust、公式ベクトル、乱数による鍵生成、改ざん拒否を確認する。
モバイルは Chromium の端末エミュレーションのみ。実機 iOS / Android / React Native は未検証。
wasm32-unknown-unknown / wasm32-wasip1 は Rust のコンパイル確認を別途行う。
ブラウザで Rust WASM 版を実行したとの主張はせず、今回のブラウザ実動作は JS 実装との相互運用を対象とする。
wasip1 の乱数 API が実際の canister で使えるとは限らず、受信秘密鍵を持つ処理を canister に配置しない。
