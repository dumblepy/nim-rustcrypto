# リリース成果物と consumer install 検証

このドキュメントは、`rustcrypto` のリリース用 static archive を **隔離した
Nimble 環境へインストールし、consumer が実際にビルド・リンク・実行できるか**を
確認する手順をまとめたものである。リリース公開・監査を完了したという意味では
ない。現時点の成果物は未公開・未コミットであり、個別の SHA-256 で固定して初めて
再現可能な配布物として扱える。

## 1. 対象成果物

Linux x86_64 ホストでビルドする 3 target の static archive が対象である。

| target | archive 名 | 生成元 |
|---|---|---|
| `linux-x86_64` | `librust_crypto_ffi-linux-x86_64.a` | `rustcrypto-ffi/target/release/librust_crypto_ffi.a` |
| `wasm32-unknown-unknown` | `librust_crypto_ffi-wasm32-unknown-unknown.a` | `rustcrypto-ffi/target/wasm32-unknown-unknown/release/librust_crypto_ffi.a` |
| `wasm32-wasip1` | `librust_crypto_ffi-wasm32-wasip1.a` | `rustcrypto-ffi/target/wasm32-wasip1/release/librust_crypto_ffi.a` |

これらは `src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim` により、パッケージ内の
`src/rustcrypto/vendor/rustcrypto-ffi/<target>/` と、`XDG_CACHE_HOME` 配下の
`rustcrypto/ffi/v<version>/<target>/` へコピーされる。`vendor/` は
`.gitignore` 対象であり、リポジトリへ commit しない。

## 2. 検証コマンド

標準の検証は次の 1 コマンドである。

```sh
cd /application
bash ci/test_release_consumer.sh
```

成功時は終了コード `0` を返し、3 archive の SHA-256・サイズ、隔離インストール先、
`rustcrypto_ffi_paths` の解決結果、consumer の実行結果を表示する。失敗時は
非 0 で終了する。デバッグ用に作業ディレクトリを残す場合だけ
`RUSTCRYPTO_RELEASE_CONSUMER_KEEP=1` を付ける。

スクリプトの処理内容:

1. `/application/rustcrypto-ffi` で native / wasm32-unknown-unknown /
   wasm32-wasip1 の `cargo build --locked --release --lib` を実行する。
2. `nim r src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim` で archive を
   package vendor と一時 cache へ同期する。
3. `NIMBLE_DIR` と `XDG_CACHE_HOME` を一時ディレクトリへ向け、
   `/application` をローカルパッケージとしてインストールする。グローバルの
   Nimble 環境は変更しない。
4. インストール済みパッケージに 3 archive が存在し、同期元と SHA-256 が一致する
   ことを確認する。
5. インストール済みパッケージの `resolve_rustcrypto_ffi.nim` を全 target で実行し、
   期待した vendor archive が解決されることを確認する。
6. `example/` を一時ディレクトリへコピーし、隔離 Nimble の依存解決で
   `nimble c` する。解決できない場合のみ、インストール済みパッケージを
   `--path` で明示して `nim c` する。
7. consumer を実行し、`verification: true` を確認する。
8. 終了時に一時ディレクトリを削除する。

### 手動で同等のことを行う場合

```sh
cd /application/rustcrypto-ffi
cargo build --locked --release --lib
cargo build --locked --release --lib --target wasm32-unknown-unknown
cargo build --locked --release --lib --target wasm32-wasip1

cd /application
work="$(mktemp -d /tmp/opencode/rustcrypto-consumer.XXXXXX)"
export XDG_CACHE_HOME="$work/cache"
nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim

# Nimble 0.24.1 は `nimble install /path` を path 依存として扱い失敗するため、
# パッケージのディレクトリで引数なしインストールを行う。
NIMBLE_DIR="$work/nimble" XDG_CACHE_HOME="$work/cache" nimble install -y --offline

pkg="$(find "$work/nimble/pkgs2" -maxdepth 1 -type d -name 'rustcrypto-0.1.14-*' | head -n 1)"
mkdir -p "$work/consumer"
cp -a example/. "$work/consumer/"
cd "$work/consumer"
NIMBLE_DIR="$work/nimble" XDG_CACHE_HOME="$work/cache" \
  nimble c -y --offline --hints:off --warnings:off -o:example src/main.nim
./example
```

`example/example.nimble` の `bin = @["example"]` と `src/main.nim` の組み合わせは
`nimble build` の既定探索と一致しないため、スクリプトと上記手順では
`nimble c src/main.nim` を使う。これは consumer のリンク・実行確認を目的とした
明示的なビルドであり、`nimble build` の成功を主張するものではない。

## 3. 今回の実測値（2026-11-28、`rustcrypto 0.1.14`）

`bash ci/test_release_consumer.sh` の実行で得られた値である。toolchain・ビルド環境
が変わればバイト列も変わり得るため、これは **この実行時点の成果物を固定するための
記録**であり、将来のビルドが同じ SHA になることを保証しない。

| target | size (bytes) | SHA-256 |
|---|---:|---|
| `linux-x86_64` | 58,796,568 | `9640ac77019d1603d30306aa0bebf6405a8775db79abe65e180ee0da679510c9` |
| `wasm32-unknown-unknown` | 35,826,962 | `8b3382d1df4e9a9f67e21b0297967a09d278c854bb8b8059773da1faac0e3544` |
| `wasm32-wasip1` | 34,925,002 | `55df14427f7c391a0759966a4e82d83f5421f5abe672cd42ba2abceef6128a7c` |

consumer の出力は次の形式で、最後の行が `verification: true` であれば成功である。
秘密鍵・署名は毎回ランダムなので値は実行ごとに異なる。

```text
secretKey: [...]
publicKey: 02...
signature: ...
verification: true
```

## 4. 配布物の固定方法

現時点では release asset の公開も commit も行っていない。将来リリースする場合は、
**version と SHA-256 の両方**を固定する。

1. `rustcrypto.nimble` の version を確定する（現在は `0.1.14`）。
2. その version のソースから 3 archive を再ビルドし、本スクリプトで consumer
   install を再検証する。
3. release asset 名を
   `rustcrypto-ffi-v<version>-<target>.tar.gz`、checksum を
   `rustcrypto-ffi-v<version>-<target>.tar.gz.sha256` とする。
   target は `linux-x86_64`、`wasm32-unknown-unknown`、`wasm32-wasip1`。
4. 配布先の checksum を、上の表のような実測 SHA-256 と照合する。

```sh
# 例: ダウンロードした asset の checksum を検証する
sha256sum -c rustcrypto-ffi-v0.1.14-linux-x86_64.tar.gz.sha256
sha256sum -c rustcrypto-ffi-v0.1.14-wasm32-unknown-unknown.tar.gz.sha256
sha256sum -c rustcrypto-ffi-v0.1.14-wasm32-wasip1.tar.gz.sha256
```

`fetch_rustcrypto_ffi.nim` は release asset を version から解決するため、
**同じ version で archive の中身だけを差し替えてはならない**。内容を変える場合は
version を上げ、新しい SHA-256 を固定する。consumer 側では少なくとも
`rustcrypto` の version と、利用する target archive の SHA-256 を lock して扱う。

## 5. Poseidon2 V2 artifact への移行と旧 V1 の拒否

Poseidon2 sponge の未使用吸収レーンと capacity 加算値に対する P0 健全性修正で、
Poseidon2 の VK/PK が変わった。現在の Poseidon2 artifact は次の V2 envelope を
使う。

| 種別 | V2 | 備考 |
|---|---|---|
| Poseidon2 VK | `RCH2IPV2` | cubic id 1 は V1 `RCH2IPV1` のまま |
| Poseidon2 PK | `RCH2IPP2` | cubic id 1 は V1 `RCH2IPP1` のまま |
| proof | `RCH2IPF1` | revision 非依存 |
| instances | `RCH2IPI1` | revision 非依存 |

Poseidon2 は **V2 のみ**をサポートし、V1-magic の Poseidon2 artifact は
受理しない。V1 fixture はリポジトリに含めない。committed fixture
（`halo2_ipa_poseidon2_v1.hex`、`halo2_ipa_poseidon2_arity12_v1.hex`）は V2
である。したがって、consumer が参照する vendor archive も
**P0 修正後の V2 を含むビルドでなければならない**。古い V1 時代の archive を
そのまま使うと、Poseidon2 の VK/PK 検証・proof verify が失敗するか、旧回路を
新回路として扱う危険な状態になる。本スクリプトはビルドした archive とインストール
済み archive の SHA-256 一致を確認するが、archive 内部の V2 magic を個別に
再検査するものではない。Poseidon2 の V1 拒否自体は Rust/Nim のテストで確認する。

## 6. 制約・未完了事項

- この検証は **mainnet への配備、release asset の公開、package registry への
  公開を行っていない**。ローカルの隔離 Nimble 環境での consumer install のみを
  確認した。
- 独立したセキュリティ監査は未実施である。暗号資産・本番用途の安全性を保証
  しない。
- consumer の実行確認は native Linux x86_64 のみである。wasm32-unknown-unknown と
  wasm32-wasip1 は archive の存在・SHA-256・`rustcrypto_ffi_paths` の解決までを
  確認する。wasm 実行そのものは各 wasm smoke（`ci/test_*_wasm.sh`）の責務である。
- 現在の成果物は未公開・未コミットであり、本ドキュメント記載の SHA-256 は
  上記実行環境での記録である。将来のリリースでは version と SHA-256 を必ず
  再取得して固定すること。
