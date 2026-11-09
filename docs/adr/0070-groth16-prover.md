# ADR 70: Groth16/BN254 の回路と証明生成

状態: 実装。暗号監査前であり、本番運用の承認を意味しない。

## 境界と採用理由

Verifier (`groth16.rs` / `Groth16Bn254`) の v1 proof、VK、public inputs を変更せず、
別モジュール `groth16_prover` / `Groth16Bn254Prover` を追加する。
C ABI は `groth16_prover_ffi.rs` に分離し、Browser は共通コアのソースだけを共有する。
Browser artifact に native setup/prove C ABI が含まれないことを実行時に検査する。
汎用の型付き命令ビルダーを採用する。任意 Rust コード、JS callback、witness に依存する
分岐を回路として登録しない。回路定義に public/private input の個数と演算を固定し、
setup と prove で同じ `ConstraintSynthesizer` を使う。アプリの承認済み回路・VK レジストリは
このライブラリの外に置く。生の snarkjs/zkey/arkworks PK は受け付けない。

Rust の `Circuit` は不透明な内部表現と `Wire` を提供し、Nim も同じ演算を構築できる。
public inputs、private inputs、命令の結果を順に slot に割り当てる。
先行 slot のみ参照可能。private witness は canonical BE Fr の配列であり、slot の個数と順序が
一致しなければ失敗する。入力値によって制約数・回路を変えない。

## 回路形式 RCCIR01

すべての整数は BE。

| フィールド | 形式 |
|---|---|
| magic | `RCCIR01\0` (8 bytes) |
| public / private / operation count | 各 u32 |
| operation | tag u8, aux u8, argument count u8, slot indices u32[] |
| constant operation の追加データ | canonical BE Fr 32 bytes |

| tag | 引数 | 意味 |
|---|---|---|
| 0 | 0 | 定数。aux=0 |
| 1 | 2 | 加算。結果を新しい変数に拘束 |
| 2 | 2 | 乗算 |
| 3 | 2 | 等値を拘束。結果 slot は左辺と同じ |
| 4 | 1..12 | Poseidon。aux=0 |
| 5 | 1 | aux=1..128 bit の範囲制約。結果 slot は入力と同じ |
| 6 | 3 | selector, yes, no。selector を 0/1 に拘束 |

tag 1..4,6 の aux は 0。余剰 bytes、未知 tag、引数数不一致、非正規定数、前方参照を拒否する。
回路は最大 64 KiB、public/private 各 256、命令 1024、生成する制約 32768 以下。
構築時に保守的な演算コスト上限も設け、合成後にも制約数を検査する。
ビルダーがエラーを返した回路は破棄して再構築する。

## Poseidon と標準部品

`light-poseidon` 0.4.1 `bn254_x5` の公開パラメータを直接再利用する。
BN254 Fr、width=arity+1、arity=1..12、x^5、full rounds=8、width ごとの partial rounds、
round constants、MDS、初期 state `[0, inputs...]`、最終 state[0] を固定する。
Circom と同じゼロ domain tag であり、任意 domain tag の切り替えは公開しない。
アプリの PRF は固定した非秘密 domain を **第一メッセージ要素** に置く
`Poseidon([domain, secret, context])`。domain tag と第一入力は別概念である。
同一の domain を鍵導出・nullifier・commitment で使い回さない。
秘密値から公開 commitment を導く場合も `prf` の出力を承認された public input に等値拘束する。
これは楕円曲線の公開鍵導出や署名検証の代用品ではない。

Merkle の direction=0 は current を左、1 は右に置く。すべての direction を真偽値に拘束。
`merkleRoot` の結果は呼出元が承認済み root に等値拘束する。
leaf/hash スキーマ、tree depth、空 leaf、ドメイン分離はアプリが回路に固定する。

range は canonical な Fr ビット分解の上位ビットをゼロに拘束する。
`boundedSum` は各入力と各中間和の両方を指定ビット幅に拘束する。
幅は最大 128 bit で 2 項の和は Fr modulus より小さく、field wraparound による価値保存偽装を防ぐ。
入出力の boundedSum を等値拘束して初めて価値保存となる。
回路に authorization や membership を追加しなければ自動的には成立しない。

## 鍵形式 RCPK01 と承認

magic `RCPK01\0\0` (8 bytes)、回路長 u32 BE、RCCIR01 回路そのもの、続いて
arkworks 0.5 の **検証あり compressed point encoding** を保存する。
VK は alpha G1、beta/gamma/delta G2、gamma_abc G1[] の順。
残りは beta G1、delta G1、a G1[]、b G1[]、b G2[]、h G1[]、l G1[] の順。
配列は u32 BE 個数に続く点の列。arkworks の Vec serialization は使わない。
最大 16 MiB、各配列の個数は最大 65536、残り bytes との関係も確保前に検査する。
点は subgroup/canonical 検査ありで読む。回路 bytes、入力個数、query 配列長、末尾を厳密に検査する。
証明生成後も組み込まれた VK で検証し、不整合な PK の proof を出力しない。
同じ回路でも別 setup の VK に対して互換な証明になるわけではない。

外部 setup ツール `groth16_prover_setup` は開発用の単独セットアップ。
CSPRNG の初期化失敗で停止し、既存鍵ファイルを上書きしない。
回路/PK/VK の SHA3-256 と profile/version、開発用である旨を manifest に記録する。
テストは deterministic RNG を使うが、その seed/生成鍵は配布物に入れない。
ブラウザ bridge は setup 機能も seed 引数も公開しない。

本番では ceremony/provenance、toxic waste 処理、回路レビュー、PK/VK の再現可能な監査と
配布 manifest の署名・固定が必要。ここで生成する単独 setup は MPC ceremony 実装ではない。
PK の内包回路との一致はアプリによる承認ではない。配布 PK と VK のハッシュを外部で固定し、
検証側は承認済み VK だけを使用する。IC サンプルはビルド時に VK を固定する。

## 乱数と秘密情報

Nim は `std/sysrand.urandom`、ブラウザ/Node は getrandom 0.2 の Web Crypto backend から
新しい 32 byte seed を取得する。C ABI はホストが全バイトを安全に埋める callback を要求し、
欠落/失敗を error 19 として返す。時間・Math.random・固定 seed の fallback はない。
arkworks の infallible RNG interface へ渡す前にエントロピー取得失敗を処理する。
内部 PRNG は zeroize feature 付き ChaCha20。seed と cipher state は drop 時に消去する。
Rust の所有 witness、事前チェックの R1CS witness assignment、Nim の一時 witness バッファ、
WASM bridge が所有する witness marshalling buffer、サンプル JS の入力配列を消去する。

**保証の限界**: arkworks 合成/証明内部、FpVar、コンパイラの一時値、ホスト側のコピー、
ホストの GC/クラッシュダンプまで完全に消去する保証はない。
ブラウザでは専用 Worker を破棄するなどの隔離が必要。本番の秘密消去要件を満たすかは
上流ライブラリを含む別の監査事項とする。PK は秘密 witness ではない。
C ABI の有効なポインタ・確保容量・非重複は呼出元の契約。panic は FFI 境界で封じ込めるが、
不正ポインタ、allocator OOM abort、WASM trap は回復可能エラーにできない。
資源上限に加えホスト側で Worker の時間/メモリ上限を適用する。

## 検証・リリース条件

- 全 arity の native Poseidon と R1CS 結果を 0/1/42 起点の複数ベクトルで比較。
- 既存 README の既知ハッシュベクトル、既存 C ABI Verifier と Nim FFI で cross check。
- 正常 proof、入力変更、秘密変更、PRF context、Merkle direction=0/1/2、range/和の overflow、
  非正規 Fr、誤回路/PK、切詰め/余剰、乱数 callback 失敗、parser 上限を試験。
- 実際の Chromium と Node で生成した proof を WASI の既存 Verifier で検証する。
- 別の wasm32-unknown-unknown IC adapter を PocketIC で実行し、VK を固定して browser proof を検証する。
  WASI は ICP canister ABI ではなく、WASI の成功を ICP 実行実績とみなさない。
- smoke の暫定予算: 各証明/検証 30 秒、WASM committed linear memory 256 MiB、
  IC verifier 20 億 instructions。小規模デモの回帰検出用であり本番回路の SLA ではない。
- 実測は `groth16-prover-validation.md`。linear memory high water と peak RSS は区別する。
  PocketIC の update cycles 差は ingress/execution 等を含み、mainnet 料金を保証しない。
- 本番リリース前に circuit completeness/soundness、乱数、setup provenance、serialization、
  witness lifecycle、ブラウザ/Worker の拒否サービス耐性を独立レビューする。

## 参照

- [ark-groth16 0.5 proving API](https://docs.rs/ark-groth16/0.5.0/ark_groth16/struct.Groth16.html)
- [light-poseidon 0.4.1](https://docs.rs/light-poseidon/0.4.1/light_poseidon/)
- [PocketIC](https://github.com/dfinity/pocketic)
- [PicJS](https://js.icp.build/pic-js/latest/api/classes/pocketic)
