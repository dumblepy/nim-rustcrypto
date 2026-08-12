# Package

version       = "0.1.9"
author        = "Anonymous"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = ""
paths         = @["src"]
installDirs   = @["src"]


# Dependencies

requires "nim >= 2.0.0"

proc fetchRustFfiCommand(): string =
  "nim r --hints:off --warnings:off src/rustcrypto/tools/fetch_rustcrypto_ffi.nim"

task fetchRustFfi, "Download Rust FFI static archive from GitHub Release":
  exec fetchRustFfiCommand()

when (defined(linux) and defined(amd64)) or (defined(macosx) and defined(arm64)):
  before install:
    exec fetchRustFfiCommand()

task buildRustFfiLocal, "Build Rust FFI static archive locally and sync it":
  exec "rustup target add wasm32-unknown-unknown wasm32-wasip1"
  exec "cd ../rustcrypto-ffi && cargo build --release --lib"
  exec "cd ../rustcrypto-ffi && cargo build --release --lib --target wasm32-unknown-unknown"
  exec "cd ../rustcrypto-ffi && cargo build --release --lib --target wasm32-wasip1"
