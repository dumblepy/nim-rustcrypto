import std/[os]

import ./rustcrypto_ffi_paths

when defined(linux) and defined(amd64):
  proc pickExistingArchive(candidates: openArray[string]): string =
    for candidate in candidates:
      if fileExists(candidate):
        return candidate
    ""

  proc syncArchive(
      sourceArchive: string;
      packageRoot: string;
      version: string;
      targetId: string;
      archiveName: string,
  ) =
    let modulePath = moduleVendorArchivePath(packageRoot, targetId, archiveName)
    let cachePath = cacheArchivePath(version, targetId, archiveName)

    createDir(modulePath.parentDir)
    copyFile(sourceArchive, modulePath)

    createDir(cachePath.parentDir)
    copyFile(sourceArchive, cachePath)

    echo modulePath

  proc sourceArchiveCandidates(sourceRoot: string; targetId: string): seq[string] =
    case targetId
    of RustCryptoTargetId:
      @[
        sourceRoot / "rustcrypto-ffi" / "target" / "release" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / "debug" / RustCryptoCargoArchiveName,
      ]
    of RustCryptoMacosArm64TargetId:
      @[
        sourceRoot / "rustcrypto-ffi" / "target" / RustCryptoMacosArm64CargoTriple / "release" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / RustCryptoMacosArm64CargoTriple / "debug" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / "release" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / "debug" / RustCryptoCargoArchiveName,
      ]
    of RustCryptoWasmTargetId, RustCryptoWasiTargetId:
      @[
        sourceRoot / "rustcrypto-ffi" / "target" / targetId / "release" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / targetId / "debug" / RustCryptoCargoArchiveName,
      ]
    else:
      @[]

  let resolvedPackageRoot = packageRoot(currentSourcePath)
  let version = versionFromNimble(resolvedPackageRoot)
  let sourceRoot = resolvedPackageRoot

  let linuxSourceArchive = pickExistingArchive(sourceArchiveCandidates(sourceRoot, RustCryptoTargetId))
  if linuxSourceArchive.len == 0:
    stderr.writeLine("rustcrypto FFI linux archive not found in target/release or target/debug.")
    quit(QuitFailure)

  let wasmSourceArchive = pickExistingArchive(sourceArchiveCandidates(sourceRoot, RustCryptoWasmTargetId))
  if wasmSourceArchive.len == 0:
    stderr.writeLine("rustcrypto FFI wasm archive not found in target/wasm32-unknown-unknown/release or target/wasm32-unknown-unknown/debug.")
    quit(QuitFailure)

  let wasiSourceArchive = pickExistingArchive(sourceArchiveCandidates(sourceRoot, RustCryptoWasiTargetId))
  if wasiSourceArchive.len == 0:
    stderr.writeLine("rustcrypto FFI wasi archive not found in target/wasm32-wasip1/release or target/wasm32-wasip1/debug.")
    quit(QuitFailure)

  syncArchive(linuxSourceArchive, resolvedPackageRoot, version, RustCryptoTargetId, RustCryptoArchiveName)
  syncArchive(wasmSourceArchive, resolvedPackageRoot, version, RustCryptoWasmTargetId, RustCryptoWasmArchiveName)
  syncArchive(wasiSourceArchive, resolvedPackageRoot, version, RustCryptoWasiTargetId, RustCryptoWasiArchiveName)

elif defined(macosx) and defined(arm64):
  proc pickExistingArchive(candidates: openArray[string]): string =
    for candidate in candidates:
      if fileExists(candidate):
        return candidate
    ""

  proc syncArchive(
      sourceArchive: string;
      packageRoot: string;
      version: string;
      targetId: string;
      archiveName: string,
  ) =
    let modulePath = moduleVendorArchivePath(packageRoot, targetId, archiveName)
    let cachePath = cacheArchivePath(version, targetId, archiveName)

    createDir(modulePath.parentDir)
    copyFile(sourceArchive, modulePath)

    createDir(cachePath.parentDir)
    copyFile(sourceArchive, cachePath)

    echo modulePath

  proc sourceArchiveCandidates(sourceRoot: string; targetId: string): seq[string] =
    case targetId
    of RustCryptoMacosArm64TargetId:
      @[
        sourceRoot / "rustcrypto-ffi" / "target" / RustCryptoMacosArm64CargoTriple / "release" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / RustCryptoMacosArm64CargoTriple / "debug" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / "release" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / "debug" / RustCryptoCargoArchiveName,
      ]
    of RustCryptoWasmTargetId, RustCryptoWasiTargetId:
      @[
        sourceRoot / "rustcrypto-ffi" / "target" / targetId / "release" / RustCryptoCargoArchiveName,
        sourceRoot / "rustcrypto-ffi" / "target" / targetId / "debug" / RustCryptoCargoArchiveName,
      ]
    else:
      @[]

  let resolvedPackageRoot = packageRoot(currentSourcePath)
  let version = versionFromNimble(resolvedPackageRoot)
  let sourceRoot = resolvedPackageRoot

  let macosSourceArchive = pickExistingArchive(sourceArchiveCandidates(sourceRoot, RustCryptoMacosArm64TargetId))
  if macosSourceArchive.len == 0:
    stderr.writeLine(
      "rustcrypto FFI macOS arm64 archive not found. Build with `cargo build --release --lib` " &
      "or `cargo build --release --lib --target " & RustCryptoMacosArm64CargoTriple & "` under rustcrypto-ffi.",
    )
    quit(QuitFailure)

  syncArchive(macosSourceArchive, resolvedPackageRoot, version, RustCryptoMacosArm64TargetId, RustCryptoMacosArm64ArchiveName)

  let wasmSourceArchive = pickExistingArchive(sourceArchiveCandidates(sourceRoot, RustCryptoWasmTargetId))
  if wasmSourceArchive.len > 0:
    syncArchive(wasmSourceArchive, resolvedPackageRoot, version, RustCryptoWasmTargetId, RustCryptoWasmArchiveName)

  let wasiSourceArchive = pickExistingArchive(sourceArchiveCandidates(sourceRoot, RustCryptoWasiTargetId))
  if wasiSourceArchive.len > 0:
    syncArchive(wasiSourceArchive, resolvedPackageRoot, version, RustCryptoWasiTargetId, RustCryptoWasiArchiveName)

else:
  {.error: "rustcrypto FFI local sync currently supports only Linux x86_64 and macOS arm64 hosts.".}
