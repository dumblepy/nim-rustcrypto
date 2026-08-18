import std/[os, osproc, strutils]

import ./rustcrypto_ffi_paths

proc normalizeTarget(targetArg: string): tuple[targetId, archiveName: string] =
  case targetArg.strip.toLowerAscii
  of "", "linux", "linux-x86_64":
    (RustCryptoTargetId, RustCryptoArchiveName)
  of "macos-arm64", "darwin-arm64", "apple-silicon", "aarch64-apple-darwin":
    (RustCryptoMacosArm64TargetId, RustCryptoMacosArm64ArchiveName)
  of "wasm", "wasm32", "wasm32-unknown-unknown":
    (RustCryptoWasmTargetId, RustCryptoWasmArchiveName)
  of "wasi", "wasm32-wasi", "wasm32-wasip1":
    (RustCryptoWasiTargetId, RustCryptoWasiArchiveName)
  else:
    ("", "")

proc firstTargetArg(): string =
  for idx in 1 .. paramCount():
    let arg = paramStr(idx).strip
    if arg.len > 0 and arg != "--":
      return arg
  ""

proc resolveArchivePath(packageRoot: string; version: string; targetArg: string): string =
  let (targetId, archiveName) = normalizeTarget(targetArg)
  if targetId.len == 0:
    stderr.writeLine(
      "unsupported rustcrypto FFI target '" & targetArg & "'. " &
      "Use linux, linux-x86_64, macos-arm64, aarch64-apple-darwin, wasm, wasm32, wasm32-unknown-unknown, wasi, wasm32-wasi, or wasm32-wasip1.",
    )
    return ""

  let modulePath = moduleVendorArchivePath(packageRoot, targetId, archiveName)
  if fileExists(modulePath):
    return modulePath

  let cachePath = cacheArchivePath(version, targetId, archiveName)
  if fileExists(cachePath):
    return cachePath

  when (defined(linux) and defined(amd64)) or (defined(macosx) and defined(arm64)):
    let fetchTool = currentSourcePath.parentDir / "fetch_rustcrypto_ffi.nim"
    let fetchResult = execCmdEx(
      "nim r --hints:off --warnings:off " & quoteShell(fetchTool) & " " & quoteShell(packageRoot),
      workingDir = packageRoot,
      options = {poUsePath, poStdErrToStdOut},
    )
    if fetchResult.exitCode != 0:
      if fetchResult.output.len > 0:
        stderr.write(fetchResult.output)
      return ""
    if fileExists(modulePath):
      return modulePath
    if fileExists(cachePath):
      return cachePath

  return ""

proc missingArchiveHint(targetId: string): string =
  if targetId == RustCryptoWasiTargetId:
    "Run `nimble fetchRustFfi` from `/application`, " &
    "or copy the wasm32-wasip1 Release asset into vendor/cache before compiling."
  elif targetId == RustCryptoWasmTargetId:
    "Run `nimble fetchRustFfi` from `/application`, " &
    "or copy the wasm32-unknown-unknown Release asset into vendor/cache before compiling."
  elif targetId == RustCryptoMacosArm64TargetId:
    "Run `nimble fetchRustFfi` or `nimble buildRustFfiLocal` from `/application`, " &
    "or copy the macos-arm64 Release asset into vendor/cache before compiling."
  else:
    "Run `nimble fetchRustFfi` or `nimble buildRustFfiLocal` from `/application`."

let resolvedPackageRoot = packageRoot(currentSourcePath)
let version = versionFromNimble(resolvedPackageRoot)
let rawTargetArg = firstTargetArg()
let defaultTargetArg = when defined(linux) and defined(amd64):
    "linux-x86_64"
  elif defined(macosx) and defined(arm64):
    "macos-arm64"
  elif defined(wasi) or defined(rustcryptoWasi):
    "wasm32-wasip1"
  elif defined(wasm32):
    "wasm32-unknown-unknown"
  else:
    "linux-x86_64"
let targetArg = if rawTargetArg.len > 0: rawTargetArg else: defaultTargetArg
let resolvedArchivePath = resolveArchivePath(resolvedPackageRoot, version, targetArg)

if resolvedArchivePath.len > 0:
  echo resolvedArchivePath
else:
  let (targetId, _) = normalizeTarget(targetArg)
  if targetId.len == 0:
    quit(QuitFailure)

  stderr.writeLine(
    "rustcrypto FFI static archive for target '" & targetId & "' was not found. " &
    missingArchiveHint(targetId),
  )
  quit(QuitFailure)
