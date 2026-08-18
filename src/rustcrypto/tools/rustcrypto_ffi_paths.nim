import std/[os, osproc, strutils]

const
  RustCryptoTargetId* = "linux-x86_64"
  RustCryptoCargoArchiveName* = "librust_crypto_ffi.a"
  RustCryptoArchiveName* = "librust_crypto_ffi-linux-x86_64.a"
  RustCryptoMacosArm64TargetId* = "macos-arm64"
  RustCryptoMacosArm64ArchiveName* = "librust_crypto_ffi-macos-arm64.a"
  RustCryptoMacosArm64CargoTriple* = "aarch64-apple-darwin"
  RustCryptoWasmTargetId* = "wasm32-unknown-unknown"
  RustCryptoWasmArchiveName* = "librust_crypto_ffi-wasm32-unknown-unknown.a"
  RustCryptoWasiTargetId* = "wasm32-wasip1"
  RustCryptoWasiArchiveName* = "librust_crypto_ffi-wasm32-wasip1.a"

proc packageRoot*(scriptSourcePath: string): string =
  var dir = scriptSourcePath.parentDir
  while true:
    if fileExists(dir / "rustcrypto.nimble"):
      return dir
    let parent = dir.parentDir
    if parent == dir:
      return ""
    dir = parent

proc moduleRoot*(packageRoot: string): string =
  if dirExists(packageRoot / "src" / "rustcrypto"):
    packageRoot / "src" / "rustcrypto"
  else:
    packageRoot / "rustcrypto"

proc moduleVendorArchivePath*(packageRoot: string; targetId, archiveName: string): string =
  moduleRoot(packageRoot) / "vendor" / "rustcrypto-ffi" / targetId / archiveName

proc versionFromNimble*(packageRoot: string): string =
  let nimblePath = packageRoot / "rustcrypto.nimble"
  for line in readFile(nimblePath).splitLines:
    let trimmed = line.strip
    if trimmed.startsWith("version"):
      let firstQuote = trimmed.find('"')
      let lastQuote = trimmed.rfind('"')
      if firstQuote >= 0 and lastQuote > firstQuote:
        return trimmed[firstQuote + 1 ..< lastQuote]
  raise newException(ValueError, "failed to parse version from " & nimblePath)

proc cacheRoot*(version: string): string =
  let base =
    if getEnv("XDG_CACHE_HOME").len > 0:
      getEnv("XDG_CACHE_HOME")
    else:
      getHomeDir() / ".cache"
  base / "rustcrypto" / "ffi" / ("v" & version)

proc cacheArchivePath*(version: string; targetId, archiveName: string): string =
  cacheRoot(version) / targetId / archiveName

proc cacheArchivePath*(version: string): string =
  cacheArchivePath(version, RustCryptoTargetId, RustCryptoArchiveName)

proc moduleVendorArchivePath*(packageRoot: string): string =
  moduleVendorArchivePath(packageRoot, RustCryptoTargetId, RustCryptoArchiveName)

proc vendorArchivePath*(packageRoot: string): string =
  let moduleVendor = moduleVendorArchivePath(packageRoot)
  if fileExists(moduleVendor):
    return moduleVendor

  let rootVendor = packageRoot / "vendor" / "rustcrypto-ffi" / RustCryptoTargetId / RustCryptoArchiveName
  if fileExists(rootVendor):
    return rootVendor

  moduleVendor

proc repositorySlug*(packageRoot: string): string =
  let overrideRepo = getEnv("RUSTCRYPTO_GITHUB_REPOSITORY")
  if overrideRepo.len > 0:
    return overrideRepo

  let fallbackRepo = "itsumura-h/nim-rustcrypto"
  let gitUrl = execCmdEx(
    "git -C " & packageRoot & " remote get-url origin",
    options = {poUsePath, poStdErrToStdOut},
  )
  if gitUrl.exitCode != 0:
    return fallbackRepo

  let remote = gitUrl.output.strip
  if remote.len == 0:
    return fallbackRepo

  if remote.startsWith("git@github.com:"):
    result = remote["git@github.com:".len .. ^1]
    if result.endsWith(".git"):
      result.setLen(result.len - 4)
    return result

  let marker = "github.com/"
  let idx = remote.find(marker)
  if idx >= 0:
    result = remote[idx + marker.len .. ^1]
    if result.endsWith(".git"):
      result.setLen(result.len - 4)
    return result

  fallbackRepo

proc releaseBaseUrl*(repositorySlug: string; version: string): string =
  "https://github.com/" & repositorySlug & "/releases/download/v" & version

proc releaseArchiveFileName*(version: string; targetId: string): string =
  "rustcrypto-ffi-v" & version & "-" & targetId & ".tar.gz"

proc releaseChecksumFileName*(version: string; targetId: string): string =
  releaseArchiveFileName(version, targetId) & ".sha256"

proc releaseArchiveUrl*(repositorySlug: string; version: string; targetId: string): string =
  releaseBaseUrl(repositorySlug, version) & "/" & releaseArchiveFileName(version, targetId)

proc releaseChecksumUrl*(repositorySlug: string; version: string; targetId: string): string =
  releaseBaseUrl(repositorySlug, version) & "/" & releaseChecksumFileName(version, targetId)

proc resolveWritableArchivePath*(packageRoot: string; version: string): string =
  let modulePath = moduleVendorArchivePath(packageRoot)
  try:
    createDir(modulePath.parentDir)
    return modulePath
  except CatchableError:
    discard

  let cachePath = cacheArchivePath(version)
  createDir(cachePath.parentDir)
  cachePath
