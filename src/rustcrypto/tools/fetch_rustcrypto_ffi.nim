import std/[os, osproc, strutils]

import ./rustcrypto_ffi_paths

when not ((defined(linux) and defined(amd64)) or (defined(macosx) and defined(arm64))):
  {.error: "rustcrypto FFI download currently supports only Linux x86_64 and macOS arm64.".}
else:
  const targetSpecs =
    when defined(linux) and defined(amd64):
      [
        (RustCryptoTargetId, RustCryptoArchiveName),
        (RustCryptoWasmTargetId, RustCryptoWasmArchiveName),
        (RustCryptoWasiTargetId, RustCryptoWasiArchiveName),
      ]
    else:
      [(RustCryptoMacosArm64TargetId, RustCryptoMacosArm64ArchiveName)]

  proc runCommand(command: string; workingDir = ""): tuple[success: bool; output: string] =
    let commandResult = execCmdEx(
      command,
      workingDir = workingDir,
      options = {poUsePath, poStdErrToStdOut},
    )
    if commandResult.output.len > 0:
      stdout.write(commandResult.output)
    (commandResult.exitCode == 0, commandResult.output)

  proc downloadFile(url: string; destination: string): bool =
    runCommand("curl -fsSL -o " & quoteShell(destination) & " " & quoteShell(url)).success

  proc checksumFile(workingDir: string; checksumFileName: string): bool =
    when defined(macosx):
      runCommand("shasum -a 256 -c " & quoteShell(checksumFileName), workingDir).success
    else:
      runCommand("sha256sum -c " & quoteShell(checksumFileName), workingDir).success

  proc extractArchive(archivePath: string; destinationDir: string): bool =
    createDir(destinationDir)
    runCommand(
      "tar -xzf " & quoteShell(archivePath) & " --strip-components=1",
      destinationDir,
    ).success

  proc copyArchive(sourcePath: string; destinationPath: string): bool =
    createDir(destinationPath.parentDir)
    copyFile(sourcePath, destinationPath)
    true

  proc createWorkRoot(): string =
    let tempDirResult = runCommand("mktemp -d " & quoteShell(getTempDir() / "rustcrypto-ffi.XXXXXX"))
    if not tempDirResult.success:
      return ""
    tempDirResult.output.strip

  proc moduleArchivesExist(packageRoot: string): bool =
    for spec in targetSpecs:
      if not fileExists(moduleVendorArchivePath(packageRoot, spec[0], spec[1])):
        return false
    true

  proc cacheArchivesExist(version: string): bool =
    for spec in targetSpecs:
      if not fileExists(cacheArchivePath(version, spec[0], spec[1])):
        return false
    true

  proc copyCacheToModule(packageRoot: string; version: string) =
    for spec in targetSpecs:
      let moduleArchive = moduleVendorArchivePath(packageRoot, spec[0], spec[1])
      let cacheArchive = cacheArchivePath(version, spec[0], spec[1])
      createDir(moduleArchive.parentDir)
      copyFile(cacheArchive, moduleArchive)

  proc tryDownloadReleaseArchives(
      packageRoot: string;
      version: string;
      repositorySlugValue: string;
      workRoot: string,
  ): bool =
    let moduleRootPath = moduleRoot(packageRoot)
    let vendorRoot = moduleRootPath / "vendor" / "rustcrypto-ffi"
    let releaseRoot = workRoot / "release"
    createDir(releaseRoot)

    for spec in targetSpecs:
      let checksumFileName = releaseChecksumFileName(version, spec[0])
      let checksumPath = releaseRoot / checksumFileName
      let archivePath = releaseRoot / releaseArchiveFileName(version, spec[0])

      if not downloadFile(releaseArchiveUrl(repositorySlugValue, version, spec[0]), archivePath):
        return false
      if not downloadFile(releaseChecksumUrl(repositorySlugValue, version, spec[0]), checksumPath):
        return false

    for spec in targetSpecs:
      if not checksumFile(releaseRoot, releaseChecksumFileName(version, spec[0])):
        return false

    for spec in targetSpecs:
      let archivePath = releaseRoot / releaseArchiveFileName(version, spec[0])
      if not extractArchive(archivePath, vendorRoot):
        return false

    for spec in targetSpecs:
      let moduleArchive = moduleVendorArchivePath(packageRoot, spec[0], spec[1])
      let cacheArchive = cacheArchivePath(version, spec[0], spec[1])
      if not copyArchive(moduleArchive, cacheArchive):
        return false

    stdout.writeLine(
      moduleVendorArchivePath(packageRoot, targetSpecs[0][0], targetSpecs[0][1]),
    )
    true

  proc tryBuildLocalArchive(
      packageRoot: string;
      version: string;
      repoSlug: string;
      workRoot: string,
  ): bool =
    when defined(linux) and defined(amd64):
      let sourceCloneDir = workRoot / "source"
      let sourceRepoUrl = "https://github.com/" & repoSlug & ".git"
      if not runCommand("git clone --depth 1 " & quoteShell(sourceRepoUrl) & " " & quoteShell(sourceCloneDir)).success:
        return false

      let sourceRoot = sourceCloneDir / "rustcrypto-ffi"
      if not runCommand("cargo build --release --lib", sourceRoot).success:
        return false

      let builtArchive = sourceRoot / "target" / "release" / RustCryptoCargoArchiveName
      if not fileExists(builtArchive):
        stderr.writeLine("rustcrypto FFI archive was not built at " & builtArchive)
        return false

      let linuxModuleArchive = moduleVendorArchivePath(packageRoot)
      let linuxCacheArchive = cacheArchivePath(version)
      if not copyArchive(builtArchive, linuxModuleArchive):
        return false
      if not copyArchive(builtArchive, linuxCacheArchive):
        return false

      stdout.writeLine(linuxModuleArchive)
      true
    else:
      false

  proc main() =
    let rootArg = if paramCount() >= 1: paramStr(1).strip else: ""
    let resolvedPackageRoot = if rootArg.len > 0: rootArg else: packageRoot(currentSourcePath)
    if resolvedPackageRoot.len == 0:
      stderr.writeLine("failed to locate rustcrypto.nimble from " & currentSourcePath)
      quit(QuitFailure)

    let version = versionFromNimble(resolvedPackageRoot)
    let repoSlug = repositorySlug(resolvedPackageRoot)
    let workRoot = createWorkRoot()
    if workRoot.len == 0:
      quit(QuitFailure)
    defer:
      discard runCommand("rm -rf " & quoteShell(workRoot))

    if moduleArchivesExist(resolvedPackageRoot):
      stdout.writeLine(
        moduleVendorArchivePath(resolvedPackageRoot, targetSpecs[0][0], targetSpecs[0][1]),
      )
      quit(QuitSuccess)

    if cacheArchivesExist(version):
      copyCacheToModule(resolvedPackageRoot, version)
      stdout.writeLine(
        moduleVendorArchivePath(resolvedPackageRoot, targetSpecs[0][0], targetSpecs[0][1]),
      )
      quit(QuitSuccess)

    if tryDownloadReleaseArchives(resolvedPackageRoot, version, repoSlug, workRoot):
      quit(QuitSuccess)

    if tryBuildLocalArchive(resolvedPackageRoot, version, repoSlug, workRoot):
      quit(QuitSuccess)

    quit(QuitFailure)

  main()
