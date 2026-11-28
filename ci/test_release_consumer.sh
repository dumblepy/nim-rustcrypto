#!/usr/bin/env bash
# Release-consumer install check.
#
# Builds the three Rust FFI static archives (native Linux x86_64,
# wasm32-unknown-unknown, wasm32-wasip1), syncs them into the package vendor
# tree, installs rustcrypto into an ISOLATED Nimble directory, and builds/runs
# example/src/main.nim against that installation.
#
# The global Nimble directory is never used for the install. NIMBLE_DIR and
# XDG_CACHE_HOME point at temporary directories and are removed on exit.
#
# Usage:
#   bash ci/test_release_consumer.sh
#
# Optional:
#   RUSTCRYPTO_RELEASE_CONSUMER_KEEP=1  keep the temporary work directory
#   CARGO_TARGET_DIR                    ignored: the sync tool requires
#                                       rustcrypto-ffi/target
#
# This performs no release publication and no independent audit.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rustcrypto_ffi_dir="$repo_root/rustcrypto-ffi"
target_root="$rustcrypto_ffi_dir/target"
version="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$repo_root/rustcrypto.nimble" | head -n 1)"
if [[ -z "$version" ]]; then
  echo "failed to read rustcrypto version from rustcrypto.nimble" >&2
  exit 1
fi

target_ids=(linux-x86_64 wasm32-unknown-unknown wasm32-wasip1)
archive_names=(
  librust_crypto_ffi-linux-x86_64.a
  librust_crypto_ffi-wasm32-unknown-unknown.a
  librust_crypto_ffi-wasm32-wasip1.a
)
cargo_archive_name="librust_crypto_ffi.a"

temp_base="${TMPDIR:-/tmp/opencode}"
mkdir -p "$temp_base"
work_root="$(mktemp -d "$temp_base/rustcrypto-release-consumer.XXXXXX")"
isolated_nimble="$work_root/nimble"
isolated_cache="$work_root/cache"
consumer_dir="$work_root/consumer"
mkdir -p "$isolated_nimble" "$isolated_cache" "$consumer_dir"

cleanup() {
  local status=$?
  if [[ "${RUSTCRYPTO_RELEASE_CONSUMER_KEEP:-0}" == "1" ]]; then
    echo "kept release-consumer work directory: $work_root" >&2
  else
    rm -rf "$work_root"
  fi
  exit "$status"
}
trap cleanup EXIT

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_size() {
  wc -c < "$1" | tr -d '[:space:]'
}

print_artifact() {
  local label="$1"
  local path="$2"
  local sha size
  sha="$(sha256_file "$path")"
  size="$(file_size "$path")"
  printf '%-28s %12s bytes  %s  %s\n' "$label" "$size" "$sha" "$path"
}

echo "==> Release consumer check (rustcrypto $version)"
echo "==> Work directory: $work_root"
echo "==> Isolated NIMBLE_DIR: $isolated_nimble"
echo "==> Isolated XDG_CACHE_HOME: $isolated_cache"

# The local sync tool only looks at rustcrypto-ffi/target. Force the default
# target directory so a caller-provided CARGO_TARGET_DIR cannot desynchronise
# the build from the archive that is copied into the package.
export CARGO_TARGET_DIR="$target_root"

if command -v rustup >/dev/null 2>&1; then
  installed_targets="$(rustup target list --installed)"
  for target in wasm32-unknown-unknown wasm32-wasip1; do
    if ! grep -qx "$target" <<<"$installed_targets"; then
      echo "==> Adding rustup target $target"
      rustup target add "$target"
    fi
  done
fi

echo "==> Build release static archives (native)"
(
  cd "$rustcrypto_ffi_dir"
  cargo build --locked --release --lib
)

echo "==> Build release static archives (wasm32-unknown-unknown)"
(
  cd "$rustcrypto_ffi_dir"
  cargo build --locked --release --lib --target wasm32-unknown-unknown
)

echo "==> Build release static archives (wasm32-wasip1)"
(
  cd "$rustcrypto_ffi_dir"
  cargo build --locked --release --lib --target wasm32-wasip1
)

source_archives=(
  "$target_root/release/$cargo_archive_name"
  "$target_root/wasm32-unknown-unknown/release/$cargo_archive_name"
  "$target_root/wasm32-wasip1/release/$cargo_archive_name"
)
for archive in "${source_archives[@]}"; do
  if [[ ! -s "$archive" ]]; then
    echo "missing or empty release archive: $archive" >&2
    exit 1
  fi
done

echo "==> Sync archives into package vendor path"
(
  cd "$repo_root"
  XDG_CACHE_HOME="$isolated_cache" \
    nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim
)

module_vendor="$repo_root/src/rustcrypto/vendor/rustcrypto-ffi"
module_archives=()
for index in "${!target_ids[@]}"; do
  module_archive="$module_vendor/${target_ids[$index]}/${archive_names[$index]}"
  if [[ ! -s "$module_archive" ]]; then
    echo "missing synced package archive: $module_archive" >&2
    exit 1
  fi
  if [[ "$(sha256_file "$module_archive")" != "$(sha256_file "${source_archives[$index]}")" ]]; then
    echo "synced archive does not match the built archive: $module_archive" >&2
    exit 1
  fi
  module_archives+=("$module_archive")
done

echo "==> Build artifacts"
for index in "${!target_ids[@]}"; do
  print_artifact "${target_ids[$index]}" "${module_archives[$index]}"
done

# Seed the package list from the existing Nimble directory when available.
# This keeps the isolated install offline and avoids a package-list download.
source_nimble_dir="${NIMBLE_DIR:-$HOME/.nimble}"
seeded_package_list=0
for package_list in packages.json packages_official.json packages_temp.json; do
  if [[ -f "$source_nimble_dir/$package_list" ]]; then
    cp "$source_nimble_dir/$package_list" "$isolated_nimble/$package_list"
    seeded_package_list=1
  fi
done

nimble_install_args=(-y)
if [[ "$seeded_package_list" == "1" ]]; then
  nimble_install_args+=(--offline)
fi

echo "==> Install rustcrypto into isolated Nimble directory"
# Nimble 0.24.1 rejects `nimble install /path` as an unsatisfiable path
# dependency, so install the local package from its own directory.
(
  cd "$repo_root"
  NIMBLE_DIR="$isolated_nimble" \
    XDG_CACHE_HOME="$isolated_cache" \
    nimble install "${nimble_install_args[@]}"
)

installed_packages=()
while IFS= read -r installed; do
  installed_packages+=("$installed")
done < <(find "$isolated_nimble/pkgs2" -mindepth 1 -maxdepth 1 -type d -name "rustcrypto-$version-*" 2>/dev/null | sort)
if [[ "${#installed_packages[@]}" -ne 1 ]]; then
  echo "expected exactly one isolated rustcrypto $version installation, found ${#installed_packages[@]}" >&2
  printf '  %s\n' "${installed_packages[@]:-}" >&2
  exit 1
fi
installed_pkg="${installed_packages[0]}"
echo "==> Installed package: $installed_pkg"

echo "==> Verify installed package archives"
installed_vendor="$installed_pkg/rustcrypto/vendor/rustcrypto-ffi"
for index in "${!target_ids[@]}"; do
  installed_archive="$installed_vendor/${target_ids[$index]}/${archive_names[$index]}"
  if [[ ! -s "$installed_archive" ]]; then
    echo "installed package is missing archive: $installed_archive" >&2
    exit 1
  fi
  if [[ "$(sha256_file "$installed_archive")" != "$(sha256_file "${module_archives[$index]}")" ]]; then
    echo "installed archive does not match the synced archive: $installed_archive" >&2
    exit 1
  fi
  print_artifact "installed ${target_ids[$index]}" "$installed_archive"
done

echo "==> Verify rustcrypto_ffi_paths resolves every installed target"
for index in "${!target_ids[@]}"; do
  expected_archive="$installed_vendor/${target_ids[$index]}/${archive_names[$index]}"
  resolved_archive="$(
    XDG_CACHE_HOME="$isolated_cache" \
      nim r --hints:off --warnings:off \
      "$installed_pkg/rustcrypto/tools/resolve_rustcrypto_ffi.nim" -- "${target_ids[$index]}"
  )"
  resolved_archive="$(printf '%s' "$resolved_archive" | tail -n 1 | tr -d '\r')"
  if [[ "$resolved_archive" != "$expected_archive" ]]; then
    echo "rustcrypto_ffi_paths resolved unexpected archive for ${target_ids[$index]}" >&2
    echo "  expected: $expected_archive" >&2
    echo "  actual:   $resolved_archive" >&2
    exit 1
  fi
  echo "  ${target_ids[$index]} -> $resolved_archive"
done

echo "==> Copy consumer example into isolated work directory"
cp -a "$repo_root/example/." "$consumer_dir/"
rm -f "$consumer_dir/src/main"
rm -f "$consumer_dir/example" "$consumer_dir/nimble.paths" "$consumer_dir/config.nims"

consumer_built=0
echo "==> Build consumer with isolated Nimble dependency resolution"
if (
  cd "$consumer_dir"
  NIMBLE_DIR="$isolated_nimble" \
    XDG_CACHE_HOME="$isolated_cache" \
    nimble c -y --offline --hints:off --warnings:off -o:example src/main.nim
); then
  consumer_built=1
else
  echo "nimble c did not resolve the installed package; falling back to explicit --path" >&2
fi

if [[ "$consumer_built" != "1" ]]; then
  (
    cd "$consumer_dir"
    XDG_CACHE_HOME="$isolated_cache" \
      nim c --hints:off --warnings:off --path:"$installed_pkg" -o:example src/main.nim
  )
fi

if [[ ! -x "$consumer_dir/example" ]]; then
  echo "consumer example was not built: $consumer_dir/example" >&2
  exit 1
fi

echo "==> Run consumer"
consumer_output="$work_root/consumer.out"
(
  cd "$consumer_dir"
  ./example
) | tee "$consumer_output"

if ! grep -qx 'verification: true' "$consumer_output"; then
  echo "consumer did not report a successful signature verification" >&2
  exit 1
fi

echo "==> Release consumer check passed"
