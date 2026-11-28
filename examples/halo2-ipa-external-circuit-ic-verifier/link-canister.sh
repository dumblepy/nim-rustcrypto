#!/usr/bin/env bash
# Links the verify-only canister static archive into a clean wasm module.
#
# Why this exists
# ---------------
# `rustcrypto-ffi` is an rlib with many `#[no_mangle]` C ABI entry points. When
# a crate that depends on it is built as a `cdylib`, rustc passes an explicit
# `--export=<symbol>` for *every* `#[no_mangle]` symbol in the dependency graph.
# That keeps every prover/other-crypto object alive and exports it, even with
# `--gc-sections` and even when the canister never references it.
#
# The canister therefore builds as a `staticlib` and this script links the
# archive with `wasm-ld`, exporting exactly the two verifier entry points.
# `--gc-sections` then drops everything not reachable from them, so the final
# module has no prover symbols and imports only `ic0`.
#
# This is export control, not source inclusion: the external circuit and
# `rustcrypto-ffi` are ordinary Cargo path dependencies.
#
# Usage:
#   link-canister.sh <output.wasm>
#
# Environment:
#   CARGO_TARGET_DIR  Cargo target directory used for the staticlib build.
#   CANISTER_ARCHIVE  Override the staticlib path.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
out="${1:?usage: link-canister.sh <output.wasm>}"
target_dir="${CARGO_TARGET_DIR:-$repo_root/rustcrypto-ffi/target}"
case "$target_dir" in
  /*) ;;
  *) target_dir="$(cd "$target_dir" && pwd)" ;;
esac
archive="${CANISTER_ARCHIVE:-$target_dir/wasm32-unknown-unknown/release/libhalo2_ipa_external_circuit_ic_verifier.a}"

if [[ ! -f "$archive" ]]; then
  echo "missing staticlib: $archive" >&2
  echo "build it with: cargo build --release --features halo2-ipa-verify-only,halo2-ipa-params-cache --manifest-path examples/halo2-ipa-external-circuit-ic-verifier/Cargo.toml --target wasm32-unknown-unknown" >&2
  exit 1
fi

sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | sed -n 's/^host: //p')"
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
if [[ ! -x "$lld" ]]; then
  lld="$(command -v wasm-ld || true)"
fi
if [[ -z "$lld" || ! -x "$lld" ]]; then
  echo "wasm-ld / rust-lld is required to link the canister" >&2
  exit 1
fi

out_dir="$(dirname "$out")"
mkdir -p "$out_dir"
tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT

# `--export` names are taken verbatim (the update method contains a space).
"$lld" -flavor wasm \
  --no-entry \
  --gc-sections \
  -z stack-size=1048576 \
  --stack-first \
  --export="canister_update verify" \
  --export=rustcrypto_halo2_ipa_external_chain_verify \
  --export-memory \
  --no-demangle \
  -O3 \
  --strip-all \
  -o "$tmp" \
  "$archive"

mv "$tmp" "$out"
trap - EXIT
echo "linked $out ($(stat -c%s "$out") bytes) from $archive"
