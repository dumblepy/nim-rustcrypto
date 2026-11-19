#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifacts="${1:-$(mktemp -d)}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
echo "Bulletproofs R1CS PoC artifacts: $artifacts"

cd "$repo_root/rustcrypto-ffi"
# Keep PoC archives out of the default build and release directories.
export CARGO_TARGET_DIR="$artifacts/target"
export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-clang}"
export CC_wasm32_wasip1="${CC_wasm32_wasip1:-clang}"
feature=bulletproofs-r1cs-poc
{
  uname -sm
  LC_ALL=C lscpu | awk '/^Model name:/'
  rustc --version
  nim --version
  node --version
  wasm-bindgen --version
  echo 'native_warmup=1 native_iterations=10 wasm_warmup=0 wasm_iterations=1'
} > "$artifacts/environment.txt"
cargo tree --locked --edges normal --prefix none > "$artifacts/default-dependencies.txt"
if grep -q '^bulletproofs v' "$artifacts/default-dependencies.txt"; then
  echo "Experimental dependency found in the default build" >&2
  exit 1
fi
rustup target add wasm32-unknown-unknown wasm32-wasip1
cargo test --locked --release --features "$feature" --lib bulletproofs_r1cs
cargo test --locked --release --features "$feature" --test bulletproofs_r1cs
cargo build --locked --release --features "$feature" --lib --example bulletproofs_r1cs_interop
native="$CARGO_TARGET_DIR/release/examples/bulletproofs_r1cs_interop"
"$native" fixture "$artifacts"
cargo build --locked --release --features "$feature" --target wasm32-wasip1 --example bulletproofs_r1cs_interop
cargo build --locked --release --features bulletproofs-r1cs-web-poc --target wasm32-unknown-unknown --example bulletproofs_r1cs_web
wasm-bindgen "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/examples/bulletproofs_r1cs_web.wasm" \
  --target web --out-dir "$artifacts/pkg"
node "$repo_root/web/bulletproofs-r1cs/smoke.mjs" "$artifacts" \
  "$CARGO_TARGET_DIR/wasm32-wasip1/release/examples/bulletproofs_r1cs_interop.wasm"

cd "$repo_root"
nim c --path:src -d:rustcryptoBulletproofsR1csPoc \
  "-d:rustCryptoBulletproofsArchive=$CARGO_TARGET_DIR/release/librust_crypto_ffi.a" \
  "--out:$artifacts/nim-interop" tests/test_bulletproofs_r1cs.nim
"$artifacts/nim-interop" "$artifacts"
for proof in node.bin web.bin nim.bin; do
  "$native" verify "$artifacts" "$proof"
done
python3 - "$native" "$artifacts" <<'PYTHON'
import resource
import subprocess
import sys
from pathlib import Path

native, directory = sys.argv[1:]
artifacts = Path(directory)
with (artifacts / "native-measurements.csv").open("w") as output:
    subprocess.run([native, "bench"], stdout=output, check=True)
peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
(artifacts / "native-rss.txt").write_text(f"peak_rss_kib={peak}\n")
PYTHON
