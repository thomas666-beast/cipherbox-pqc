#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crypto=$(cd -- "${1:-$root/../cipherbox}" && pwd)
target=${CARGO_TARGET_DIR:-"$root/.build/crypto"}
mkdir -p -- "$target"
target=$(cd -- "$target" && pwd)
export CARGO_TARGET_DIR="$target"

wasm="$crypto/cipherbox-pqc-wasm"
native="$crypto/cipherbox-pqc-native"
if [[ ! -f "$wasm/Cargo.lock" || ! -f "$native/Cargo.lock" || ! -f "$crypto/cipherbox-pqc-core/SECURITY-UPGRADE.md" && ! -f "$crypto/SECURITY-UPGRADE.md" ]]; then
  echo "Pass the directory of the hardened Cipherbox source with all three crates." >&2
  exit 1
fi
bindgen=$(awk '/^name = "wasm-bindgen"$/ {getline; gsub(/"/,"",$3); print $3; exit}' "$wasm/Cargo.lock")
if [[ "$(wasm-bindgen --version 2>/dev/null || true)" != "wasm-bindgen $bindgen" ]]; then
  echo "Install the matching CLI: cargo install --locked wasm-bindgen-cli --version $bindgen" >&2
  exit 1
fi
cargo build --locked --release --target wasm32-unknown-unknown --manifest-path "$wasm/Cargo.toml"
cargo build --locked --release --manifest-path "$native/Cargo.toml" --bin cipherbox-pqc-verify

out=$(mktemp -d)
trap 'rm -rf -- "$out"' EXIT
wasm-bindgen --target web --out-dir "$out" "$target/wasm32-unknown-unknown/release/cipherbox_pqc_wasm.wasm"
mkdir -p -- "$root/frontend/src/pqc" "$root/bin"
install -m 644 "$out"/cipherbox_pqc_wasm* "$root/frontend/src/pqc/"
install -m 755 "$target/release/cipherbox-pqc-verify" "$root/bin/"
printf 'Installed hardened WASM and native verifier in %s\n' "$root"
