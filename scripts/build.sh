#!/usr/bin/env bash
# Build a fresh release binary from the current tree.
#
#   scripts/build.sh [extra cargo args...]
#
# Anything you pass is handed to cargo, so `scripts/build.sh --features foo`
# or `scripts/build.sh -v` work as expected.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

# Nothing here needs root, and a build run as root would leave root-owned files
# in target/ and ~/.cargo that break the next plain `cargo build` — quite apart
# from rustup's cargo not being in root's PATH at all. Under sudo, hand the
# build back to whoever called it. (After this exec the euid is theirs, so the
# test is false the second time round and it cannot loop.)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    echo "==> building as $SUDO_USER, not root"
    exec sudo -u "$SUDO_USER" -i -- "$root/scripts/build.sh" "$@"
fi

# rustup keeps cargo in the user's home, which a stripped PATH (sudo's
# secure_path, a cron job) does not reach. Find it before giving up.
if ! command -v cargo >/dev/null 2>&1; then
    for bin in "${CARGO_HOME:-$HOME/.cargo}/bin" "$HOME/.cargo/bin" /usr/local/cargo/bin; do
        if [ -x "$bin/cargo" ]; then
            PATH="$bin:$PATH"
            break
        fi
    done
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo is not on PATH and is not in ${CARGO_HOME:-$HOME/.cargo}/bin" >&2
    echo "       (running under sudo? sudo's secure_path does not include ~/.cargo/bin)" >&2
    exit 1
fi

echo "==> cargo build --release -p linrdp${*:+ $*}"
cargo build --release -p linrdp "$@"

binary="$root/target/release/linrdp"
if [ ! -x "$binary" ]; then
    echo "error: cargo reported success but $binary is not there" >&2
    exit 1
fi

echo
echo "==> built $binary"
ls -lh -- "$binary" | awk '{ printf "    %s  %s %s %s\n", $5, $6, $7, $8 }'
