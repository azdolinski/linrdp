#!/usr/bin/env bash
# Build the current tree and install it over the one on this machine.
#
#   sudo scripts/install-dev.sh [extra cargo args...]
#
# Compiles a release binary, copies it to /usr/local/bin/linrdp, and leaves the
# running service alone unless you say otherwise: it asks before restarting an
# installed service, and asks before installing one that is not there yet.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

readonly TARGET=/usr/local/bin/linrdp
readonly UNIT=/etc/systemd/system/linrdp.service

if [ "$(id -u)" -ne 0 ]; then
    echo "error: this installs into /usr/local/bin and talks to systemd — run it with sudo:" >&2
    echo "       sudo $0${*:+ $*}" >&2
    exit 1
fi

# Ask a yes/no question on the terminal. Returns 0 for yes, 1 for no, and 2
# when there is no terminal to ask on (cron, a pipe) — the caller then says
# what it is skipping rather than silently touching the machine.
confirm() {
    local answer
    # Open it in a subshell first: -r passes on a /dev/tty that cannot actually
    # be opened (a detached session), and the failed read would print over us.
    (: </dev/tty) 2>/dev/null || return 2
    read -r -p "$1 [y/N] " answer </dev/tty || return 2
    case $answer in
        [yY] | [yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# build.sh drops back to $SUDO_USER on its own, so the compile does not run as
# root; only the install and systemd steps below do.
"$root/scripts/build.sh" "$@"

echo
echo "==> installing $root/target/release/linrdp -> $TARGET"
install -m755 "$root/target/release/linrdp" "$TARGET"

echo
if [ -f "$UNIT" ]; then
    echo "==> $UNIT is installed"
    set +e
    confirm "    Restart the linrdp service now?"
    reply=$?
    set -e
    case $reply in
        0)
            echo "==> $TARGET service restart"
            "$TARGET" service restart
            ;;
        1)
            echo "    Left running. The supervisor execs the new binary for the next"
            echo "    connection; restart it to put the supervisor itself on this build:"
            echo "      sudo linrdp service restart"
            ;;
        *)
            echo "    No terminal to ask on — service left running, nothing restarted."
            ;;
    esac
else
    echo "==> no $UNIT: the service is not installed on this machine"
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "    There is no systemd here either. Run it without a unit with:"
        echo "      sudo linrdp daemon start"
        exit 0
    fi
    set +e
    confirm "    Install the service and start it?"
    reply=$?
    set -e
    case $reply in
        0)
            # Through $TARGET, not the build tree: `service install` writes the
            # unit's ExecStart from the path of the binary running it.
            echo "==> $TARGET service install"
            "$TARGET" service install
            ;;
        1)
            echo "    Skipped. The binary is in place; install the service later with:"
            echo "      sudo linrdp service install"
            ;;
        *)
            echo "    No terminal to ask on — binary installed, service not touched."
            ;;
    esac
fi

echo
echo "==> done: $("$TARGET" --version 2>/dev/null || echo "$TARGET")"
