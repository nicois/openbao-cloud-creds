#!/usr/bin/env bash
#
# Registration smoke test: verifies every credential-* plugin builds as a
# binary AND successfully registers + enables in a live OpenBao dev server.
#
# This catches failures that `go build`/`go test` miss:
#   - missing cmd/main.go entrypoint (package compiles, binary doesn't exist)
#   - broken Factory wiring (panics or errors at backend setup)
#   - plugin RPC handshake / SDK protocol mismatches
#
# Requires: `bao` (OpenBao) on PATH, and a Go toolchain.
# Usage: scripts/registration-smoke-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_PREFIX="github.com/nicois/openbao-cloud-creds"
WORK_DIR="$(mktemp -d)"
PLUGIN_DIR="$WORK_DIR/plugins"   # only plugin binaries live here
LOG_FILE="$WORK_DIR/bao.log"     # kept OUT of PLUGIN_DIR: bao tries to exec every file in the plugin dir
mkdir -p "$PLUGIN_DIR"
ADDR="http://127.0.0.1:8200"
TOKEN="root"

cleanup() {
  [ -n "${BAO_PID:-}" ] && kill "$BAO_PID" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Discover all plugins (directories under plugins/ with a cmd/ subdir).
mapfile -t PLUGINS < <(cd "$REPO_ROOT/plugins" && for d in */; do
  name="${d%/}"
  [ -f "$name/cmd/main.go" ] && echo "$name"
done)

if [ "${#PLUGINS[@]}" -eq 0 ]; then
  echo "FAIL: no plugins with cmd/main.go found"
  exit 1
fi

echo "==> Building ${#PLUGINS[@]} plugin binaries"
for name in "${PLUGINS[@]}"; do
  echo "    building $name"
  go build -o "$PLUGIN_DIR/$name" "$MODULE_PREFIX/plugins/$name/cmd"
done

echo "==> Starting OpenBao dev server (plugin dir: $PLUGIN_DIR)"
bao server -dev \
  -dev-root-token-id="$TOKEN" \
  -dev-listen-address=127.0.0.1:8200 \
  -dev-plugin-dir="$PLUGIN_DIR" \
  > "$LOG_FILE" 2>&1 &
BAO_PID=$!

export BAO_ADDR="$ADDR"
export BAO_TOKEN="$TOKEN"

# Wait for the server to be ready FOR THE OPERATION WE DEPEND ON.
#
# `bao status` only reports seal/init state, which goes healthy before the
# mount subsystem can serve an enable write coherently to a subsequent read
# (this raced the first plugin's enable). The correct readiness gate polls
# until the dependency itself round-trips: enable a throwaway mount and
# confirm it appears in the list, then tear it down. Once this succeeds the
# mount table is verifiably serving write-then-read, so each plugin below
# needs only a single post-enable check.
READY=0
for _ in $(seq 1 60); do
  if bao status >/dev/null 2>&1 \
     && bao secrets enable -path=smoke-readiness-probe kv >/dev/null 2>&1 \
     && bao secrets list 2>/dev/null | grep -q '^smoke-readiness-probe/'; then
    bao secrets disable smoke-readiness-probe >/dev/null 2>&1 || true
    READY=1
    break
  fi
  sleep 0.5
done
if [ "$READY" -ne 1 ]; then
  echo "FAIL: OpenBao dev server did not become ready (mount round-trip never succeeded)"
  cat "$LOG_FILE"
  exit 1
fi

FAILED=0
echo "==> Registering and enabling each plugin"
for name in "${PLUGINS[@]}"; do
  sha="$(sha256sum "$PLUGIN_DIR/$name" | cut -d' ' -f1)"

  if ! bao plugin register -sha256="$sha" secret "$name" >/dev/null 2>&1; then
    echo "    FAIL: $name failed to register in plugin catalog"
    FAILED=1
    continue
  fi

  if ! bao secrets enable -path="smoke-$name" "$name" >/dev/null 2>&1; then
    echo "    FAIL: $name registered but failed to enable as a mount"
    FAILED=1
    continue
  fi

  # Confirm the mount is actually present. `enable` returning success does not
  # guarantee the mount table is immediately consistent on a subsequent `list`
  # — CI observed this lag hit different plugins on different runs (not just the
  # first), so the startup readiness gate alone is insufficient. Poll the list
  # until the mount appears, with a bounded timeout.
  mounted=0
  for _ in $(seq 1 20); do
    if bao secrets list 2>/dev/null | grep -q "^smoke-$name/"; then
      mounted=1
      break
    fi
    sleep 1
  done
  if [ "$mounted" -eq 1 ]; then
    echo "    OK:   $name"
  else
    echo "    FAIL: $name enable reported success but mount absent after polling"
    FAILED=1
  fi
done

if [ "$FAILED" -ne 0 ]; then
  echo "==> Registration smoke test FAILED"
  exit 1
fi

echo "==> All ${#PLUGINS[@]} plugins registered and enabled successfully"
