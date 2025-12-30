#!/bin/sh
set -eu

echo "[axebch] BCHN entrypoint starting"

if ! command -v bitcoind >/dev/null 2>&1; then
  echo "[axebch] ERROR: bitcoind not found in PATH"
  exit 127
fi

extra=""
if [ -f /data/.reindex-chainstate ]; then
  echo "[axebch] Reindex requested (chainstate)."
  rm -f /data/.reindex-chainstate || true
  extra="-reindex-chainstate"
fi

echo "[axebch] Exec: bitcoind -datadir=/data -printtoconsole $extra"
exec bitcoind -datadir=/data -printtoconsole $extra

