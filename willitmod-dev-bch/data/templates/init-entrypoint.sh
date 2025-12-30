#!/bin/sh
set -eu

apk add --no-cache envsubst curl >/dev/null

mkdir -p /data/node /data/pool/config /data/pool/www/pool /data/ui/static

if [ -n "${APP_VERSION:-}" ] && [ -n "${UI_SOURCE_BASE:-}" ]; then
  current="$(cat /data/ui/VERSION 2>/dev/null || true)"
  if [ "$current" != "$APP_VERSION" ]; then
    echo "[axebch] Updating UI to $APP_VERSION"
    curl -fsSL "${UI_SOURCE_BASE}/data/ui/app.py" -o /data/ui/app.py
    curl -fsSL "${UI_SOURCE_BASE}/data/ui/static/index.html" -o /data/ui/static/index.html
    curl -fsSL "${UI_SOURCE_BASE}/data/ui/static/app.js" -o /data/ui/static/app.js
    curl -fsSL "${UI_SOURCE_BASE}/data/ui/static/app.css" -o /data/ui/static/app.css
    printf "%s\n" "$APP_VERSION" > /data/ui/VERSION
    chown -R 1000:1000 /data/ui
  fi
fi

if [ ! -f /data/node/bitcoin.conf ]; then
  envsubst < /data/templates/bitcoin.conf.template > /data/node/bitcoin.conf
  chown -R 1000:1000 /data/node
fi

if [ ! -f /data/pool/config/ckpool.conf ]; then
  envsubst < /data/templates/ckpool.conf.template > /data/pool/config/ckpool.conf
  chown -R 1000:1000 /data/pool
else
  if ! grep -q '"btcaddress"' /data/pool/config/ckpool.conf; then
    mv /data/pool/config/ckpool.conf "/data/pool/config/ckpool.conf.bak.$(date +%s 2>/dev/null || echo 0)" || true
    envsubst < /data/templates/ckpool.conf.template > /data/pool/config/ckpool.conf
    chown -R 1000:1000 /data/pool
  fi
fi

