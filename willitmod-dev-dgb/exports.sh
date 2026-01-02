#!/usr/bin/env bash
set -euo pipefail

# Umbrel's auth-server signs tokens with JWT_SECRET. In some legacy-compat paths
# this isn't exported for apps, so app_proxy ends up verifying with the wrong key.
# Read it from Umbrel's .env if available so app_proxy can validate Umbrel JWTs.

if [[ -z "${JWT_SECRET:-}" ]] && [[ -n "${UMBREL_ROOT:-}" ]] && [[ -f "${UMBREL_ROOT}/.env" ]]; then
  jwt_line="$(grep -E '^JWT_SECRET=' "${UMBREL_ROOT}/.env" 2>/dev/null | tail -n 1 || true)"
  if [[ -n "${jwt_line}" ]]; then
    jwt_val="${jwt_line#JWT_SECRET=}"
    jwt_val="${jwt_val%\"}"; jwt_val="${jwt_val#\"}"
    jwt_val="${jwt_val%\'}"; jwt_val="${jwt_val#\'}"
    if [[ -n "${jwt_val}" ]]; then
      export JWT_SECRET="${jwt_val}"
    fi
  fi
fi

# Last-resort fallback (may not match Umbrel auth tokens, but avoids empty secret).
export JWT_SECRET="${JWT_SECRET:-${UMBREL_AUTH_SECRET:-DEADBEEF}}"

