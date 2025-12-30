import base64
import json
import os
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError


STATIC_DIR = Path("/data/ui/static")
CKPOOL_STATUS_DIR = Path(os.getenv("CKPOOL_STATUS_DIR", "/data/pool/www/pool"))
NODE_CONF_PATH = Path("/data/node/bitcoin.conf")

BCH_RPC_HOST = os.getenv("BCH_RPC_HOST", "bchn")
BCH_RPC_PORT = int(os.getenv("BCH_RPC_PORT", "28332"))
BCH_RPC_USER = os.getenv("BCH_RPC_USER", "bch")
BCH_RPC_PASS = os.getenv("BCH_RPC_PASS", "")


def _json(data, status=200):
    body = json.dumps(data).encode("utf-8")
    return status, body, "application/json; charset=utf-8"


def _read_static(rel_path: str):
    rel = rel_path.lstrip("/") or "index.html"
    path = (STATIC_DIR / rel).resolve()
    if not str(path).startswith(str(STATIC_DIR.resolve())):
        return 403, b"forbidden", "text/plain; charset=utf-8"
    if not path.exists() or not path.is_file():
        return 404, b"not found", "text/plain; charset=utf-8"
    suffix = path.suffix.lower()
    content_type = "application/octet-stream"
    if suffix in [".html", ".htm"]:
        content_type = "text/html; charset=utf-8"
    elif suffix == ".css":
        content_type = "text/css; charset=utf-8"
    elif suffix == ".js":
        content_type = "application/javascript; charset=utf-8"
    elif suffix == ".svg":
        content_type = "image/svg+xml"
    return 200, path.read_bytes(), content_type


def _rpc_call(method: str, params=None):
    if params is None:
        params = []
    url = f"http://{BCH_RPC_HOST}:{BCH_RPC_PORT}/"
    payload = json.dumps({"jsonrpc": "1.0", "id": "umbrel", "method": method, "params": params}).encode("utf-8")

    auth = base64.b64encode(f"{BCH_RPC_USER}:{BCH_RPC_PASS}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    return data.get("result")

def _read_conf_kv(path: Path):
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


_CONF_LINE_RE = re.compile(r"^\s*(#\s*)?(?P<key>[A-Za-z0-9_]+)\s*=\s*(?P<value>.*)\s*$")


def _set_conf_key(lines: list[str], key: str, value: str | None, *, comment_out: bool = False):
    found = False
    for i, line in enumerate(lines):
        m = _CONF_LINE_RE.match(line)
        if not m:
            continue
        if m.group("key") != key:
            continue
        found = True
        if value is None:
            lines[i] = f"# {key}=1"
        else:
            lines[i] = f"{key}={value}" if not comment_out else f"# {key}={value}"
    if not found and value is not None:
        lines.append(f"{key}={value}")


def _update_node_conf(network: str, prune: int, txindex: int):
    NODE_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    if NODE_CONF_PATH.exists():
        lines = NODE_CONF_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = []

    network = network.lower().strip()
    if network not in ["mainnet", "testnet", "regtest"]:
        raise ValueError("invalid network")

    _set_conf_key(lines, "txindex", str(int(bool(txindex))))
    _set_conf_key(lines, "prune", str(int(prune)))

    if network == "mainnet":
        _set_conf_key(lines, "testnet", "1", comment_out=True)
        _set_conf_key(lines, "regtest", "1", comment_out=True)
    elif network == "testnet":
        _set_conf_key(lines, "testnet", "1", comment_out=False)
        _set_conf_key(lines, "regtest", "1", comment_out=True)
    else:
        _set_conf_key(lines, "testnet", "1", comment_out=True)
        _set_conf_key(lines, "regtest", "1", comment_out=False)

    NODE_CONF_PATH.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _current_settings():
    conf = _read_conf_kv(NODE_CONF_PATH)
    net = "mainnet"
    if conf.get("regtest") == "1":
        net = "regtest"
    elif conf.get("testnet") == "1":
        net = "testnet"
    prune = int(conf.get("prune") or 550)
    txindex = int(conf.get("txindex") or 0)
    return {"network": net, "prune": prune, "txindex": txindex}


def _node_status():
    info = _rpc_call("getblockchaininfo")
    net = _rpc_call("getnetworkinfo")
    mempool = _rpc_call("getmempoolinfo")

    blocks = int(info.get("blocks") or 0)
    headers = int(info.get("headers") or blocks)
    progress = float(info.get("verificationprogress") or 0.0)
    ibd = bool(info.get("initialblockdownload", False))

    return {
        "chain": info.get("chain"),
        "blocks": blocks,
        "headers": headers,
        "verificationprogress": progress,
        "initialblockdownload": ibd,
        "connections": int(net.get("connections") or 0),
        "subversion": str(net.get("subversion") or ""),
        "mempool_bytes": int(mempool.get("bytes") or 0),
    }


def _read_pool_status_raw():
    candidates = [
        CKPOOL_STATUS_DIR / "pool.status",
        Path("/data/pool/www/pool.status"),
        Path("/data/pool/www/pool/pool.status"),
    ]
    for path in candidates:
        if path.exists() and path.is_file():
            try:
                return path.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                continue
    return ""


def _parse_pool_status(raw: str):
    if not raw:
        return {"workers": 0, "hashrate_ths": None, "best_share": None}

    try:
        data = json.loads(raw)
        return {
            "workers": int(data.get("workers") or 0),
            "hashrate_ths": data.get("hashrate"),
            "best_share": data.get("bestshare") or data.get("best_share"),
        }
    except Exception:
        return {"workers": 0, "hashrate_ths": None, "best_share": None}


def _widget_sync():
    try:
        s = _node_status()
        progress = max(0.0, min(1.0, float(s["verificationprogress"])))
        pct = int(progress * 100)
        label = "In progress" if s["initialblockdownload"] else "Synchronized"
        return {
            "type": "text-with-progress",
            "title": "BCH sync",
            "text": f"{pct}%",
            "progressLabel": label,
            "progress": progress,
        }
    except Exception:
        return {
            "type": "text-with-progress",
            "title": "BCH sync",
            "text": "—",
            "progressLabel": "Unavailable",
            "progress": 0,
        }


def _widget_pool():
    p = _parse_pool_status(_read_pool_status_raw())
    return {
        "type": "three-stats",
        "items": [
            {"title": "Hashrate", "text": str(p.get("hashrate_ths") or "—"), "subtext": "TH/s"},
            {"title": "Workers", "text": str(p.get("workers") or 0)},
            {"title": "Best Share", "text": str(p.get("best_share") or "—")},
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "willitmod-dev-bch/0.2"

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/settings":
            return self._send(*_json(_current_settings()))

        if self.path == "/api/node":
            try:
                return self._send(*_json(_node_status()))
            except (HTTPError, URLError, RuntimeError) as e:
                return self._send(*_json({"error": str(e)}, status=503))

        if self.path == "/api/pool":
            return self._send(*_json(_parse_pool_status(_read_pool_status_raw())))

        if self.path == "/api/widget/sync":
            return self._send(*_json(_widget_sync()))

        if self.path == "/api/widget/pool":
            return self._send(*_json(_widget_pool()))

        status, body, ct = _read_static(self.path if self.path != "/" else "/index.html")
        return self._send(status, body, ct)

    def do_POST(self):
        if self.path != "/api/settings":
            return self._send(*_json({"error": "not found"}, status=404))

        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._send(*_json({"error": "invalid json"}, status=400))

        network = str(body.get("network") or "").strip().lower()
        prune_raw = body.get("prune")
        txindex_raw = body.get("txindex")

        try:
            prune = int(prune_raw)
        except Exception:
            return self._send(*_json({"error": "invalid prune"}, status=400))

        if prune != 0 and prune < 550:
            return self._send(*_json({"error": "prune must be 0 or >= 550"}, status=400))

        txindex = 1 if bool(txindex_raw) else 0

        try:
            _update_node_conf(network=network, prune=prune, txindex=txindex)
        except Exception as e:
            return self._send(*_json({"error": str(e)}, status=400))

        return self._send(*_json({"ok": True, "restartRequired": True}))


def main():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    CKPOOL_STATUS_DIR.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()


if __name__ == "__main__":
    main()
