import base64
import io
import json
import math
import os
import platform
import re
import threading
import time
import urllib.request
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit


_DEFAULT_STATIC_DIR = "/app/static" if Path("/app/static").exists() else "/data/ui/static"
STATIC_DIR = Path(os.getenv("STATIC_DIR", _DEFAULT_STATIC_DIR))
MININGCORE_API_URL = os.getenv("MININGCORE_API_URL", "http://miningcore:4000").strip().rstrip("/")
MININGCORE_POOL_ID = os.getenv("MININGCORE_POOL_ID", "dgb-sha256-1").strip()
MININGCORE_CONF_PATH = Path(os.getenv("MININGCORE_CONF_PATH", "/data/pool/config/miningcore.json"))
NODE_CONF_PATH = Path("/data/node/digibyte.conf")
NODE_LOG_PATH = Path("/data/node/debug.log")
NODE_REINDEX_FLAG_PATH = Path("/data/node/.reindex-chainstate")
STATE_DIR = Path("/data/ui/state")
POOL_SERIES_PATH = STATE_DIR / "pool_timeseries.jsonl"
POOL_SETTINGS_STATE_PATH = STATE_DIR / "pool_settings.json"
INSTALL_ID_PATH = STATE_DIR / "install_id.txt"
NODE_CACHE_PATH = STATE_DIR / "node_cache.json"
POOL_CACHE_PATH = STATE_DIR / "pool_cache.json"
CHECKIN_STATE_PATH = STATE_DIR / "checkin.json"
POOL_PLACEHOLDER_PAYOUT_ADDRESS = "CHANGEME_DGB_PAYOUT_ADDRESS"

APP_CHANNEL = os.getenv("APP_CHANNEL", "").strip()
DGB_IMAGE = os.getenv("DGB_IMAGE", "").strip()
MININGCORE_IMAGE = os.getenv("MININGCORE_IMAGE", "").strip()
POSTGRES_IMAGE = os.getenv("POSTGRES_IMAGE", "").strip()
DEFAULT_SUPPORT_BASE_URL = "https://axebench.dreamnet.uk"
INSTALL_ID_HEADER = "X-Install-Id"

def _env_or_default(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    val = raw.strip()
    return val or default


SUPPORT_CHECKIN_URL = _env_or_default("SUPPORT_CHECKIN_URL", f"{DEFAULT_SUPPORT_BASE_URL}/api/telemetry/ping")
SUPPORT_TICKET_URL = _env_or_default("SUPPORT_TICKET_URL", f"{DEFAULT_SUPPORT_BASE_URL}/api/support/upload")

APP_ID = "willitmod-dev-dgb"
APP_VERSION = "0.7.56-alpha"

DGB_RPC_HOST = os.getenv("DGB_RPC_HOST", "dgbd")
DGB_RPC_PORT = int(os.getenv("DGB_RPC_PORT", "14022"))
DGB_RPC_USER = os.getenv("DGB_RPC_USER", "dgb")
DGB_RPC_PASS = os.getenv("DGB_RPC_PASS", "")

SAMPLE_INTERVAL_S = int(os.getenv("SERIES_SAMPLE_INTERVAL_S", "30"))
MAX_RETENTION_S = int(os.getenv("SERIES_MAX_RETENTION_S", str(7 * 24 * 60 * 60)))
MAX_SERIES_POINTS = int(os.getenv("SERIES_MAX_POINTS", "20000"))

INSTALL_ID = None


class RpcError(RuntimeError):
    def __init__(self, code: int | None, message: str, raw=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.raw = raw


def _json(data, status=200):
    body = json.dumps(data).encode("utf-8")
    return status, body, "application/json; charset=utf-8"


def _read_static(rel_path: str):
    # Ignore query-string fragments (e.g. /app.js?v=... for cache-busting).
    rel = urlsplit(rel_path).path.lstrip("/") or "index.html"
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
    rpc_port = _effective_rpc_port()
    url = f"http://{DGB_RPC_HOST}:{rpc_port}/"
    payload = json.dumps({"jsonrpc": "1.0", "id": "umbrel", "method": method, "params": params}).encode("utf-8")

    auth = base64.b64encode(f"{DGB_RPC_USER}:{DGB_RPC_PASS}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method="POST",
    )
    last_err = None
    for attempt in range(2):
        try:
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            except HTTPError as e:
                # Bitcoin-style JSON-RPC returns HTTP 500 for application errors (e.g. warmup -28).
                # Parse the JSON body so callers can handle structured error codes/messages.
                raw = e.read()
                data = json.loads(raw.decode("utf-8", errors="replace"))
            last_err = None
            break
        except Exception as e:
            last_err = e
            if attempt == 0:
                time.sleep(0.4)
                continue
            raise
    if last_err is not None:
        raise last_err
    if data.get("error"):
        err = data["error"]
        code = None
        msg = None
        if isinstance(err, dict):
            try:
                code = int(err.get("code")) if err.get("code") is not None else None
            except Exception:
                code = None
            msg = str(err.get("message") or "")
        if not msg:
            msg = str(err)
        raise RpcError(code, msg, raw=err)
    return data.get("result")


def _read_conf_kv_in_section(path: Path, section: str) -> dict:
    if not path.exists():
        return {}
    header = f"[{section}]"
    in_section = False
    out = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_section = (line == header)
            continue
        if not in_section or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _effective_rpc_port() -> int:
    try:
        conf = _read_conf_kv(NODE_CONF_PATH)
        net = "mainnet"
        if conf.get("regtest") == "1":
            net = "regtest"
        elif conf.get("testnet") == "1":
            net = "testnet"

        if net == "testnet":
            sec = _read_conf_kv_in_section(NODE_CONF_PATH, "test")
            if sec.get("rpcport"):
                return int(sec["rpcport"])
            if conf.get("rpcport"):
                return int(conf["rpcport"])
            return 14023

        if net == "regtest":
            sec = _read_conf_kv_in_section(NODE_CONF_PATH, "regtest")
            if sec.get("rpcport"):
                return int(sec["rpcport"])
            if conf.get("rpcport"):
                return int(conf["rpcport"])
            return 18443

        if conf.get("rpcport"):
            return int(conf["rpcport"])
        return int(DGB_RPC_PORT)
    except Exception:
        return int(DGB_RPC_PORT)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def _write_text(path: Path, value: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.strip() + "\n", encoding="utf-8")


def _get_or_create_install_id() -> str:
    existing = _read_text(INSTALL_ID_PATH)
    if existing:
        return existing
    new_id = uuid.uuid4().hex
    _write_text(INSTALL_ID_PATH, new_id)
    return new_id


def _read_json(path: Path) -> dict:
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_json(path: Path, data: dict):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception:
        pass


def _post_json(url: str, payload: dict, *, timeout_s: int = 6, headers: dict | None = None):
    body = json.dumps(payload).encode("utf-8")
    all_headers = {"Content-Type": "application/json"}
    if headers:
        all_headers.update(headers)
    req = urllib.request.Request(
        url,
        data=body,
        headers=all_headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return resp.status, resp.read()


def _encode_multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]):
    boundary = uuid.uuid4().hex
    crlf = "\r\n"
    body = bytearray()

    for name, value in fields.items():
        body.extend(f"--{boundary}{crlf}".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"{crlf}{crlf}'.encode("utf-8"))
        body.extend(value.encode("utf-8"))
        body.extend(crlf.encode("utf-8"))

    for name, (filename, data, content_type) in files.items():
        body.extend(f"--{boundary}{crlf}".encode("utf-8"))
        body.extend(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"{crlf}'.encode("utf-8")
        )
        body.extend(f"Content-Type: {content_type}{crlf}{crlf}".encode("utf-8"))
        body.extend(data)
        body.extend(crlf.encode("utf-8"))

    body.extend(f"--{boundary}--{crlf}".encode("utf-8"))
    return boundary, bytes(body)


def _post_support_bundle(url: str, *, bundle_bytes: bytes, filename: str, timeout_s: int = 20):
    boundary, body = _encode_multipart(fields={}, files={"bundle": (filename, bundle_bytes, "application/zip")})
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        INSTALL_ID_HEADER: str(INSTALL_ID or ""),
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return resp.status, resp.read()


def _support_payload_base() -> dict:
    return {
        "install_id": INSTALL_ID,
        "app_id": APP_ID,
        "app_version": APP_VERSION,
        "channel": APP_CHANNEL or None,
        "arch": platform.machine(),
        "ts": int(time.time()),
    }


def _support_checkin_once():
    try:
        now = time.time()
        st = _read_json(CHECKIN_STATE_PATH)
        last = float(st.get("last_ping_at") or 0.0)
        if (now - last) < float(24 * 60 * 60):
            return
        payload = {"app": "AxeDGB", "version": APP_VERSION}
        _post_json(SUPPORT_CHECKIN_URL, payload, timeout_s=6, headers={INSTALL_ID_HEADER: str(INSTALL_ID or "")})
        _write_json(CHECKIN_STATE_PATH, {"last_ping_at": now})
    except Exception:
        pass


def _support_checkin_loop(stop_event: threading.Event):
    _support_checkin_once()
    while not stop_event.is_set():
        stop_event.wait(24 * 60 * 60)
        if stop_event.is_set():
            break
        _support_checkin_once()

def _read_conf_kv(path: Path):
    if not path.exists():
        return {}
    out = {}
    in_section = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_section = True
            continue
        if in_section:
            # Ignore section-scoped settings like [test]/[regtest] so they don't override global values.
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


def _conf_find_section(lines: list[str], name: str) -> tuple[int, int]:
    header = f"[{name}]"
    start = None
    for i, line in enumerate(lines):
        if line.strip() == header:
            start = i
            break
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        start = len(lines)
        lines.append(header)
        lines.append("")
        return start, len(lines)

    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].lstrip().startswith("[") and lines[j].rstrip().endswith("]"):
            end = j
            break
    return start, end


def _set_conf_key_in_range(lines: list[str], start: int, end: int, key: str, value: str):
    found = False
    for i in range(start, end):
        m = _CONF_LINE_RE.match(lines[i])
        if not m:
            continue
        if m.group("key") != key:
            continue
        lines[i] = f"{key}={value}"
        found = True
    if not found:
        insert_at = end
        while insert_at > start and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines.insert(insert_at, f"{key}={value}")


def _ensure_addnodes_in_range(lines: list[str], start: int, end: int, nodes: list[str]):
    existing = set()
    for i in range(start, end):
        line = lines[i].strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == "addnode":
            existing.add(v.strip())

    to_add = [n for n in nodes if n not in existing]
    if not to_add:
        return

    insert_at = end
    while insert_at > start and not lines[insert_at - 1].strip():
        insert_at -= 1
    for n in to_add:
        lines.insert(insert_at, f"addnode={n}")
        insert_at += 1


def _update_miningcore_daemon_port(network: str):
    if not MININGCORE_CONF_PATH.exists():
        return
    try:
        conf = _read_miningcore_conf()
        pools = conf.get("pools") or []
        if not isinstance(pools, list):
            return

        port = 14022
        if network == "testnet":
            port = 14023
        elif network == "regtest":
            # Best-effort; regtest is not a supported mining target in AxeDGB.
            port = 18443

        for pool in pools:
            if not isinstance(pool, dict):
                continue
            if str(pool.get("id") or "") != MININGCORE_POOL_ID:
                continue
            daemons = pool.get("daemons") or []
            if not isinstance(daemons, list):
                continue
            for d in daemons:
                if isinstance(d, dict):
                    d["port"] = int(port)
        _write_miningcore_conf(conf)
    except Exception:
        return


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
        _set_conf_key(lines, "port", "12024")
        _set_conf_key(lines, "rpcport", "14022")
        _set_conf_key(lines, "testnet", "1", comment_out=True)
        _set_conf_key(lines, "regtest", "1", comment_out=True)
    elif network == "testnet":
        _set_conf_key(lines, "port", "12026")
        _set_conf_key(lines, "rpcport", "14023")
        _set_conf_key(lines, "testnet", "1", comment_out=False)
        _set_conf_key(lines, "regtest", "1", comment_out=True)
    else:
        _set_conf_key(lines, "port", "18444")
        _set_conf_key(lines, "rpcport", "18443")
        _set_conf_key(lines, "testnet", "1", comment_out=True)
        _set_conf_key(lines, "regtest", "1", comment_out=False)

    # DigiByte only applies several settings to testnet/regtest when placed in a section block.
    # Ensure testnet has sane defaults + bootstrap nodes so peers don't stay at 0.
    if network == "testnet":
        s, e = _conf_find_section(lines, "test")
        s += 1
        test_p2p_port = 12026
        test_rpc_port = 14023  # observed default for DigiByte 7.17.x testnet4
        _set_conf_key_in_range(lines, s, e, "port", str(test_p2p_port))
        _set_conf_key_in_range(lines, s, e, "rpcport", str(test_rpc_port))
        _set_conf_key_in_range(lines, s, e, "rpcbind", "0.0.0.0")
        _set_conf_key_in_range(lines, s, e, "zmqpubhashblock", "tcp://0.0.0.0:28344")
        _ensure_addnodes_in_range(
            lines,
            s,
            e,
            [
                "testnet-seed.digibyte.org:12026",
                "95.179.160.53:12026",
                "51.15.113.125:12026",
            ],
        )

    NODE_CONF_PATH.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    _update_miningcore_daemon_port(network)


def _tail_text(path: Path, *, max_bytes: int = 64 * 1024) -> str:
    try:
        if not path.exists():
            return ""
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        with path.open("rb") as f:
            f.seek(start)
            raw = f.read()
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _detect_reindex_required() -> bool:
    txt = _tail_text(NODE_LOG_PATH)
    if not txt:
        return False
    lowered = txt.lower()
    return ("previously been pruned" in lowered) and ("reindex" in lowered)


def _request_reindex_chainstate():
    try:
        NODE_REINDEX_FLAG_PATH.parent.mkdir(parents=True, exist_ok=True)
        NODE_REINDEX_FLAG_PATH.write_text(str(int(time.time())) + "\n", encoding="utf-8")
    except Exception:
        pass


def _build_support_bundle_zip(payload: dict) -> tuple[bytes, str]:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ticket.json", json.dumps(payload, indent=2, sort_keys=True))
        zf.writestr("about.json", json.dumps(_about(), indent=2, sort_keys=True))
        zf.writestr("settings.json", json.dumps(_current_settings(), indent=2, sort_keys=True))
    name = f"axedgb-support-{int(time.time())}.zip"
    return bio.getvalue(), name


def _current_settings():
    conf = _read_conf_kv(NODE_CONF_PATH)
    net = "mainnet"
    if conf.get("regtest") == "1":
        net = "regtest"
    elif conf.get("testnet") == "1":
        net = "testnet"
    prune = int(conf.get("prune") or 0)
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

    status = {
        "chain": info.get("chain"),
        "blocks": blocks,
        "headers": headers,
        "verificationprogress": progress,
        "initialblockdownload": ibd,
        "connections": int(net.get("connections") or 0),
        "subversion": str(net.get("subversion") or ""),
        "mempool_bytes": int(mempool.get("bytes") or 0),
    }

    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        NODE_CACHE_PATH.write_text(json.dumps({"t": int(time.time()), "status": status}) + "\n", encoding="utf-8")
    except Exception:
        pass

    return status


def _read_node_cache():
    try:
        if not NODE_CACHE_PATH.exists():
            return None
        obj = json.loads(NODE_CACHE_PATH.read_text(encoding="utf-8", errors="replace"))
        t = int(obj.get("t") or 0)
        status = obj.get("status") or {}
        if not isinstance(status, dict):
            return None
        return {"t": t, "status": status}
    except Exception:
        return None


def _write_pool_cache(status: dict):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        POOL_CACHE_PATH.write_text(json.dumps({"t": int(time.time()), "status": status}) + "\n", encoding="utf-8")
    except Exception:
        pass


def _read_pool_cache():
    try:
        if not POOL_CACHE_PATH.exists():
            return None
        obj = json.loads(POOL_CACHE_PATH.read_text(encoding="utf-8", errors="replace"))
        t = int(obj.get("t") or 0)
        status = obj.get("status") or {}
        if not isinstance(status, dict):
            return None
        return {"t": t, "status": status}
    except Exception:
        return None


def _about():
    node = None
    node_error = None
    try:
        node = _node_status()
    except Exception as e:
        node_error = str(e)

    return {
        "channel": APP_CHANNEL or None,
        "images": {
            "dgbd": DGB_IMAGE or None,
            "miningcore": MININGCORE_IMAGE or None,
            "postgres": POSTGRES_IMAGE or None,
        },
        "node": node,
        "nodeError": node_error,
        "pool": _pool_settings(),
    }


def _extract_json_obj(text: str):
    s = text.strip()
    if not s:
        raise ValueError("empty json")

    try:
        return json.loads(s)
    except Exception:
        pass

    last = s.rfind("}")
    while last != -1:
        try:
            return json.loads(s[: last + 1])
        except Exception:
            last = s.rfind("}", 0, last)
    raise ValueError("invalid json")


def _read_miningcore_conf() -> dict:
    if not MININGCORE_CONF_PATH.exists():
        return {}
    return _extract_json_obj(MININGCORE_CONF_PATH.read_text(encoding="utf-8", errors="replace"))


def _write_miningcore_conf(conf: dict):
    try:
        if isinstance(conf, dict):
            conf.setdefault("notifications", {"enabled": False})
            banning = conf.get("banning")
            if isinstance(banning, dict):
                banning.pop("manager", None)
            pools = conf.get("pools")
            if isinstance(pools, list):
                for pool in pools:
                    if not isinstance(pool, dict):
                        continue
                    pp = pool.get("paymentProcessing")
                    if pp is None:
                        pool["paymentProcessing"] = {"enabled": False}
                    elif isinstance(pp, dict):
                        pp.setdefault("enabled", False)
    except Exception:
        pass
    MININGCORE_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    MININGCORE_CONF_PATH.write_text(json.dumps(conf, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_pool_settings_state() -> dict:
    try:
        if not POOL_SETTINGS_STATE_PATH.exists():
            return {}
        obj = json.loads(POOL_SETTINGS_STATE_PATH.read_text(encoding="utf-8", errors="replace"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _write_pool_settings_state(obj: dict):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        POOL_SETTINGS_STATE_PATH.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception:
        pass


def _to_int(value, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _maybe_int(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return int(value)
    s = str(value).strip()
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def _pool_settings():
    conf_addr = ""
    mindiff = None
    startdiff = None
    maxdiff = None

    try:
        conf = _read_miningcore_conf()
        pools = conf.get("pools") or []
        pool_conf = None
        if isinstance(pools, list):
            for item in pools:
                if isinstance(item, dict) and str(item.get("id") or "") == MININGCORE_POOL_ID:
                    pool_conf = item
                    break
            if pool_conf is None:
                for item in pools:
                    if isinstance(item, dict):
                        pool_conf = item
                        break
        if isinstance(pool_conf, dict):
            conf_addr = str(pool_conf.get("address") or "").strip()
            ports = pool_conf.get("ports") or {}
            if isinstance(ports, dict) and ports:
                first = next(iter(ports.values()))
                if isinstance(first, dict):
                    startdiff = first.get("difficulty")
                    vardiff = first.get("varDiff") or {}
                    if isinstance(vardiff, dict):
                        mindiff = vardiff.get("minDiff")
                        maxdiff = vardiff.get("maxDiff")
    except Exception:
        conf_addr = ""

    state = _read_pool_settings_state()
    validated = state.get("validated")
    validation_warning = state.get("validationWarning")

    payout_address = conf_addr
    configured = bool(payout_address) and payout_address != POOL_PLACEHOLDER_PAYOUT_ADDRESS

    if validated is not None:
        validated = bool(validated)
    if not isinstance(validation_warning, str):
        validation_warning = None

    return {
        "payoutAddress": payout_address or "",
        "configured": configured,
        "validated": validated,
        "validationWarning": validation_warning,
        "mindiff": _to_int(mindiff, 1024),
        "startdiff": _to_int(startdiff, 1024),
        "maxdiff": _to_int(maxdiff, 0),
        "warning": (
            "Set a payout address before mining. Miningcore uses this address when generating blocks."
            if not configured
            else None
        ),
    }


def _update_pool_settings(
    *,
    payout_address: str,
    mindiff=None,
    startdiff=None,
    maxdiff=None,
):
    addr = payout_address.strip()
    if not addr:
        raise ValueError("payoutAddress is required")

    validated = None
    validation_warning = None
    try:
        res = _rpc_call("validateaddress", [addr]) or {}
    except Exception:
        res = None
        validated = None
        validation_warning = (
            "Node RPC unavailable; saved without RPC validation. Double-check your address, then restart the app."
        )
    else:
        validated = bool(res.get("isvalid")) if isinstance(res, dict) else False
        if not validated:
            raise ValueError("payoutAddress is not a valid DigiByte address")

    conf = _read_miningcore_conf()
    pools = conf.get("pools")
    if not isinstance(pools, list):
        pools = []
        conf["pools"] = pools

    pool_conf = None
    for item in pools:
        if isinstance(item, dict) and str(item.get("id") or "") == MININGCORE_POOL_ID:
            pool_conf = item
            break
    if pool_conf is None:
        pool_conf = {"id": MININGCORE_POOL_ID, "enabled": True, "coin": "digibyte-sha256"}
        pools.append(pool_conf)
    pool_conf["address"] = addr

    md = _maybe_int(mindiff)
    sd = _maybe_int(startdiff)
    xd = _maybe_int(maxdiff)
    try:
        ports = pool_conf.get("ports") or {}
        if not isinstance(ports, dict):
            ports = {}
            pool_conf["ports"] = ports
        if ports:
            port_key = next(iter(ports.keys()))
        else:
            port_key = "3333"
            ports[port_key] = {"listenAddress": "0.0.0.0"}

        endpoint = ports.get(port_key)
        if not isinstance(endpoint, dict):
            endpoint = {"listenAddress": "0.0.0.0"}
            ports[port_key] = endpoint

        vardiff = endpoint.get("varDiff") or {}
        if not isinstance(vardiff, dict):
            vardiff = {}
        endpoint["varDiff"] = vardiff

        md_existing = _maybe_int(vardiff.get("minDiff")) or 1024
        sd_existing = _maybe_int(endpoint.get("difficulty")) or 1024
        xd_existing = _maybe_int(vardiff.get("maxDiff")) or 0

        md = md if md is not None else md_existing
        sd = sd if sd is not None else sd_existing
        xd = xd if xd is not None else xd_existing

        if md < 1:
            raise ValueError("mindiff must be >= 1")
        if sd < md:
            raise ValueError("startdiff must be >= mindiff")
        if xd != 0 and xd < sd:
            raise ValueError("maxdiff must be 0 (no limit) or >= startdiff")

        endpoint["difficulty"] = int(sd)
        vardiff["minDiff"] = int(md)
        vardiff["maxDiff"] = None if int(xd) == 0 else int(xd)
    except (TypeError, ValueError):
        raise
    except Exception:
        # Fall back to safe defaults.
        pool_conf.setdefault("ports", {"3333": {"listenAddress": "0.0.0.0"}})
        endpoint = next(iter(pool_conf["ports"].values()))
        if isinstance(endpoint, dict):
            endpoint.setdefault("difficulty", 1024)
            endpoint.setdefault("varDiff", {})
            if isinstance(endpoint["varDiff"], dict):
                endpoint["varDiff"].setdefault("minDiff", 1024)
                endpoint["varDiff"].setdefault("maxDiff", None)

    _write_miningcore_conf(conf)
    _write_pool_settings_state(
        {
            "validated": bool(validated) if validated is not None else None,
            "validationWarning": validation_warning,
            "updatedAt": int(time.time()),
        }
    )

    return _pool_settings()


def _miningcore_get_json(path: str, *, timeout_s: int = 8) -> dict:
    base = MININGCORE_API_URL
    if not base:
        raise RuntimeError("MININGCORE_API_URL not set")
    if not path.startswith("/"):
        path = "/" + path
    url = base + path
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _dget(obj: dict, *keys, default=None):
    if not isinstance(obj, dict):
        return default
    for key in keys:
        if key in obj:
            return obj.get(key)
    return default


def _pool_status():
    try:
        data = _miningcore_get_json(f"/api/pools/{MININGCORE_POOL_ID}")
        pool = _dget(data, "pool", "Pool", default={}) or {}
        stats = _dget(pool, "poolStats", "PoolStats", default={}) or {}

        connected = _dget(stats, "connectedMiners", "ConnectedMiners", default=0) or 0
        hashrate_hs = _dget(stats, "poolHashrate", "PoolHashrate", default=0) or 0
        effort = _dget(pool, "poolEffort", "PoolEffort", default=None)

        try:
            workers_i = int(connected)
        except Exception:
            workers_i = 0
        try:
            hashrate_ths = float(hashrate_hs) / 1e12
        except Exception:
            hashrate_ths = None

        try:
            effort_pct = float(effort) if effort is not None else None
        except Exception:
            effort_pct = None

        status = {
            "backend": "miningcore",
            "poolId": MININGCORE_POOL_ID,
            "workers": workers_i,
            "hashrate_ths": hashrate_ths,
            "effort_percent": effort_pct,
            "hashrates_ths": {},
            "cached": False,
            "lastSeen": int(time.time()),
        }
        _write_pool_cache(status)
        return status
    except Exception as e:
        cached = _read_pool_cache()
        if cached:
            status = dict(cached["status"])
            status.update(
                {
                    "cached": True,
                    "lastSeen": int(cached["t"]),
                    "error": str(e),
                }
            )
            status.setdefault("backend", "miningcore")
            status.setdefault("poolId", MININGCORE_POOL_ID)
            status.setdefault("workers", 0)
            status.setdefault("hashrate_ths", None)
            status.setdefault("effort_percent", None)
            status.setdefault("hashrates_ths", {})
            return status

        return {
            "backend": "miningcore",
            "poolId": MININGCORE_POOL_ID,
            "workers": 0,
            "hashrate_ths": None,
            "effort_percent": None,
            "hashrates_ths": {},
            "cached": False,
            "lastSeen": int(time.time()),
            "error": str(e),
        }


def _read_pool_status_raw():
    def iter_candidates(filename: str):
        bases = [
            Path("/data/pool/www/pool"),
            Path("/data/pool/www"),
        ]
        seen = set()
        for base in bases:
            if not isinstance(base, Path):
                continue
            for p in [
                base / filename,
                base.parent / filename,
                base / "pool" / filename,
                base.parent / "pool" / filename,
            ]:
                if p in seen:
                    continue
                seen.add(p)
                yield p
            try:
                for p in base.glob(f"*/{filename}"):
                    if p in seen:
                        continue
                    seen.add(p)
                    yield p
            except Exception:
                continue

    entries = []
    for path in iter_candidates("pool.status"):
        if not (path.exists() and path.is_file()):
            continue
        try:
            entries.append((float(path.stat().st_mtime), path.read_text(encoding="utf-8", errors="replace").strip()))
        except Exception:
            continue

    if not entries:
        return ""

    non_empty = [e for e in entries if e[1]]
    if non_empty:
        return max(non_empty, key=lambda x: x[0])[1]
    return max(entries, key=lambda x: x[0])[1]

def _read_pool_workers_raw():
    def iter_candidates(filename: str):
        bases = [
            Path("/data/pool/www/pool"),
            Path("/data/pool/www"),
        ]
        seen = set()
        for base in bases:
            if not isinstance(base, Path):
                continue
            for p in [
                base / filename,
                base.parent / filename,
                base / "pool" / filename,
                base.parent / "pool" / filename,
            ]:
                if p in seen:
                    continue
                seen.add(p)
                yield p
            try:
                for p in base.glob(f"*/{filename}"):
                    if p in seen:
                        continue
                    seen.add(p)
                    yield p
            except Exception:
                continue

    entries = []
    for path in iter_candidates("pool.workers"):
        if not (path.exists() and path.is_file()):
            continue
        try:
            entries.append((float(path.stat().st_mtime), path.read_text(encoding="utf-8", errors="replace").strip()))
        except Exception:
            continue

    if not entries:
        return ""

    non_empty = [e for e in entries if e[1]]
    if non_empty:
        return max(non_empty, key=lambda x: x[0])[1]
    return max(entries, key=lambda x: x[0])[1]


def _parse_pool_status(raw: str):
    if not raw:
        return {"workers": 0, "hashrate_ths": None, "best_share": None}

    def to_int(value):
        try:
            return int(str(value).strip())
        except Exception:
            return 0

    def to_hashrate_ths(value):
        if value is None:
            return None
        if isinstance(value, (int, float)):
            try:
                return float(value)
            except Exception:
                return None

        s = str(value).strip()
        if not s:
            return None
        s = s.replace(",", "")
        # Extract leading float (supports scientific notation).
        m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)", s)
        if not m:
            return None
        try:
            n = float(m.group(1))
        except Exception:
            return None

        rest = s[m.end() :].strip().replace("/", " ")
        # Find unit token like H/KH/MH/GH/TH/PH/EH, but also handle ckpool's
        # shorthand like "78.6G" / "8.06T" (no "H").
        unit = ""
        unit_match = re.search(r"(?i)\b([kmgtep]?h)\b", rest)
        if unit_match:
            unit = unit_match.group(1).lower().strip()
        else:
            shorthand = re.search(r"(?i)\b([kmgtep])\b", rest)
            if shorthand:
                unit = f"{shorthand.group(1).lower()}h"
            elif re.search(r"(?i)\bh\b", rest):
                unit = "h"

        # No unit: assume TH/s (historical behavior of this app).
        if not unit:
            return n

        scale_to_ths = {
            "h": 1e-12,
            "kh": 1e-9,
            "mh": 1e-6,
            "gh": 1e-3,
            "th": 1.0,
            "ph": 1e3,
            "eh": 1e6,
        }
        factor = scale_to_ths.get(unit)
        if factor is None:
            return None
        return n * factor

    def normalize(data: dict):
        if not isinstance(data, dict):
            return {"workers": 0, "hashrate_ths": None, "best_share": None}
        workers = (
            data.get("workers")
            or data.get("Workers")
            or data.get("Users")
            or data.get("users")
            or data.get("active_workers")
            or data.get("activeWorkers")
        )

        hashrates_raw = {
            "1m": data.get("hashrate1m"),
            "5m": data.get("hashrate5m"),
            "15m": data.get("hashrate15m"),
            "1h": data.get("hashrate1hr") or data.get("hashrate1h"),
            "6h": data.get("hashrate6hr") or data.get("hashrate6h"),
            "1d": data.get("hashrate1d"),
            "7d": data.get("hashrate7d"),
        }
        hashrates_ths = {}
        for k, v in hashrates_raw.items():
            if v is None or (isinstance(v, str) and not v.strip()):
                continue
            hashrates_ths[k] = to_hashrate_ths(v)

        hashrate = (
            data.get("hashrate_ths")
            or data.get("hashrateThs")
            or data.get("hashrate")
            or data.get("Hashrate")
            or data.get("rate")
        )
        if hashrate is None:
            for k in ["1m", "5m", "15m", "1h", "6h", "1d", "7d"]:
                if k in hashrates_raw and hashrates_raw[k] is not None:
                    hashrate = hashrates_raw[k]
                    break

        best_share = data.get("bestshare") or data.get("best_share") or data.get("bestShare") or data.get("best")
        return {
            "workers": to_int(workers),
            "hashrate_ths": to_hashrate_ths(hashrate),
            "best_share": best_share,
            "hashrates_ths": hashrates_ths or None,
        }

    def merge_json_objects(text: str) -> dict | None:
        merged = {}
        found = False
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if not (line.startswith("{") and line.endswith("}")):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                merged.update(obj)
                found = True
        return merged if found else None

    merged = merge_json_objects(raw)
    if merged is not None:
        return normalize(merged)

    # Prefer JSON (ckpool often writes JSON, but can include extra log noise).
    try:
        return normalize(_extract_json_obj(raw))
    except Exception:
        try:
            start = raw.find("{")
            if start != -1:
                return normalize(_extract_json_obj(raw[start:]))
        except Exception:
            pass

    # Fallback: parse key/value lines.
    data = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
        elif ":" in line:
            key, val = line.split(":", 1)
        else:
            continue
        data[key.strip()] = val.strip()

    return normalize(data)

def _parse_pool_workers(raw: str):
    if not raw:
        return []

    # Best case: JSON list or object
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Some formats store under a key
            for key in ["workers", "data", "result"]:
                if isinstance(data.get(key), list):
                    return data[key]
            # Or a dict keyed by worker
            if all(isinstance(v, dict) for v in data.values()):
                out = []
                for k, v in data.items():
                    item = dict(v)
                    item.setdefault("worker", k)
                    out.append(item)
                return out
    except Exception:
        pass

    # Fallback: parse lines "worker ... lastshare ..."
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p for p in line.replace("\t", " ").split(" ") if p]
        if not parts:
            continue
        out.append({"worker": parts[0], "raw": line})
    return out


def _support_ticket_payload(*, subject: str, message: str, email: str | None):
    diagnostics = {}
    try:
        node = _node_status()
        diagnostics["node"] = {
            "chain": node.get("chain"),
            "blocks": node.get("blocks"),
            "headers": node.get("headers"),
            "progress": node.get("verificationprogress"),
            "connections": node.get("connections"),
            "subversion": node.get("subversion"),
            "mempool_bytes": node.get("mempool_bytes"),
        }
    except Exception as e:
        diagnostics["node_error"] = str(e)

    try:
        pool = _pool_status()
        diagnostics["pool"] = {
            "workers": pool.get("workers"),
            "hashrate_ths": pool.get("hashrate_ths"),
            "effort_percent": pool.get("effort_percent"),
        }
    except Exception as e:
        diagnostics["pool_error"] = str(e)

    payload = _support_payload_base()
    payload.update(
        {
            "type": "support_ticket",
            "subject": subject,
            "message": message,
            "email": email or None,
            "diagnostics": diagnostics,
        }
    )
    return payload


def _now_ms():
    return int(time.time() * 1000)


class PoolSeries:
    def __init__(self):
        self._lock = threading.Lock()
        self._points: list[dict] = []

    def load(self):
        cutoff_ms = _now_ms() - (MAX_RETENTION_S * 1000)
        points: list[dict] = []
        if POOL_SERIES_PATH.exists():
            for line in POOL_SERIES_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    t = int(obj.get("t") or 0)
                    if t >= cutoff_ms:
                        points.append(obj)
                except Exception:
                    continue

        points.sort(key=lambda p: p.get("t", 0))
        if len(points) > MAX_SERIES_POINTS:
            points = points[-MAX_SERIES_POINTS:]

        with self._lock:
            self._points = points

        # Rewrite the file if we dropped old points or it's missing.
        self._rewrite(points)

    def _rewrite(self, points: list[dict]):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = POOL_SERIES_PATH.with_suffix(".tmp")
        tmp.write_text("\n".join(json.dumps(p, separators=(",", ":")) for p in points) + ("\n" if points else ""), encoding="utf-8")
        tmp.replace(POOL_SERIES_PATH)

    def append(self, point: dict):
        cutoff_ms = _now_ms() - (MAX_RETENTION_S * 1000)
        with self._lock:
            self._points.append(point)
            self._points = [p for p in self._points if int(p.get("t") or 0) >= cutoff_ms]
            if len(self._points) > MAX_SERIES_POINTS:
                self._points = self._points[-MAX_SERIES_POINTS:]

            STATE_DIR.mkdir(parents=True, exist_ok=True)
            with POOL_SERIES_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(point, separators=(",", ":")) + "\n")

            # Occasionally compact the file (simple heuristic).
            if POOL_SERIES_PATH.stat().st_size > 10 * 1024 * 1024:
                self._rewrite(self._points)

    def query(self, trail: str, max_points: int = 1000):
        trail = (trail or "").strip().lower()
        seconds = {
            "30m": 30 * 60,
            "6h": 6 * 60 * 60,
            "12h": 12 * 60 * 60,
            "1d": 24 * 60 * 60,
            "3d": 3 * 24 * 60 * 60,
            "6d": 6 * 24 * 60 * 60,
            "7d": 7 * 24 * 60 * 60,
        }.get(trail, 30 * 60)

        cutoff_ms = _now_ms() - (seconds * 1000)
        with self._lock:
            pts = [p for p in self._points if int(p.get("t") or 0) >= cutoff_ms]

        if len(pts) <= max_points:
            return pts

        stride = (len(pts) + max_points - 1) // max_points
        return pts[::stride]


POOL_SERIES = PoolSeries()


def _series_sampler(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            status = _pool_status()
            workers = status.get("workers")
            try:
                workers_i = int(workers)
            except Exception:
                workers_i = 0

            def to_float(value):
                if value is None:
                    return None
                try:
                    return float(value)
                except Exception:
                    return None

            hashrate_f = to_float(status.get("hashrate_ths"))

            POOL_SERIES.append(
                {
                    "t": _now_ms(),
                    "workers": workers_i,
                    "hashrate_ths": hashrate_f,
                }
            )
        except Exception:
            pass

        stop_event.wait(SAMPLE_INTERVAL_S)


def _widget_sync():
    try:
        s = _node_status()
        progress = max(0.0, min(1.0, float(s["verificationprogress"])))
        pct = int(progress * 100)
        label = "In progress" if s["initialblockdownload"] else "Synchronized"
        return {
            "type": "text-with-progress",
            "title": "DGB sync",
            "text": f"{pct}%",
            "progressLabel": label,
            "progress": progress,
        }
    except Exception:
        return {
            "type": "text-with-progress",
            "title": "DGB sync",
            "text": "-",
            "progressLabel": "Unavailable",
            "progress": 0,
        }


def _widget_pool():
    p = _pool_status()
    return {
        "type": "three-stats",
        "items": [
            {"title": "Hashrate", "text": str(p.get("hashrate_ths") or "-"), "subtext": "TH/s"},
            {"title": "Workers", "text": str(p.get("workers") or 0)},
            {"title": "Effort", "text": str(p.get("effort_percent") or "-"), "subtext": "%"},
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = f"{APP_ID}/{APP_VERSION}"

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/about":
            return self._send(*_json(_about()))

        if self.path == "/api/settings":
            return self._send(*_json(_current_settings()))

        if self.path == "/api/pool/settings":
            return self._send(*_json(_pool_settings()))

        if self.path == "/api/support/status":
            return self._send(
                *_json(
                    {
                        "ticketEnabled": bool(SUPPORT_TICKET_URL),
                        "checkinEnabled": bool(SUPPORT_CHECKIN_URL),
                    }
                )
            )

        if self.path == "/api/node":
            reindex_requested = NODE_REINDEX_FLAG_PATH.exists()
            reindex_required = _detect_reindex_required()
            try:
                s = _node_status()
                payload = dict(s)
                payload.update(
                    {
                        "cached": False,
                        "lastSeen": int(time.time()),
                        "reindexRequested": reindex_requested,
                        "reindexRequired": False,
                    }
                )
                return self._send(*_json(payload))
            except (HTTPError, URLError, RuntimeError) as e:
                if isinstance(e, RpcError) and e.code == -28:
                    payload = {
                        "cached": False,
                        "lastSeen": int(time.time()),
                        "warmup": True,
                        "warmupMessage": e.message,
                        "reindexRequested": reindex_requested,
                        "reindexRequired": reindex_required,
                    }
                    return self._send(*_json(payload))
                cached = _read_node_cache()
                if cached:
                    payload = dict(cached["status"])
                    payload.update(
                        {
                            "cached": True,
                            "lastSeen": int(cached["t"]),
                            "error": str(e),
                            "warmup": isinstance(e, RpcError) and e.code == -28,
                            "warmupMessage": e.message if isinstance(e, RpcError) and e.code == -28 else None,
                            "reindexRequested": reindex_requested,
                            "reindexRequired": reindex_required,
                        }
                    )
                    return self._send(*_json(payload))
                return self._send(
                    *_json(
                        {
                            "error": str(e),
                            "reindexRequested": reindex_requested,
                            "reindexRequired": reindex_required,
                        },
                        status=503,
                    )
                )

        if self.path == "/api/pool":
            return self._send(*_json(_pool_status()))

        if self.path == "/api/pool/workers":
            # The current UI only uses aggregated worker count from /api/pool.
            return self._send(*_json({"workers": []}))

        if self.path.startswith("/api/timeseries/pool"):
            try:
                query = ""
                if "?" in self.path:
                    _, query = self.path.split("?", 1)
                trail = "30m"
                for part in query.split("&"):
                    if part.startswith("trail="):
                        trail = part.split("=", 1)[1]
                        break
                pts = POOL_SERIES.query(trail=trail, max_points=1000)
                return self._send(*_json({"trail": trail, "points": pts}))
            except Exception as e:
                return self._send(*_json({"error": str(e)}, status=500))

        if self.path == "/api/widget/sync":
            return self._send(*_json(_widget_sync()))

        if self.path == "/api/widget/pool":
            return self._send(*_json(_widget_pool()))

        status, body, ct = _read_static(self.path if self.path != "/" else "/index.html")
        return self._send(status, body, ct)

    def do_POST(self):
        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._send(*_json({"error": "invalid json"}, status=400))

        if self.path == "/api/settings":
            prev = _current_settings()
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

            reindex_required = False
            try:
                prev_prune = int(prev.get("prune") or 0)
            except Exception:
                prev_prune = 0
            if prev_prune > 0 and prune == 0:
                reindex_required = True
                _request_reindex_chainstate()

            return self._send(*_json({"ok": True, "restartRequired": True, "reindexRequired": reindex_required}))

        if self.path == "/api/pool/settings":
            payout_address = str(body.get("payoutAddress") or "")
            mindiff = body.get("mindiff")
            startdiff = body.get("startdiff")
            maxdiff = body.get("maxdiff")
            try:
                settings = _update_pool_settings(
                    payout_address=payout_address,
                    mindiff=mindiff,
                    startdiff=startdiff,
                    maxdiff=maxdiff,
                )
                return self._send(*_json({"ok": True, "settings": settings, "restartRequired": True}))
            except Exception as e:
                return self._send(*_json({"error": str(e)}, status=400))

        if self.path == "/api/support/ticket":
            if not SUPPORT_TICKET_URL:
                return self._send(*_json({"error": "support not configured"}, status=503))

            subject = str(body.get("subject") or "").strip()
            message = str(body.get("message") or "").strip()
            email = str(body.get("email") or "").strip()

            if len(subject) < 3 or len(subject) > 120:
                return self._send(*_json({"error": "subject must be 3-120 chars"}, status=400))
            if len(message) < 10 or len(message) > 8000:
                return self._send(*_json({"error": "message must be 10-8000 chars"}, status=400))
            if email and len(email) > 200:
                return self._send(*_json({"error": "email too long"}, status=400))

            payload = _support_ticket_payload(subject=subject, message=message, email=email or None)
            try:
                bundle, filename = _build_support_bundle_zip(payload)
                status, resp = _post_support_bundle(
                    SUPPORT_TICKET_URL, bundle_bytes=bundle, filename=filename, timeout_s=20
                )
                if int(status) >= 400:
                    return self._send(*_json({"error": "support server error"}, status=502))
                try:
                    data = json.loads(resp.decode("utf-8", errors="replace"))
                    ticket = data.get("ticket") if isinstance(data, dict) else None
                except Exception:
                    ticket = None
            except Exception:
                return self._send(*_json({"error": "support server unreachable"}, status=502))

            return self._send(*_json({"ok": True, "ticket": ticket}))

        return self._send(*_json({"error": "not found"}, status=404))


def main():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    POOL_SERIES.load()

    global INSTALL_ID
    INSTALL_ID = _get_or_create_install_id()

    stop_event = threading.Event()
    t = threading.Thread(target=_series_sampler, args=(stop_event,), daemon=True)
    t.start()

    t2 = threading.Thread(target=_support_checkin_loop, args=(stop_event,), daemon=True)
    t2.start()

    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()


if __name__ == "__main__":
    main()
