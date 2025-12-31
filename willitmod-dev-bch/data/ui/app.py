import base64
import hashlib
import io
import json
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


STATIC_DIR = Path("/data/ui/static")
CKPOOL_STATUS_DIR = Path(os.getenv("CKPOOL_STATUS_DIR", "/data/pool/www/pool"))
CKPOOL_CONF_PATH = Path(os.getenv("CKPOOL_CONF_PATH", "/data/pool/config/ckpool.conf"))
NODE_CONF_PATH = Path("/data/node/bitcoin.conf")
NODE_LOG_PATH = Path("/data/node/debug.log")
NODE_REINDEX_FLAG_PATH = Path("/data/node/.reindex-chainstate")
STATE_DIR = Path("/data/ui/state")
POOL_SERIES_PATH = STATE_DIR / "pool_timeseries.jsonl"
INSTALL_ID_PATH = STATE_DIR / "install_id.txt"
NODE_CACHE_PATH = STATE_DIR / "node_cache.json"
CHECKIN_STATE_PATH = STATE_DIR / "checkin.json"
CKPOOL_FALLBACK_DONATION_ADDRESS = "14BMjogz69qe8hk9thyzbmR5pg34mVKB1e"

APP_CHANNEL = os.getenv("APP_CHANNEL", "").strip()
BCHN_IMAGE = os.getenv("BCHN_IMAGE", "").strip()
CKPOOL_IMAGE = os.getenv("CKPOOL_IMAGE", "").strip()
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

APP_ID = "willitmod-dev-bch"
APP_VERSION = "0.7.2-alpha"

BCH_RPC_HOST = os.getenv("BCH_RPC_HOST", "bchn")
BCH_RPC_PORT = int(os.getenv("BCH_RPC_PORT", "28332"))
BCH_RPC_USER = os.getenv("BCH_RPC_USER", "bch")
BCH_RPC_PASS = os.getenv("BCH_RPC_PASS", "")

SAMPLE_INTERVAL_S = int(os.getenv("SERIES_SAMPLE_INTERVAL_S", "30"))
MAX_RETENTION_S = int(os.getenv("SERIES_MAX_RETENTION_S", str(7 * 24 * 60 * 60)))
MAX_SERIES_POINTS = int(os.getenv("SERIES_MAX_POINTS", "20000"))

INSTALL_ID = None


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
        payload = {"app": "AxeBCH", "version": APP_VERSION}
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
    name = f"axebch-support-{int(time.time())}.zip"
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
            "bchn": BCHN_IMAGE or None,
            "ckpool": CKPOOL_IMAGE or None,
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


def _read_ckpool_conf():
    if not CKPOOL_CONF_PATH.exists():
        return {}
    return _extract_json_obj(CKPOOL_CONF_PATH.read_text(encoding="utf-8", errors="replace"))


def _write_ckpool_conf(conf: dict):
    CKPOOL_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    CKPOOL_CONF_PATH.write_text(json.dumps(conf, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pool_settings():
    conf_addr = ""
    validation_warning = None
    validated = None
    try:
        conf = _read_ckpool_conf()
        conf_addr = str(conf.get("btcaddress") or "").strip()
        validation_warning = conf.get("validationWarning")
        validated = conf.get("validated")
    except Exception:
        conf_addr = ""

    payout_address = conf_addr
    configured = bool(payout_address) and payout_address not in [
        CKPOOL_FALLBACK_DONATION_ADDRESS,
        "CHANGEME_BCH_PAYOUT_ADDRESS",
    ]

    if not isinstance(validation_warning, str):
        validation_warning = None
    if validated is not None:
        validated = bool(validated)

    return {
        "payoutAddress": payout_address or "",
        "configured": configured,
        "validated": validated,
        "validationWarning": validation_warning,
        "warning": (
            "Set a payout address before mining. If unset, ckpool may default to a donation address."
            if not configured
            else None
        ),
    }


_CASHADDR_RE = re.compile(r"^(?:(?:bitcoincash|bchtest|bchreg):)?(?P<body>[qp][0-9a-z]{41,60})$", re.IGNORECASE)
_LEGACY_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")


_CASHADDR_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CASHADDR_HELP_URL = "https://bch.info/en/tools/cashaddr"
_CASHADDR_ALPHABET_REV = {c: i for i, c in enumerate(_CASHADDR_ALPHABET)}
_CASHADDR_POLYMOD_GEN = (
    0x98F2BC8E61,
    0x79B76D99E2,
    0xF33E5FB3C4,
    0xAE2EABE2A8,
    0x1E4F43E470,
)
_CASHADDR_SIZE_MAP = {0: 20, 1: 24, 2: 28, 3: 32, 4: 40, 5: 48, 6: 56, 7: 64}


def _cashaddr_prefix_expand(prefix: str) -> list[int]:
    return [ord(ch) & 0x1F for ch in prefix] + [0]


def _cashaddr_polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 35
        chk = ((chk & 0x07FFFFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _CASHADDR_POLYMOD_GEN[i]
    return chk


def _cashaddr_verify_checksum(prefix: str, payload: list[int]) -> bool:
    # CashAddr checksum constant is 1 (i.e. polymod == 1)
    return _cashaddr_polymod(_cashaddr_prefix_expand(prefix) + payload) == 1


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid value")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    else:
        if bits >= frombits:
            raise ValueError("illegal zero padding")
        if (acc << (tobits - bits)) & maxv:
            raise ValueError("non-zero padding")
    return ret


def _base58check_encode(prefix_byte: int, payload: bytes) -> str:
    raw = bytes([prefix_byte]) + payload
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    b = raw + chk

    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out

    leading_zeros = 0
    for c in b:
        if c == 0:
            leading_zeros += 1
        else:
            break
    return ("1" * leading_zeros) + out


def _cashaddr_to_legacy(addr: str) -> tuple[str, bool]:
    a = (addr or "").strip()
    if _LEGACY_RE.match(a):
        return a, False

    m = _CASHADDR_RE.match(a)
    if not m:
        raise ValueError("payoutAddress must be a CashAddr (q/p...) or legacy (1/3...) BCH address")

    prefix = "bitcoincash"
    if ":" in a:
        prefix = a.split(":", 1)[0].lower()
    body = m.group("body").lower()
    data = [_CASHADDR_ALPHABET_REV[ch] for ch in body]
    if not _cashaddr_verify_checksum(prefix, data):
        raise ValueError("payoutAddress has an invalid CashAddr checksum")

    payload_no_checksum = data[:-8]
    decoded = _convertbits(payload_no_checksum, 5, 8, pad=False)
    version = decoded[0]
    h = bytes(decoded[1:])

    addr_type = version >> 3
    size_code = version & 7
    expected_len = _CASHADDR_SIZE_MAP.get(size_code)
    if expected_len is None or len(h) != expected_len:
        raise ValueError("payoutAddress has an unexpected hash size")

    if addr_type == 0:
        return _base58check_encode(0x00, h), True  # P2PKH
    if addr_type == 1:
        return _base58check_encode(0x05, h), True  # P2SH

    raise ValueError("payoutAddress must be a P2PKH or P2SH address")


def _looks_like_bch_address(addr: str) -> bool:
    a = (addr or "").strip()
    return bool(_CASHADDR_RE.match(a) or _LEGACY_RE.match(a))


def _update_pool_settings(*, payout_address: str):
    addr_raw = payout_address.strip()
    if not addr_raw:
        raise ValueError("payoutAddress is required")

    addr_legacy, converted_from_cashaddr = _cashaddr_to_legacy(addr_raw)

    validated = None
    validation_warning = None
    conversion_notice = None
    if converted_from_cashaddr:
        conversion_notice = (
            f"CashAddr detected and converted to legacy format for ckpool compatibility: {addr_legacy}. "
            f"Converter: {_CASHADDR_HELP_URL}"
        )
    try:
        res = _rpc_call("validateaddress", [addr_legacy]) or {}
        validated = bool(res.get("isvalid"))
        if not validated:
            raise ValueError("payoutAddress is not a valid BCH address")
    except Exception:
        validated = False
        validation_warning = (
            "Node RPC unavailable; saved without RPC validation. Double-check your address, then restart the app."
        )
        if conversion_notice:
            validation_warning = f"{validation_warning} {conversion_notice}"

    conf = _read_ckpool_conf()
    # ckpool expects a legacy/Base58 address here.
    conf["btcaddress"] = addr_legacy
    conf["validated"] = bool(validated) if validated is not None else False
    if conversion_notice and not validation_warning:
        validation_warning = conversion_notice
    if validation_warning:
        conf["validationWarning"] = validation_warning
    else:
        conf.pop("validationWarning", None)
    _write_ckpool_conf(conf)

    return _pool_settings()


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

def _read_pool_workers_raw():
    candidates = [
        CKPOOL_STATUS_DIR / "pool.workers",
        Path("/data/pool/www/pool.workers"),
        Path("/data/pool/www/pool/pool.workers"),
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
        pool = _parse_pool_status(_read_pool_status_raw())
        diagnostics["pool"] = {
            "workers": pool.get("workers"),
            "hashrate_ths": pool.get("hashrate_ths"),
            "best_share": pool.get("best_share"),
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
            status = _parse_pool_status(_read_pool_status_raw())
            workers = status.get("workers")
            try:
                workers_i = int(workers)
            except Exception:
                workers_i = 0

            hashrate = status.get("hashrate_ths")
            try:
                hashrate_f = float(hashrate)
            except Exception:
                hashrate_f = None

            POOL_SERIES.append({"t": _now_ms(), "workers": workers_i, "hashrate_ths": hashrate_f})
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
            "title": "BCH sync",
            "text": f"{pct}%",
            "progressLabel": label,
            "progress": progress,
        }
    except Exception:
        return {
            "type": "text-with-progress",
            "title": "BCH sync",
            "text": "-",
            "progressLabel": "Unavailable",
            "progress": 0,
        }


def _widget_pool():
    p = _parse_pool_status(_read_pool_status_raw())
    return {
        "type": "three-stats",
        "items": [
            {"title": "Hashrate", "text": str(p.get("hashrate_ths") or "-"), "subtext": "TH/s"},
            {"title": "Workers", "text": str(p.get("workers") or 0)},
            {"title": "Best Share", "text": str(p.get("best_share") or "-")},
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "willitmod-dev-bch/0.7.2"

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
                cached = _read_node_cache()
                if cached:
                    payload = dict(cached["status"])
                    payload.update(
                        {
                            "cached": True,
                            "lastSeen": int(cached["t"]),
                            "error": str(e),
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
            return self._send(*_json(_parse_pool_status(_read_pool_status_raw())))

        if self.path == "/api/pool/workers":
            raw = _read_pool_workers_raw()
            workers = _parse_pool_workers(raw)
            return self._send(*_json({"workers": workers}))

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
            try:
                settings = _update_pool_settings(payout_address=payout_address)
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
    CKPOOL_STATUS_DIR.mkdir(parents=True, exist_ok=True)
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
