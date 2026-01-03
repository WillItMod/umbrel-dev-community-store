import base64
import io
import json
import math
import os
import platform
import re
import errno
import tempfile
import threading
import time
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

try:
    import pg8000  # type: ignore
except Exception:
    pg8000 = None


_DEFAULT_STATIC_DIR = "/app/static" if Path("/app/static").exists() else "/data/ui/static"
STATIC_DIR = Path(os.getenv("STATIC_DIR", _DEFAULT_STATIC_DIR))
MININGCORE_API_URL = os.getenv("MININGCORE_API_URL", "http://miningcore:4000").strip().rstrip("/")
MININGCORE_POOL_ID = os.getenv("MININGCORE_POOL_ID", "dgb-sha256-1").strip()
MININGCORE_POOL_IDS = os.getenv("MININGCORE_POOL_IDS", "").strip()
STRATUM_PORTS = os.getenv("STRATUM_PORTS", "").strip()
MININGCORE_CONF_PATH = Path(os.getenv("MININGCORE_CONF_PATH", "/data/pool/config/miningcore.json"))
NODE_CONF_PATH = Path("/data/node/digibyte.conf")
NODE_LOG_PATH = Path("/data/node/debug.log")
NODE_REINDEX_FLAG_PATH = Path("/data/node/.reindex-chainstate")
STATE_DIR = Path("/data/ui/state")
POOL_SETTINGS_STATE_PATH = STATE_DIR / "pool_settings.json"
INSTALL_ID_PATH = STATE_DIR / "install_id.txt"
NODE_CACHE_PATH = STATE_DIR / "node_cache.json"
NODE_EXTRAS_CACHE_PATH = STATE_DIR / "node_extras_cache.json"
CHECKIN_STATE_PATH = STATE_DIR / "checkin.json"
# Miningcore requires a syntactically valid payout address in its config at startup.
# This is a deterministic "burn" address (hash160=0x00..00, base58check version=0x1e)
# so no real wallet address is shipped in the repo, and the pool remains "not configured"
# until the user sets their own payout address.
# Placeholder address used to keep Miningcore running before the user configures a payout address.
# Stratum stays bound to localhost until a real address is set.
POOL_PLACEHOLDER_PAYOUT_ADDRESS = "D596YFweJQuHY1BbjazZYmAbt8jJPbKehC"

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
APP_VERSION = "0.8.37"

DGB_RPC_HOST = os.getenv("DGB_RPC_HOST", "dgbd")
DGB_RPC_PORT = int(os.getenv("DGB_RPC_PORT", "14022"))
DGB_RPC_USER = os.getenv("DGB_RPC_USER", "dgb")
DGB_RPC_PASS = os.getenv("DGB_RPC_PASS", "")

SAMPLE_INTERVAL_S = int(os.getenv("SERIES_SAMPLE_INTERVAL_S", "30"))
MAX_RETENTION_S = int(os.getenv("SERIES_MAX_RETENTION_S", str(7 * 24 * 60 * 60)))
MAX_SERIES_POINTS = int(os.getenv("SERIES_MAX_POINTS", "20000"))
WORKER_STALE_SECONDS = int(os.getenv("WORKER_STALE_SECONDS", "180"))

INSTALL_ID = None

_PG_CONF_CACHE = None
_PG_CONF_CACHE_T = 0.0
_PG_CONF_LOCK = threading.Lock()

_POOL_WORKERS_CACHE: dict[str, dict] = {}
_POOL_WORKERS_LOCK = threading.Lock()
_POOL_WORKERS_TTL_S = 5.0


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

    if rel == "index.html" and content_type.startswith("text/html"):
        try:
            html = path.read_text(encoding="utf-8", errors="replace")
            html = html.replace("__APP_VERSION__", APP_VERSION)
            html = html.replace("__APP_CHANNEL__", APP_CHANNEL or "")
            return 200, html.encode("utf-8"), content_type
        except Exception:
            pass

    return 200, path.read_bytes(), content_type


def _pg_conf():
    """
    Return Miningcore Postgres config from miningcore.json.
    Cached because UI polls frequently.
    """
    global _PG_CONF_CACHE, _PG_CONF_CACHE_T
    now = time.time()
    with _PG_CONF_LOCK:
        if _PG_CONF_CACHE is not None and (now - _PG_CONF_CACHE_T) < 30:
            return _PG_CONF_CACHE
        try:
            raw = MININGCORE_CONF_PATH.read_text(encoding="utf-8", errors="replace")
            cfg = json.loads(raw) if raw.strip() else {}
            pg = (((cfg or {}).get("persistence") or {}).get("postgres") or {})
            if not isinstance(pg, dict):
                pg = {}
            out = {
                "host": str(pg.get("host") or "postgres"),
                "port": int(pg.get("port") or 5432),
                "database": str(pg.get("database") or "miningcore"),
                "user": str(pg.get("user") or "miningcore"),
                "password": str(pg.get("password") or ""),
            }
            _PG_CONF_CACHE = out
            _PG_CONF_CACHE_T = now
            return out
        except Exception:
            _PG_CONF_CACHE = None
            _PG_CONF_CACHE_T = now
            return None


def _pool_workers_from_db(pool_id: str):
    """
    Miningcore's /miners endpoint aggregates by payout address and may not expose per-worker rows.
    The minerstats table retains per-(miner, worker) rows, so use it for accurate worker lists.
    """
    if pg8000 is None:
        return None
    pg = _pg_conf()
    if not pg or not pg.get("password"):
        return None

    now = time.time()
    with _POOL_WORKERS_LOCK:
        cached = _POOL_WORKERS_CACHE.get(pool_id)
        if cached and (now - float(cached.get("t") or 0)) < _POOL_WORKERS_TTL_S:
            return cached.get("workers") or []

    try:
        conn = pg8000.connect(
            host=pg["host"],
            port=pg["port"],
            user=pg["user"],
            password=pg["password"],
            database=pg["database"],
            timeout=3,
        )
    except Exception:
        return None

    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT DISTINCT ON (miner, worker)
              miner, worker, hashrate, sharespersecond, created
            FROM minerstats
            WHERE poolid = %s
            ORDER BY miner, worker, created DESC
            """,
            (pool_id,),
        )
        rows = cur.fetchall() or []

        # Pull "last share" timestamps and an estimated hashrate from shares
        # (minerstats.created is a snapshot timestamp, not the last share time).
        #
        # H/s ≈ sum(difficulty) * 2^32 / elapsed_seconds
        #
        # Notes:
        # - We cap elapsed_seconds at the window size (10m) to avoid inflating
        #   hashrate when there are gaps.
        # - We floor elapsed_seconds at 60s to avoid huge spikes on the first
        #   1-2 accepted shares.
        cur.execute(
            """
            SELECT
              miner,
              worker,
              MAX(created) AS last_share,
              MIN(CASE WHEN created >= NOW() - INTERVAL '10 minutes' THEN created END) AS first_share_10m,
              MAX(CASE WHEN created >= NOW() - INTERVAL '10 minutes' THEN created END) AS last_share_10m,
              COALESCE(SUM(CASE WHEN created >= NOW() - INTERVAL '10 minutes' THEN difficulty ELSE 0 END), 0) AS sumdiff_10m
            FROM shares
            WHERE poolid = %s AND created >= NOW() - INTERVAL '2 days'
            GROUP BY miner, worker
            """,
            (pool_id,),
        )
        share_rows = cur.fetchall() or []
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass

    last_share_by_key: dict[tuple[str, str | None], datetime] = {}
    hashrate_hs_10m_by_key: dict[tuple[str, str | None], float] = {}
    for r in share_rows:
        try:
            miner, worker, last_share, first_share_10m, last_share_10m, sumdiff_10m = r
        except Exception:
            continue
        miner_s = str(miner or "")
        worker_s = str(worker or "").strip() or None
        if isinstance(last_share, datetime):
            last_share_by_key[(miner_s, worker_s)] = last_share
        try:
            sumdiff_f = float(sumdiff_10m) if sumdiff_10m is not None else 0.0
            if math.isfinite(sumdiff_f) and sumdiff_f > 0:
                span_s = None
                try:
                    if isinstance(first_share_10m, datetime) and isinstance(last_share_10m, datetime):
                        span_s = (last_share_10m - first_share_10m).total_seconds()
                    elif isinstance(first_share_10m, datetime):
                        span_s = (datetime.now(timezone.utc) - first_share_10m).total_seconds()
                except Exception:
                    span_s = None

                window_s = 10 * 60
                if span_s is None or not math.isfinite(float(span_s)) or span_s <= 0:
                    span_s = window_s
                span_s = max(60.0, min(float(span_s), float(window_s)))
                hashrate_hs_10m_by_key[(miner_s, worker_s)] = (sumdiff_f * (2**32)) / span_s
        except Exception:
            pass

    out = []
    for r in rows:
        try:
            miner, worker, hashrate_hs, shares_per_s, created = r
        except Exception:
            continue

        miner_s = str(miner or "")
        worker_s = str(worker or "").strip() or None

        try:
            hashrate_hs_f = float(hashrate_hs) if hashrate_hs is not None else None
        except Exception:
            hashrate_hs_f = None
        if hashrate_hs_f is not None and not math.isfinite(hashrate_hs_f):
            hashrate_hs_f = None

        last_share_dt = last_share_by_key.get((miner_s, worker_s))
        if isinstance(last_share_dt, datetime):
            try:
                age_s = (datetime.now(timezone.utc) - last_share_dt.astimezone(timezone.utc)).total_seconds()
                if WORKER_STALE_SECONDS > 0 and age_s > WORKER_STALE_SECONDS:
                    continue
            except Exception:
                pass

        hashrate_hs_live = hashrate_hs_10m_by_key.get((miner_s, worker_s))
        hashrate_ths_live = (hashrate_hs_live / 1e12) if hashrate_hs_live is not None else None

        # Prefer live estimate from accepted shares, fallback to Miningcore minerstats estimate.
        hashrate_ths = hashrate_ths_live
        if hashrate_ths is None and hashrate_hs_f is not None:
            hashrate_ths = hashrate_hs_f / 1e12

        last_share = None
        try:
            if isinstance(last_share_dt, datetime):
                last_share = last_share_dt.astimezone(timezone.utc).isoformat()
            elif last_share_dt is not None:
                last_share = str(last_share_dt)
        except Exception:
            last_share = None

        out.append(
            {
                "miner": miner_s,
                "worker": worker_s,
                "hashrate_hs": hashrate_hs_f,
                "hashrate_ths": hashrate_ths,
                "hashrate_hs_live_10m": hashrate_hs_live,
                "hashrate_ths_live_10m": hashrate_ths_live,
                "lastShare": last_share,
                "sharesPerSecond": shares_per_s,
            }
        )

    # Miningcore can emit both per-worker rows and an aggregate (worker=null) row for the same miner.
    # If we have any named workers, hide the aggregate row so the UI doesn't under/over-count workers.
    has_named = any(isinstance(m.get("worker"), str) and m.get("worker") for m in out)
    if has_named:
        out = [m for m in out if m.get("worker")]

    out.sort(key=lambda m: float(m.get("hashrate_hs") or 0), reverse=True)
    with _POOL_WORKERS_LOCK:
        _POOL_WORKERS_CACHE[pool_id] = {"t": now, "workers": out}
    return out


def _parse_pool_ids(raw: str) -> dict[str, str]:
    """
    Parse MININGCORE_POOL_IDS like: "sha256:dgb-sha256-1".
    """
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if not k or not v:
            continue
        out[k] = v
    return out


def _pool_ids() -> dict[str, str]:
    ids = _parse_pool_ids(MININGCORE_POOL_IDS)
    if ids:
        return ids
    return {"sha256": MININGCORE_POOL_ID}


def _parse_ports(raw: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if not k or not v:
            continue
        try:
            out[k] = int(v)
        except Exception:
            continue
    return out


def _stratum_ports() -> dict[str, int]:
    ports = _parse_ports(STRATUM_PORTS)
    if ports:
        return ports
    return {"sha256": 5678, "scrypt": 5679}


def _algo_from_query(path: str) -> str | None:
    try:
        if "?" not in path:
            return None
        _, query = path.split("?", 1)
        for part in query.split("&"):
            if part.startswith("algo="):
                return part.split("=", 1)[1].strip().lower() or None
    except Exception:
        return None
    return None


def _pool_id_for_algo(algo: str | None) -> str:
    ids = _pool_ids()
    if algo and algo in ids:
        return ids[algo]
    if "sha256" in ids:
        return ids["sha256"]
    return next(iter(ids.values()))


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
                raw = e.read() or b""
                try:
                    data = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    snippet = raw.decode("utf-8", errors="replace").strip()
                    snippet = snippet[:200] if snippet else ""
                    msg = f"HTTP {getattr(e, 'code', '')} {getattr(e, 'reason', '')}".strip()
                    if snippet:
                        msg = f"{msg}: {snippet}"
                    raise RpcError(getattr(e, "code", None), msg, raw=snippet or None)
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


NODE_STATUS_LOCK = threading.Lock()


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

    blocks = int(info.get("blocks") or 0)
    headers = int(info.get("headers") or blocks)
    progress = float(info.get("verificationprogress") or 0.0)
    ibd = bool(info.get("initialblockdownload", False))

    extras: dict = {}
    cached_extras = _read_node_extras_cache()
    now = int(time.time())
    extras_max_age_s = 60
    if cached_extras and (now - int(cached_extras["t"])) <= extras_max_age_s:
        extras = dict(cached_extras["extras"])
    else:
        try:
            net = _rpc_call("getnetworkinfo")
            mempool = _rpc_call("getmempoolinfo")
            extras = {
                "connections": int(net.get("connections") or 0),
                "subversion": str(net.get("subversion") or ""),
                "mempool_bytes": int(mempool.get("bytes") or 0),
            }
            _write_node_extras_cache(extras)
        except Exception:
            if cached_extras:
                extras = dict(cached_extras["extras"])

    status = {
        "chain": info.get("chain"),
        "blocks": blocks,
        "headers": headers,
        "verificationprogress": progress,
        "initialblockdownload": ibd,
        "difficulty": info.get("difficulty"),
        "difficulties": info.get("difficulties") if isinstance(info.get("difficulties"), dict) else None,
        "connections": int(extras.get("connections") or 0),
        "subversion": str(extras.get("subversion") or ""),
        "mempool_bytes": int(extras.get("mempool_bytes") or 0),
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


def _read_node_extras_cache():
    try:
        if not NODE_EXTRAS_CACHE_PATH.exists():
            return None
        obj = json.loads(NODE_EXTRAS_CACHE_PATH.read_text(encoding="utf-8", errors="replace"))
        t = int(obj.get("t") or 0)
        extras = obj.get("extras") or {}
        if not isinstance(extras, dict):
            return None
        return {"t": t, "extras": extras}
    except Exception:
        return None


def _write_node_extras_cache(extras: dict):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        NODE_EXTRAS_CACHE_PATH.write_text(
            json.dumps({"t": int(time.time()), "extras": extras}) + "\n", encoding="utf-8"
        )
    except Exception:
        pass


def _safe_slug(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value or "").strip())
    return s or "default"


def _pool_cache_path(pool_id: str) -> Path:
    return STATE_DIR / f"pool_cache_{_safe_slug(pool_id)}.json"


def _pool_series_path(pool_id: str) -> Path:
    return STATE_DIR / f"pool_timeseries_{_safe_slug(pool_id)}.jsonl"


def _write_pool_cache(pool_id: str, status: dict):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        _pool_cache_path(pool_id).write_text(json.dumps({"t": int(time.time()), "status": status}) + "\n", encoding="utf-8")
    except Exception:
        pass


def _read_pool_cache(pool_id: str):
    try:
        path = _pool_cache_path(pool_id)
        if not path.exists():
            return None
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
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
        "poolIds": _pool_ids(),
        "stratumPorts": _stratum_ports(),
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


def _atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8"):
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            dir=str(path.parent),
            prefix=f".{path.name}.tmp-",
            delete=False,
        ) as f:
            tmp_path = Path(f.name)
            f.write(text)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

        try:
            if path.exists():
                os.chmod(tmp_path, path.stat().st_mode)
        except Exception:
            pass

        os.replace(tmp_path, path)
    except Exception:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
        raise


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
    try:
        _atomic_write_text(MININGCORE_CONF_PATH, json.dumps(conf, indent=2, sort_keys=True) + "\n")
    except OSError as e:
        if getattr(e, "errno", None) not in (errno.EACCES, errno.EROFS):
            raise
        raise ValueError(
            f"Cannot write Miningcore config at '{MININGCORE_CONF_PATH}' (permission denied). "
            "This usually means the file is owned by root due to an older install; restart the app to run migrations, "
            "or fix permissions on /data/pool/config/miningcore.json."
        )


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
        _atomic_write_text(POOL_SETTINGS_STATE_PATH, json.dumps(obj, indent=2, sort_keys=True) + "\n")
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
    primary_pool_id = _pool_id_for_algo("sha256")

    try:
        conf = _read_miningcore_conf()
        pools = conf.get("pools") or []
        pool_conf = None
        if isinstance(pools, list):
            for item in pools:
                if isinstance(item, dict) and str(item.get("id") or "") == primary_pool_id:
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
    desired_addr = str(state.get("payoutAddress") or "").strip()
    desired_mindiff = _maybe_int(state.get("mindiff"))
    desired_startdiff = _maybe_int(state.get("startdiff"))
    desired_maxdiff = _maybe_int(state.get("maxdiff"))
    validated = state.get("validated")
    validation_warning = state.get("validationWarning")

    actual_addr = conf_addr
    actual_configured = bool(actual_addr) and actual_addr != POOL_PLACEHOLDER_PAYOUT_ADDRESS

    # If the user saved a new payout address but hasn't restarted yet, surface the
    # saved value in the UI while still indicating the pool isn't configured
    # until Miningcore is updated (via init on restart).
    payout_address = desired_addr or actual_addr
    pending_apply = bool(desired_addr) and desired_addr != actual_addr
    configured = bool(payout_address) and payout_address != POOL_PLACEHOLDER_PAYOUT_ADDRESS and actual_configured and not pending_apply

    if pending_apply:
        validation_warning = (
            "Saved. Restart the app to apply the new payout address and varDiff settings."
            + (f" {validation_warning}" if isinstance(validation_warning, str) and validation_warning.strip() else "")
        )

    if not configured and not pending_apply:
        payout_address = ""
        validated = None
        validation_warning = None

    if validated is not None:
        validated = bool(validated)
    if not isinstance(validation_warning, str):
        validation_warning = None

    return {
        "payoutAddress": payout_address or "",
        "configured": configured,
        "validated": validated,
        "validationWarning": validation_warning,
        "mindiff": _to_int(desired_mindiff if desired_mindiff is not None else mindiff, 1024),
        "startdiff": _to_int(desired_startdiff if desired_startdiff is not None else startdiff, 1024),
        "maxdiff": _to_int(desired_maxdiff if desired_maxdiff is not None else maxdiff, 0),
        "warning": (
            "Set a payout address before mining, then restart the app. Miningcore uses this address when generating blocks."
            if not configured and not pending_apply
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
        raise ValueError("Node is still starting/syncing; can't verify payout address yet. Try again in a few minutes.")
    else:
        validated = bool(res.get("isvalid")) if isinstance(res, dict) else False
        if not validated:
            raise ValueError("payoutAddress is not a valid DigiByte address")

    # Miningcore currently cannot use DigiByte bech32 (dgb1...) payout addresses.
    if addr.lower().startswith("dgb1"):
        raise ValueError("payoutAddress must be a legacy/base58 DigiByte address (not dgb1)")

    md = _maybe_int(mindiff)
    sd = _maybe_int(startdiff)
    xd = _maybe_int(maxdiff)

    use_md = md if md is not None else 1024
    use_sd = sd if sd is not None else max(1024, use_md)
    use_xd = xd if xd is not None else 0

    if use_md < 1:
        raise ValueError("mindiff must be >= 1")
    if use_sd < use_md:
        raise ValueError("startdiff must be >= mindiff")
    if use_xd != 0 and use_xd < use_sd:
        raise ValueError("maxdiff must be 0 (no limit) or >= startdiff")

    # Do not write miningcore.json from the UI container; persist desired settings in
    # a UI-owned state file and let the init container (root) apply them on restart.
    _write_pool_settings_state(
        {
            "payoutAddress": addr,
            "mindiff": int(use_md),
            "startdiff": int(use_sd),
            "maxdiff": int(use_xd),
            "validated": bool(validated) if validated is not None else None,
            "validationWarning": validation_warning,
            "updatedAt": int(time.time()),
        }
    )

    return _pool_settings()


def _miningcore_get_any(path: str, *, timeout_s: int = 8):
    base = MININGCORE_API_URL
    if not base:
        raise RuntimeError("MININGCORE_API_URL not set")
    if not path.startswith("/"):
        path = "/" + path
    url = base + path
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _miningcore_get_json(path: str, *, timeout_s: int = 8) -> dict:
    data = _miningcore_get_any(path, timeout_s=timeout_s)
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected JSON object from Miningcore at {path}")
    return data


def _dget(obj: dict, *keys, default=None):
    if not isinstance(obj, dict):
        return default
    for key in keys:
        if key in obj:
            return obj.get(key)
    return default


def _avg_hashrate_ths(points: list[dict], *, window_s: int) -> float | None:
    if not points:
        return None
    try:
        t_max = max(int(p.get("t") or 0) for p in points)
    except Exception:
        return None
    cutoff = t_max - (window_s * 1000)
    vals = []
    for p in points:
        try:
            t = int(p.get("t") or 0)
        except Exception:
            continue
        if t < cutoff:
            continue
        v = p.get("hashrate_ths")
        try:
            fv = float(v)
        except Exception:
            continue
        if math.isfinite(fv):
            vals.append(fv)
    if not vals:
        return None
    return sum(vals) / len(vals)


def _pool_status(pool_id: str, *, algo: str | None = None):
    try:
        data = _miningcore_get_json(f"/api/pools/{pool_id}")
        pool = _dget(data, "pool", "Pool", default={}) or {}
        stats = _dget(pool, "poolStats", "PoolStats", default={}) or {}
        netstats = _dget(pool, "networkStats", "NetworkStats", default={}) or {}

        connected = _dget(stats, "connectedMiners", "ConnectedMiners", default=0) or 0
        hashrate_hs = _dget(stats, "poolHashrate", "PoolHashrate", default=0) or 0
        total_blocks = _dget(pool, "totalBlocks", "TotalBlocks", default=None)
        network_difficulty = _dget(netstats, "networkDifficulty", "NetworkDifficulty", default=None)
        network_height = _dget(netstats, "blockHeight", "BlockHeight", default=None)

        workers_rows = _pool_workers_from_db(pool_id) or []
        if workers_rows:
            workers_i = len(workers_rows)
            try:
                total_hs = sum(float(w.get("hashrate_hs") or 0) for w in workers_rows)
            except Exception:
                total_hs = 0.0
            hashrate_ths = (total_hs / 1e12) if total_hs > 0 else None
        else:
            try:
                workers_i = int(connected)
            except Exception:
                workers_i = 0
            try:
                hashrate_ths = float(hashrate_hs) / 1e12
            except Exception:
                hashrate_ths = None

        try:
            best = _pool_best_difficulties(pool_id)
        except Exception:
            best = {}

        try:
            share_health = _pool_share_health(pool_id)
        except Exception:
            share_health = {}

        hashrate_ths_best_effort = hashrate_ths
        hashrate_ths_live = None
        try:
            hs10m = share_health.get("hashrate_hs_10m")
            hs10m_f = float(hs10m) if hs10m is not None else None
            if hs10m_f is not None and math.isfinite(hs10m_f) and hs10m_f > 0:
                hashrate_ths_live = hs10m_f / 1e12
        except Exception:
            hashrate_ths_live = None

        if hashrate_ths_live is not None:
            hashrate_ths = hashrate_ths_live

        eta_seconds = None
        try:
            if hashrate_ths and network_difficulty:
                hashrate_hs_f = float(hashrate_ths) * 1e12
                netdiff_f = float(network_difficulty)
                if hashrate_hs_f > 0 and netdiff_f > 0:
                    eta_seconds = (netdiff_f * (2**32)) / hashrate_hs_f
        except Exception:
            eta_seconds = None

        status = {
            "backend": "miningcore",
            "poolId": pool_id,
            "algo": algo,
            "workers": workers_i,
            "hashrate_ths": hashrate_ths,
            "hashrate_ths_best_effort": hashrate_ths_best_effort,
            "hashrate_ths_live_10m": hashrate_ths_live,
            "total_blocks": total_blocks,
            "network_difficulty": network_difficulty,
            "network_height": network_height,
            "best_difficulty_all": best.get("best_difficulty_all"),
            "best_difficulty_since_block": best.get("best_difficulty_since_block"),
            "best_difficulty_since_block_at": best.get("best_difficulty_since_block_at"),
            "best_share_all": best.get("best_share_all") or best.get("best_difficulty_all"),
            "best_share_since_block": best.get("best_share_since_block") or best.get("best_difficulty_since_block"),
            "best_share_since_block_at": best.get("best_share_since_block_at") or best.get("best_difficulty_since_block_at"),
            "shares_10m": share_health.get("shares_10m"),
            "shares_1h": share_health.get("shares_1h"),
            "last_share_at": share_health.get("last_share_at"),
            "eta_seconds": eta_seconds,
            "hashrates_ths": {},
            "cached": False,
            "lastSeen": int(time.time()),
        }
        _write_pool_cache(pool_id, status)

        try:
            series = _pool_series(pool_id).query(trail="7d", max_points=MAX_SERIES_POINTS)
            status["hashrates_ths"] = {
                "1m": _avg_hashrate_ths(series, window_s=60),
                "5m": _avg_hashrate_ths(series, window_s=5 * 60),
                "15m": _avg_hashrate_ths(series, window_s=15 * 60),
                "1h": _avg_hashrate_ths(series, window_s=60 * 60),
                "6h": _avg_hashrate_ths(series, window_s=6 * 60 * 60),
                "1d": _avg_hashrate_ths(series, window_s=24 * 60 * 60),
                "7d": _avg_hashrate_ths(series, window_s=7 * 24 * 60 * 60),
            }
        except Exception:
            pass

        return status
    except Exception as e:
        cached = _read_pool_cache(pool_id)
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
            status.setdefault("poolId", pool_id)
            status.setdefault("algo", algo)
            status.setdefault("workers", 0)
            status.setdefault("hashrate_ths", None)
            status.setdefault("total_blocks", None)
            status.setdefault("network_difficulty", None)
            status.setdefault("network_height", None)
            status.setdefault("best_difficulty_all", None)
            status.setdefault("best_difficulty_since_block", None)
            status.setdefault("best_difficulty_since_block_at", None)
            status.setdefault("best_share_all", status.get("best_difficulty_all"))
            status.setdefault("best_share_since_block", status.get("best_difficulty_since_block"))
            status.setdefault("best_share_since_block_at", status.get("best_difficulty_since_block_at"))
            status.setdefault("shares_10m", None)
            status.setdefault("shares_1h", None)
            status.setdefault("last_share_at", None)
            status.setdefault("eta_seconds", None)
            status.setdefault("hashrate_ths_best_effort", None)
            status.setdefault("hashrate_ths_live_10m", None)
            status.setdefault("hashrates_ths", {})
            return status

        return {
            "backend": "miningcore",
            "poolId": pool_id,
            "algo": algo,
            "workers": 0,
            "hashrate_ths": None,
            "total_blocks": None,
            "network_difficulty": None,
            "network_height": None,
            "best_difficulty_all": None,
            "best_difficulty_since_block": None,
            "best_difficulty_since_block_at": None,
            "best_share_all": None,
            "best_share_since_block": None,
            "best_share_since_block_at": None,
            "shares_10m": None,
            "shares_1h": None,
            "last_share_at": None,
            "eta_seconds": None,
            "hashrate_ths_best_effort": None,
            "hashrate_ths_live_10m": None,
            "hashrates_ths": {},
            "cached": False,
            "lastSeen": int(time.time()),
            "error": str(e),
        }


def _pool_miners(pool_id: str):
    db_rows = _pool_workers_from_db(pool_id)
    if isinstance(db_rows, list) and db_rows:
        return db_rows

    miners = _miningcore_get_any(f"/api/pools/{pool_id}/miners", timeout_s=6)
    if not isinstance(miners, list):
        return []

    out = []
    for item in miners:
        if not isinstance(item, dict):
            continue

        miner = str(item.get("miner") or item.get("Miner") or "")
        worker = item.get("worker") or item.get("Worker") or None
        if isinstance(worker, str) and worker.strip() == "":
            worker = None

        hashrate_hs = item.get("hashrate") if "hashrate" in item else item.get("Hashrate")
        if hashrate_hs is None:
            hashrate_hs = item.get("hashrate_hs") if "hashrate_hs" in item else item.get("hashrateHs")
        try:
            hashrate_hs_f = float(hashrate_hs)
        except Exception:
            hashrate_hs_f = None
        if hashrate_hs_f is not None and not math.isfinite(hashrate_hs_f):
            hashrate_hs_f = None

        hashrate_ths = None
        if hashrate_hs_f is not None:
            hashrate_ths = hashrate_hs_f / 1e12

        out.append(
            {
                "miner": miner,
                "worker": worker,
                "hashrate_hs": hashrate_hs_f,
                "hashrate_ths": hashrate_ths,
                "lastShare": item.get("lastShare") or item.get("LastShare") or None,
                "sharesPerSecond": item.get("sharesPerSecond") or item.get("SharesPerSecond") or None,
            }
        )

    return out


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
        pool_id = _pool_id_for_algo("sha256")
        pool = _pool_status(pool_id, algo="sha256")
        diagnostics["pool"] = {
            "workers": pool.get("workers"),
            "hashrate_ths": pool.get("hashrate_ths"),
            "best_difficulty_since_block": pool.get("best_difficulty_since_block"),
            "best_difficulty_all": pool.get("best_difficulty_all"),
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


def _parse_iso_to_ms(value: str) -> int | None:
    s = str(value or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return None


def _trail_to_seconds(trail: str) -> int:
    trail = (trail or "").strip().lower()
    return {
        "30m": 30 * 60,
        "6h": 6 * 60 * 60,
        "12h": 12 * 60 * 60,
        "1d": 24 * 60 * 60,
        "3d": 3 * 24 * 60 * 60,
        "6d": 6 * 24 * 60 * 60,
        "7d": 7 * 24 * 60 * 60,
    }.get(trail, 30 * 60)


def _downsample(points: list[dict], max_points: int) -> list[dict]:
    if len(points) <= max_points:
        return points
    stride = (len(points) + max_points - 1) // max_points
    return points[::stride]


class PoolSeries:
    def __init__(self, path: Path):
        self._lock = threading.Lock()
        self._points: list[dict] = []
        self._path = path

    def load(self):
        cutoff_ms = _now_ms() - (MAX_RETENTION_S * 1000)
        points: list[dict] = []
        if self._path.exists():
            for line in self._path.read_text(encoding="utf-8", errors="replace").splitlines():
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
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text("\n".join(json.dumps(p, separators=(",", ":")) for p in points) + ("\n" if points else ""), encoding="utf-8")
        tmp.replace(self._path)

    def append(self, point: dict):
        cutoff_ms = _now_ms() - (MAX_RETENTION_S * 1000)
        with self._lock:
            self._points.append(point)
            self._points = [p for p in self._points if int(p.get("t") or 0) >= cutoff_ms]
            if len(self._points) > MAX_SERIES_POINTS:
                self._points = self._points[-MAX_SERIES_POINTS:]

            STATE_DIR.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(point, separators=(",", ":")) + "\n")

            # Occasionally compact the file (simple heuristic).
            if self._path.stat().st_size > 10 * 1024 * 1024:
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


POOL_SERIES_BY_POOL: dict[str, PoolSeries] = {}
POOL_LAST_REQUEST_S: dict[str, float] = {}
POOL_LAST_REQUEST_LOCK = threading.Lock()


def _pool_series(pool_id: str) -> PoolSeries:
    series = POOL_SERIES_BY_POOL.get(pool_id)
    if series is None:
        series = PoolSeries(_pool_series_path(pool_id))
        POOL_SERIES_BY_POOL[pool_id] = series
    return series


BEST_DIFFICULTY_TTL_S = int(os.getenv("BEST_DIFFICULTY_TTL_S", "15"))
BEST_DIFFICULTY_CACHE: dict[str, dict] = {}
BEST_DIFFICULTY_CACHE_LOCK = threading.Lock()


def _iso_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _miningcore_postgres_cfg() -> dict | None:
    try:
        conf = _read_miningcore_conf()
        persistence = conf.get("persistence") if isinstance(conf, dict) else None
        postgres = persistence.get("postgres") if isinstance(persistence, dict) else None
        postgres = postgres if isinstance(postgres, dict) else None
        if not postgres:
            return None
        host = str(postgres.get("host") or "").strip()
        user = str(postgres.get("user") or "").strip()
        password = str(postgres.get("password") or "").strip()
        database = str(postgres.get("database") or "").strip()
        port = _to_int(postgres.get("port"), 5432)
        if not host or not user or not database:
            return None
        return {"host": host, "port": port, "user": user, "password": password, "database": database}
    except Exception:
        return None


def _pool_best_difficulties(pool_id: str) -> dict:
    now = time.time()
    with BEST_DIFFICULTY_CACHE_LOCK:
        cached = BEST_DIFFICULTY_CACHE.get(pool_id)
        if cached and (now - float(cached.get("t") or 0.0)) <= BEST_DIFFICULTY_TTL_S:
            data = cached.get("data")
            return dict(data) if isinstance(data, dict) else {}

    if pg8000 is None:
        return {}

    cfg = _miningcore_postgres_cfg()
    if not cfg:
        return {}

    best_diff_all = None
    best_diff_since = None
    best_share_all = None
    best_share_since = None
    last_block_created = None

    try:
        conn = pg8000.connect(
            user=cfg["user"],
            password=cfg.get("password") or None,
            host=cfg["host"],
            port=int(cfg["port"]),
            database=cfg["database"],
            timeout=3,
        )
        try:
            cur = conn.cursor()
            cur.execute("SELECT MAX(difficulty) FROM shares WHERE poolid=%s", (pool_id,))
            row = cur.fetchone()
            best_diff_all = float(row[0]) if row and row[0] is not None else None

            try:
                cur.execute("SELECT MAX(actualdifficulty) FROM shares WHERE poolid=%s", (pool_id,))
                row = cur.fetchone()
                best_share_all = float(row[0]) if row and row[0] is not None else None
            except Exception:
                best_share_all = None

            cur.execute("SELECT MAX(created) FROM blocks WHERE poolid=%s", (pool_id,))
            row = cur.fetchone()
            last_block_created = row[0] if row and row[0] is not None else None

            if last_block_created is not None:
                cur.execute(
                    "SELECT MAX(difficulty) FROM shares WHERE poolid=%s AND created >= %s",
                    (pool_id, last_block_created),
                )
                row = cur.fetchone()
                best_diff_since = float(row[0]) if row and row[0] is not None else None

                try:
                    cur.execute(
                        "SELECT MAX(actualdifficulty) FROM shares WHERE poolid=%s AND created >= %s",
                        (pool_id, last_block_created),
                    )
                    row = cur.fetchone()
                    best_share_since = float(row[0]) if row and row[0] is not None else None
                except Exception:
                    best_share_since = None
            else:
                best_diff_since = best_diff_all
                best_share_since = best_share_all

            if best_share_all is None:
                best_share_all = best_diff_all
            if best_share_since is None:
                best_share_since = best_diff_since
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        out = {
            "best_difficulty_all": None,
            "best_difficulty_since_block": None,
            "best_difficulty_since_block_at": None,
            "best_share_all": None,
            "best_share_since_block": None,
            "best_share_since_block_at": None,
        }
        with BEST_DIFFICULTY_CACHE_LOCK:
            BEST_DIFFICULTY_CACHE[pool_id] = {"t": now, "data": out}
        return dict(out)

    out = {
        "best_difficulty_all": best_diff_all,
        "best_difficulty_since_block": best_diff_since,
        "best_difficulty_since_block_at": _iso_z(last_block_created) if isinstance(last_block_created, datetime) else None,
        "best_share_all": best_share_all,
        "best_share_since_block": best_share_since,
        "best_share_since_block_at": _iso_z(last_block_created) if isinstance(last_block_created, datetime) else None,
    }

    with BEST_DIFFICULTY_CACHE_LOCK:
        BEST_DIFFICULTY_CACHE[pool_id] = {"t": now, "data": out}
    return out


def _pool_share_health(pool_id: str) -> dict:
    if pg8000 is None:
        return {}
    cfg = _miningcore_postgres_cfg()
    if not cfg:
        return {}

    cutoff_10m = datetime.now(timezone.utc) - timedelta(minutes=10)
    cutoff_1h = datetime.now(timezone.utc) - timedelta(hours=1)

    try:
        conn = pg8000.connect(
            user=cfg["user"],
            password=cfg.get("password") or None,
            host=cfg["host"],
            port=int(cfg["port"]),
            database=cfg["database"],
            timeout=3,
        )
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*), COALESCE(SUM(difficulty), 0), MIN(created), MAX(created) FROM shares WHERE poolid=%s AND created >= %s",
                (pool_id, cutoff_10m),
            )
            row = cur.fetchone()
            shares_10m = int(row[0]) if row and row[0] is not None else 0
            sumdiff_10m = float(row[1]) if row and row[1] is not None else 0.0
            first_share_10m = row[2] if row and len(row) > 2 else None
            last_share_10m = row[3] if row and len(row) > 3 else None

            cur.execute(
                "SELECT COUNT(*) FROM shares WHERE poolid=%s AND created >= %s",
                (pool_id, cutoff_1h),
            )
            row = cur.fetchone()
            shares_1h = int(row[0]) if row and row[0] is not None else 0

            cur.execute(
                "SELECT MAX(created) FROM shares WHERE poolid=%s",
                (pool_id,),
            )
            row = cur.fetchone()
            last_share_created = row[0] if row and row[0] is not None else None
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        return {}

    last_share_iso = _iso_z(last_share_created) if isinstance(last_share_created, datetime) else None
    # Estimate pool hashrate from accepted shares over the last 10 minutes:
    # H/s ≈ sum(share_difficulty) * 2^32 / elapsed_seconds (capped to 10m, floored to 60s)
    hashrate_hs_10m = None
    try:
        if sumdiff_10m and sumdiff_10m > 0:
            window_s = 10 * 60
            span_s = None
            if isinstance(first_share_10m, datetime) and isinstance(last_share_10m, datetime):
                try:
                    span_s = (last_share_10m - first_share_10m).total_seconds()
                except Exception:
                    span_s = None
            if span_s is None or not math.isfinite(float(span_s)) or span_s <= 0:
                span_s = window_s
            span_s = max(60.0, min(float(span_s), float(window_s)))
            hashrate_hs_10m = (sumdiff_10m * (2**32)) / span_s
    except Exception:
        hashrate_hs_10m = None

    return {
        "shares_10m": shares_10m,
        "shares_1h": shares_1h,
        "last_share_at": last_share_iso,
        "hashrate_hs_10m": hashrate_hs_10m,
    }


def _series_sampler(stop_event: threading.Event):
    while not stop_event.is_set():
        ids = _pool_ids()
        for algo, pool_id in ids.items():
            # Avoid hammering Miningcore for secondary pools during node warmup.
            # Miningcore can return 500s for pools that haven't fully initialized yet.
            if algo != "sha256":
                with POOL_LAST_REQUEST_LOCK:
                    last = float(POOL_LAST_REQUEST_S.get(pool_id) or 0.0)
                if last <= 0 or (time.time() - last) > 120:
                    continue
            try:
                status = _pool_status(pool_id, algo=algo)
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
                netdiff_f = to_float(status.get("network_difficulty"))
                netheight_i = _maybe_int(status.get("network_height"))

                _pool_series(pool_id).append(
                    {
                        "t": _now_ms(),
                        "workers": workers_i,
                        "hashrate_ths": hashrate_f,
                        "network_difficulty": netdiff_f,
                        "network_height": netheight_i,
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
    pool_id = _pool_id_for_algo("sha256")
    p = _pool_status(pool_id, algo="sha256")
    best = p.get("best_share_since_block") or p.get("best_share_all") or p.get("best_difficulty_since_block") or p.get("best_difficulty_all")
    return {
        "type": "three-stats",
        "items": [
            {"title": "Hashrate", "text": str(p.get("hashrate_ths") or "-"), "subtext": "TH/s"},
            {"title": "Workers", "text": str(p.get("workers") or 0)},
            {"title": "Best share", "text": str(best or "-"), "subtext": ""},
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
        raw_path = self.path
        path = urlsplit(self.path).path
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
            cached = _read_node_cache()
            if cached and (int(time.time()) - int(cached["t"])) <= 4:
                payload = dict(cached["status"])
                payload.update(
                    {
                        "cached": True,
                        "lastSeen": int(cached["t"]),
                        "reindexRequested": reindex_requested,
                        "reindexRequired": reindex_required,
                    }
                )
                return self._send(*_json(payload))

            acquired = NODE_STATUS_LOCK.acquire(blocking=False)
            if not acquired:
                if cached:
                    payload = dict(cached["status"])
                    payload.update(
                        {
                            "cached": True,
                            "lastSeen": int(cached["t"]),
                            "error": "busy",
                            "reindexRequested": reindex_requested,
                            "reindexRequired": reindex_required,
                        }
                    )
                    return self._send(*_json(payload))
                return self._send(*_json({"error": "busy"}, status=503))

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
            except Exception as e:
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
                cached = cached or _read_node_cache()
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
            finally:
                if acquired:
                    try:
                        NODE_STATUS_LOCK.release()
                    except Exception:
                        pass

        if path == "/api/pool":
            algo = _algo_from_query(raw_path)
            pool_id = _pool_id_for_algo(algo)
            with POOL_LAST_REQUEST_LOCK:
                POOL_LAST_REQUEST_S[pool_id] = time.time()
            return self._send(*_json(_pool_status(pool_id, algo=algo)))

        if path == "/api/pool/miners" or path == "/api/pool/workers":
            algo = _algo_from_query(raw_path)
            pool_id = _pool_id_for_algo(algo)
            with POOL_LAST_REQUEST_LOCK:
                POOL_LAST_REQUEST_S[pool_id] = time.time()
            try:
                miners = _pool_miners(pool_id)
                return self._send(*_json({"poolId": pool_id, "algo": algo, "miners": miners}))
            except Exception as e:
                return self._send(*_json({"poolId": pool_id, "algo": algo, "miners": [], "error": str(e)}, status=503))

        if path == "/api/blocks":
            try:
                query = ""
                if "?" in raw_path:
                    _, query = raw_path.split("?", 1)
                algo = None
                page = 0
                page_size = 25
                for part in query.split("&"):
                    if part.startswith("algo="):
                        algo = part.split("=", 1)[1].strip().lower() or None
                    if part.startswith("page="):
                        try:
                            page = int(part.split("=", 1)[1])
                        except Exception:
                            page = 0
                    if part.startswith("pageSize="):
                        try:
                            page_size = int(part.split("=", 1)[1])
                        except Exception:
                            page_size = 25
                page = max(0, page)
                page_size = max(1, min(100, page_size))

                pool_id = _pool_id_for_algo(algo)
                with POOL_LAST_REQUEST_LOCK:
                    POOL_LAST_REQUEST_S[pool_id] = time.time()

                data = _miningcore_get_any(f"/api/pools/{pool_id}/blocks?page={page}&pageSize={page_size}", timeout_s=6)
                blocks = []
                if isinstance(data, list):
                    blocks = data
                elif isinstance(data, dict):
                    maybe = data.get("blocks") or data.get("Blocks")
                    if isinstance(maybe, list):
                        blocks = maybe

                return self._send(*_json({"poolId": pool_id, "algo": algo, "page": page, "pageSize": page_size, "blocks": blocks}))
            except Exception as e:
                return self._send(*_json({"error": str(e)}, status=503))

        if path.startswith("/api/timeseries/pool"):
            try:
                query = ""
                if "?" in raw_path:
                    _, query = raw_path.split("?", 1)
                trail = "30m"
                algo = None
                for part in query.split("&"):
                    if part.startswith("trail="):
                        trail = part.split("=", 1)[1]
                    if part.startswith("algo="):
                        algo = part.split("=", 1)[1].strip().lower() or None

                pool_id = _pool_id_for_algo(algo)
                pts = _pool_series(pool_id).query(trail=trail, max_points=1000)

                windows = [
                    ("hashrate_1m_ths", 60),
                    ("hashrate_5m_ths", 5 * 60),
                    ("hashrate_15m_ths", 15 * 60),
                    ("hashrate_1h_ths", 60 * 60),
                ]
                enriched = []
                for i, p in enumerate(pts):
                    obj = dict(p)
                    # Compute rolling averages ending at this point's timestamp.
                    try:
                        t = int(obj.get("t") or 0)
                    except Exception:
                        t = 0
                    for key, window_s in windows:
                        cutoff = t - (window_s * 1000)
                        vals = []
                        for q in pts[: i + 1]:
                            try:
                                qt = int(q.get("t") or 0)
                            except Exception:
                                continue
                            if qt < cutoff:
                                continue
                            try:
                                fv = float(q.get("hashrate_ths"))
                            except Exception:
                                continue
                            if math.isfinite(fv):
                                vals.append(fv)
                        obj[key] = (sum(vals) / len(vals)) if vals else None
                    enriched.append(obj)

                return self._send(*_json({"trail": trail, "algo": algo, "poolId": pool_id, "points": enriched}))
            except Exception as e:
                return self._send(*_json({"error": str(e)}, status=500))

        if path.startswith("/api/timeseries/difficulty"):
            try:
                query = ""
                if "?" in raw_path:
                    _, query = raw_path.split("?", 1)

                trail = "30m"
                algo = None
                for part in query.split("&"):
                    if part.startswith("trail="):
                        trail = part.split("=", 1)[1]
                    if part.startswith("algo="):
                        algo = part.split("=", 1)[1].strip().lower() or None

                pool_id = _pool_id_for_algo(algo)

                # Prefer our higher-frequency sampler series (updates every ~30s) so 30m views
                # don't go blank between Miningcore's hourly performance buckets.
                series = _pool_series(pool_id).query(trail=trail, max_points=2000)
                pts = []
                for p in series:
                    try:
                        t = int(p.get("t") or 0)
                    except Exception:
                        continue
                    v = p.get("network_difficulty")
                    try:
                        v = float(v) if v is not None else None
                    except Exception:
                        v = None
                    if v is None or not math.isfinite(v):
                        continue
                    pts.append({"t": t, "difficulty": v})

                pts.sort(key=lambda p: p.get("t", 0))
                pts = _downsample(pts, 1000)
                if pts:
                    return self._send(*_json({"trail": trail, "algo": algo, "poolId": pool_id, "points": pts}))

                # Fallback: Miningcore hourly performance points.
                perf = _miningcore_get_json(f"/api/pools/{pool_id}/performance")
                rows = perf.get("stats") if isinstance(perf, dict) else None
                rows = rows if isinstance(rows, list) else []

                pts = []
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    t = _parse_iso_to_ms(r.get("created"))
                    if t is None:
                        continue
                    v = r.get("networkDifficulty")
                    try:
                        v = float(v) if v is not None else None
                    except Exception:
                        v = None
                    if v is None or not math.isfinite(v):
                        continue
                    pts.append({"t": int(t), "difficulty": v})

                pts.sort(key=lambda p: p.get("t", 0))
                cutoff_ms = _now_ms() - (_trail_to_seconds(trail) * 1000)
                pts = [p for p in pts if int(p.get("t") or 0) >= cutoff_ms]
                pts = _downsample(pts, 1000)

                return self._send(*_json({"trail": trail, "algo": algo, "poolId": pool_id, "points": pts}))
            except Exception as e:
                return self._send(*_json({"error": str(e)}, status=500))

        if self.path == "/api/widget/sync":
            return self._send(*_json(_widget_sync()))

        if self.path == "/api/widget/pool":
            return self._send(*_json(_widget_pool()))

        status, body, ct = _read_static(path if path != "/" else "/index.html")
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
    for pool_id in _pool_ids().values():
        _pool_series(pool_id).load()

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
