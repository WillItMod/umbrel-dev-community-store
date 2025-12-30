import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


CONFIG_PATH = Path("/config/ckpool.conf")
WWW_ROOT = Path("/www")


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _read_config_for_ui():
    defaults = {
        "rpc_host": os.getenv("BCH_RPC_HOST", "umbrel.local"),
        "rpc_port": os.getenv("BCH_RPC_PORT", "28332"),
        "rpc_user": os.getenv("BCH_RPC_USER", "bch"),
        "zmq_host": os.getenv("BCH_ZMQ_HOST", "umbrel.local"),
        "zmq_port": os.getenv("BCH_ZMQ_HASHBLOCK_PORT", "28334"),
    }
    if not CONFIG_PATH.exists():
        return defaults

    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return defaults

    btcd = (data.get("btcd") or [{}])[0] or {}
    url = str(btcd.get("url") or "")
    host, _, port = url.partition(":")
    zmq = str(data.get("zmqblock") or "")
    zmq = zmq.removeprefix("tcp://")
    zhost, _, zport = zmq.partition(":")

    return {
        "rpc_host": host or defaults["rpc_host"],
        "rpc_port": port or defaults["rpc_port"],
        "rpc_user": str(btcd.get("auth") or defaults["rpc_user"]),
        "zmq_host": zhost or defaults["zmq_host"],
        "zmq_port": zport or defaults["zmq_port"],
    }


def _write_ckpool_conf(rpc_host: str, rpc_port: str, rpc_user: str, rpc_pass: str, zmq_host: str, zmq_port: str):
    rpc_host = (rpc_host or "umbrel.local").strip()
    rpc_port_int = _safe_int((rpc_port or "28332").strip(), 28332)
    rpc_user = (rpc_user or "bch").strip()
    rpc_pass = rpc_pass or ""
    if not rpc_pass.strip():
        raise ValueError("RPC password is required")

    zmq_host = (zmq_host or "umbrel.local").strip()
    zmq_port_int = _safe_int((zmq_port or "28334").strip(), 28334)

    conf = {
        "btcd": [
            {
                "url": f"{rpc_host}:{rpc_port_int}",
                "auth": rpc_user,
                "pass": rpc_pass,
                "notify": True,
            }
        ],
        "btcsig": "/mined by WillItMod on Umbrel/",
        "mindiff": 1,
        "startdiff": 16,
        "maxdiff": 0,
        "logdir": "/www",
        "zmqblock": f"tcp://{zmq_host}:{zmq_port_int}",
    }

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(conf, indent=2) + "\n", encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/config":
            payload = json.dumps(_read_config_for_ui()).encode("utf-8")
            self._send(200, payload, "application/json")
            return

        if self.path == "/" or self.path.startswith("/index.html"):
            index = WWW_ROOT / "index.html"
            if index.exists():
                self._send(200, index.read_bytes(), "text/html; charset=utf-8")
                return
            self._send(404, b"missing index.html", "text/plain; charset=utf-8")
            return

        rel = self.path.lstrip("/")
        file_path = (WWW_ROOT / rel).resolve()
        if not str(file_path).startswith(str(WWW_ROOT.resolve())):
            self._send(403, b"forbidden", "text/plain; charset=utf-8")
            return
        if not file_path.exists() or not file_path.is_file():
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return

        body = file_path.read_bytes()
        content_type = "application/octet-stream"
        if file_path.suffix in [".html", ".htm"]:
            content_type = "text/html; charset=utf-8"
        elif file_path.suffix == ".json":
            content_type = "application/json"
        elif file_path.suffix in [".txt", ".log"]:
            content_type = "text/plain; charset=utf-8"
        self._send(200, body, content_type)

    def do_POST(self):
        if self.path != "/api/config":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return

        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(400, b"invalid json", "text/plain; charset=utf-8")
            return

        try:
            _write_ckpool_conf(
                rpc_host=str(body.get("rpc_host") or ""),
                rpc_port=str(body.get("rpc_port") or ""),
                rpc_user=str(body.get("rpc_user") or ""),
                rpc_pass=str(body.get("rpc_pass") or ""),
                zmq_host=str(body.get("zmq_host") or ""),
                zmq_port=str(body.get("zmq_port") or ""),
            )
        except Exception as e:
            self._send(400, str(e).encode("utf-8"), "text/plain; charset=utf-8")
            return

        self._send(200, b"ok", "text/plain; charset=utf-8")


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 3000), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

