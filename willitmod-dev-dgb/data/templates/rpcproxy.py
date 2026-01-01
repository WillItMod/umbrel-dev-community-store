import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


TARGET_RPC_URL = os.environ.get("TARGET_RPC_URL", "http://dgbd:14022/")
FORCE_ALGO = os.environ.get("FORCE_ALGO", "sha256d")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "14022"))


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length_header = handler.headers.get("Content-Length")
    if not length_header:
        return b""
    return handler.rfile.read(int(length_header))


def _force_algo(payload: object) -> object:
    if not isinstance(payload, dict):
        return payload
    if payload.get("method") != "getblocktemplate":
        return payload

    params = payload.get("params")
    if params is None:
        payload["params"] = [{}, FORCE_ALGO]
        return payload

    if not isinstance(params, list):
        return payload

    if len(params) == 0:
        payload["params"] = [{}, FORCE_ALGO]
        return payload

    if len(params) == 1:
        template_req = params[0]
        if template_req is None:
            template_req = {}
        payload["params"] = [template_req, FORCE_ALGO]
        return payload

    return payload


class Handler(BaseHTTPRequestHandler):
    server_version = "axedgb-rpcproxy/1.0"

    def do_POST(self) -> None:
        body = _read_body(self)
        try:
            request_json = json.loads(body.decode("utf-8")) if body else None
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"invalid json")
            return

        if isinstance(request_json, list):
            request_json = [_force_algo(item) for item in request_json]
        else:
            request_json = _force_algo(request_json)

        out_body = json.dumps(request_json).encode("utf-8")

        req = urllib.request.Request(TARGET_RPC_URL, data=out_body, method="POST")
        content_type = self.headers.get("Content-Type")
        if content_type:
            req.add_header("Content-Type", content_type)
        req.add_header("Content-Length", str(len(out_body)))

        auth = self.headers.get("Authorization")
        if auth:
            req.add_header("Authorization", auth)

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for key, value in resp.headers.items():
                    if key.lower() in {"connection", "transfer-encoding"}:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))


def main() -> None:
    httpd = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    sys.stderr.write(f"[rpcproxy] listening on {LISTEN_HOST}:{LISTEN_PORT}, forwarding to {TARGET_RPC_URL}, force_algo={FORCE_ALGO}\n")
    httpd.serve_forever()


if __name__ == "__main__":
    main()

