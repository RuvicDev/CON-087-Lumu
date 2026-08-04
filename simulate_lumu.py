"""Simulación local de la API Lumu Defender para probar el conector sin key real.

Uso:
    python simulate_lumu.py

Levanta un servidor HTTP en http://127.0.0.1:8000 que emula los endpoints:
    POST /incidents/all
    POST /incidents/open
    POST /adversarial-activity
    GET  /incidents/<id>/context

- key correcta -> HTTP 200 con datos de ejemplo.
- key "BAD_KEY" -> HTTP 401 simulado ("Invalid authentication credentials").
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

HOST, PORT = "127.0.0.1", 8000
VALID_KEY = "DEFENDER_API_KEY_VALIDA"

SAMPLE_INCIDENT = {
    "id": "11111111-2222-3333-4444-555555555555",
    "companyId": "d359098f-68ec-4956-bd61-7a66eca5df80",
    "status": "open",
    "adversaryType": "Malware",
    "endpoint": "10.0.0.5",
    "contact": "malicious.example.com",
}

SAMPLE_EVIDENCE = {
    "id": "aaaaaaaa-0000-1111-2222-333333333333",
    "endpoint": "10.0.0.5",
    "contact": "malicious.example.com",
    "type": "C2C",
}

def _read_json(body: bytes) -> dict:
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {}

class LumuMockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    daemon_threads = True

    def _send(self, code: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _check_auth(self) -> bool:
        query = parse_qs(urlparse(self.path).query)
        key = (query.get("key") or [""])[0]
        return key == VALID_KEY

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = _read_json(self.rfile.read(length))
        print(f"  [mock] POST {self.path} body={json.dumps(body)}", flush=True)
        if not self._check_auth():
            print("  [mock] -> 401 Invalid authentication credentials", flush=True)
            self._send(401, {"message": "Invalid authentication credentials"})
            return
        if self.path.startswith("/incidents/all"):
            self._send(200, {"incidents": [SAMPLE_INCIDENT, dict(SAMPLE_INCIDENT, status="closed")]})
        elif self.path.startswith("/incidents/open"):
            self._send(200, {"incidents": [SAMPLE_INCIDENT]})
        elif self.path.startswith("/adversarial-activity"):
            self._send(200, {"iocs": [{"indicator": "1.2.3.4", "type": "ip", "adversaryType": "Malware"}]})
        else:
            self._send(404, {"message": "not found"})

    def do_GET(self) -> None:
        print(f"  [mock] GET {self.path}", flush=True)
        if not self._check_auth():
            print("  [mock] -> 401 Invalid authentication credentials", flush=True)
            self._send(401, {"message": "Invalid authentication credentials"})
            return
        if self.path.startswith("/incidents/"):
            self._send(200, {"context": [SAMPLE_EVIDENCE]})
        else:
            self._send(404, {"message": "not found"})

    def log_message(self, *args) -> None:
        pass

def main() -> None:
    from ruvic_lumu_connector import LumuClient, LumuConfig

    server = HTTPServer((HOST, PORT), LumuMockHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://{HOST}:{PORT}"
    print(f"Mock Lumu escuchando en {base}\n", flush=True)

    print("== Prueba 1: key válida (simula STATUS 200) ==")
    good = LumuClient(LumuConfig(api_key=VALID_KEY, base_url=base))
    print("ping:", good.ping())
    print("incidents:", good.get_incidents(limit=5))
    print("compromises:", good.get_compromises(limit=5))
    print("iocs:", good.get_iocs(days=7, limit=5))
    print("evidence:", good.get_evidence(SAMPLE_INCIDENT["id"], limit=5))

    print("\n== Prueba 2: key inválida (simula STATUS 401) ==")
    bad = LumuClient(LumuConfig(api_key="BAD_KEY", base_url=base))
    try:
        bad.get_incidents(limit=1)
    except Exception as exc:
        print(f"get_incidents -> {type(exc).__name__}: {exc}")

    server.shutdown()
    print("\nSimulación terminada.")

if __name__ == "__main__":
    main()
