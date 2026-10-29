"""Проверка клиента OpenCTI на локальном фейковом GraphQL-сервере."""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_extractor.extractor import IoC
from ioc_extractor.opencti import OpenCTIClient, OpenCTIError, observable_variables


class FakeOpenCTI(BaseHTTPRequestHandler):
    calls: list = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOpenCTI.calls.append((self.headers.get("opencti-draft-id"), self.headers.get("Authorization"), body))
        q = body["query"]
        if self.headers.get("Authorization") != "Bearer good":
            self.send_response(401)
            self.end_headers()
            return
        if "draftWorkspaceAdd" in q:
            data = {"data": {"draftWorkspaceAdd": {"id": "draft-1", "name": body["variables"]["input"]["name"]}}}
        elif "stixCyberObservableAdd" in q:
            if body["variables"].get("Url", {}).get("value") == "http://bad/":
                data = {"errors": [{"message": "Validation", "extensions": {"data": {"reason": "bad url"}}}]}
            else:
                data = {"data": {"stixCyberObservableAdd": {"id": f"obs-{len(FakeOpenCTI.calls)}"}}}
        elif "reportAdd" in q:
            data = {"data": {"reportAdd": {"id": "report-1"}}}
        else:
            data = {"data": {"about": {"version": "6.8.0"}}}
        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _server():
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenCTI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_observable_variables():
    v = observable_variables(IoC("hash", "a" * 64, "sha256"))
    assert v == {"type": "StixFile", "StixFile": {"hashes": [{"algorithm": "SHA-256", "hash": "a" * 64}]}}
    assert observable_variables(IoC("ip", "::1", "ipv6"))["type"] == "IPv6-Addr"
    assert observable_variables(IoC("domain", "x.ru"))["DomainName"] == {"value": "x.ru"}


def test_import_flow():
    srv, url = _server()
    FakeOpenCTI.calls = []
    try:
        client = OpenCTIClient(url, "good")
        assert client.version() == "6.8.0"
        iocs = [IoC("domain", "evil.com"), IoC("url", "http://bad/"), IoC("hash", "b" * 32, "md5")]
        progress = []
        res = client.import_iocs(iocs, "Draft X", score=70, progress=lambda n, t: progress.append(n))
        assert res.draft_id == "draft-1" and res.created == 2 and res.report_id == "report-1"
        assert res.errors == ["http://bad/: Validation: bad url"]
        assert progress == [1, 2, 3]
        draft_hdr = [c[0] for c in FakeOpenCTI.calls]
        # версия и создание черновика — вне черновика, всё остальное — внутри
        assert draft_hdr[:2] == [None, None] and set(draft_hdr[2:]) == {"draft-1"}
        obs = FakeOpenCTI.calls[2][2]["variables"]
        assert obs["score"] == 70 and obs["createIndicator"] is True
        report = FakeOpenCTI.calls[-1][2]["variables"]["input"]
        assert report["name"] == "Draft X" and len(report["objects"]) == 2
    finally:
        srv.shutdown()


def test_bad_token():
    srv, url = _server()
    try:
        try:
            OpenCTIClient(url, "wrong").version()
            raise AssertionError("ожидалась ошибка")
        except OpenCTIError as e:
            assert "токен" in str(e)
    finally:
        srv.shutdown()
