"""API tests (need: pip install -r requirements-dev.txt)."""
import http.server
import os
import tempfile
import threading

# Must be set before the app is imported
os.environ["ALLOW_PRIVATE"] = "1"          # tests monitor a local target server
os.environ["CHECK_INTERVAL_SEC"] = "0"     # no background scheduler during tests
os.environ["DATA_FILE"] = os.path.join(tempfile.mkdtemp(), "monitors.json")

import pytest
from fastapi.testclient import TestClient

from app.main import app


class _Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(500 if self.path == "/fail" else 200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def target():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_dashboard_is_served_with_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "DevPulse" in r.text
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_rejects_bad_urls(client):
    for bad in ["file:///etc/passwd", "not a url", "ftp://example.com"]:
        assert client.post("/api/monitors", json={"url": bad}).status_code == 400


def test_rejects_missing_url(client):
    assert client.post("/api/monitors", json={}).status_code == 422


def test_create_up_monitor(client, target):
    r = client.post("/api/monitors", json={"name": "local", "url": target})
    assert r.status_code == 201
    m = r.json()
    assert m["status"] == "up" and m["uptime"] == 100 and m["checks"] == 1


def test_detects_down_and_check_now(client, target):
    m = client.post("/api/monitors", json={"name": "bad", "url": target + "/fail"}).json()
    assert m["status"] == "down" and m["uptime"] == 0
    again = client.post(f"/api/monitors/{m['id']}/check").json()
    assert again["checks"] == 2


def test_list_get_delete(client, target):
    m = client.post("/api/monitors", json={"url": target}).json()
    assert any(x["id"] == m["id"] for x in client.get("/api/monitors").json())
    assert client.get(f"/api/monitors/{m['id']}").status_code == 200
    assert client.delete(f"/api/monitors/{m['id']}").status_code == 200
    assert client.get(f"/api/monitors/{m['id']}").status_code == 404


def test_ssrf_guard_blocks_internal_targets(client, monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE", "0")
    for url in ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data",
                "http://10.0.0.5", "http://[::1]/", "http://localhost"]:
        assert client.post("/api/monitors", json={"url": url}).status_code == 400, url
