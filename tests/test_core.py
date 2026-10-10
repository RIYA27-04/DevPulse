"""Tests for app.core. Standard library only (unittest); pytest runs these too."""
import http.server
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app import core


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(500 if self.path == "/fail" else 200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    # ---- SSRF helpers ----
    def test_is_private_ip(self):
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                   "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"]:
            self.assertTrue(core.is_private_ip(ip), ip)
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2606:4700:4700::1111"]:
            self.assertFalse(core.is_private_ip(ip), ip)

    def test_parse_target_accepts_valid_urls(self):
        t = core.parse_target("https://example.com/path?q=1")
        self.assertEqual((t.scheme, t.host, t.port, t.path), ("https", "example.com", 443, "/path?q=1"))
        self.assertEqual(core.parse_target("http://example.com").port, 80)
        self.assertEqual(core.parse_target("http://example.com:8081/").port, 8081)

    def test_parse_target_rejects_bad_input(self):
        for bad in ["file:///etc/passwd", "ftp://example.com", "javascript:alert(1)", "not a url",
                    "", "http://", "http://user:pw@example.com", "http://example.com:99999",
                    "http://example.com/" + "a" * 3000]:
            with self.assertRaises(core.ValidationError, msg=bad):
                core.parse_target(bad)

    def test_parse_target_blocks_private_literals(self):
        with patch.dict(os.environ, {"ALLOW_PRIVATE": "0"}):
            for bad in ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data",
                        "http://10.0.0.5", "http://[::1]/"]:
                with self.assertRaises(core.ValidationError, msg=bad):
                    core.parse_target(bad)

    # ---- prober ----
    def test_probe_up(self):
        with patch.dict(os.environ, {"ALLOW_PRIVATE": "1"}):
            r = core.probe(core.parse_target(self.base))
        self.assertTrue(r["ok"])
        self.assertEqual(r["status"], 200)
        self.assertGreaterEqual(r["ms"], 0)

    def test_probe_down_on_http_500(self):
        with patch.dict(os.environ, {"ALLOW_PRIVATE": "1"}):
            r = core.probe(core.parse_target(self.base + "/fail"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], 500)

    def test_probe_blocks_internal_targets(self):
        with patch.dict(os.environ, {"ALLOW_PRIVATE": "1"}):
            target = core.parse_target(self.base)       # allowed to parse...
        with patch.dict(os.environ, {"ALLOW_PRIVATE": "0"}):
            r = core.probe(target)                       # ...but blocked at connect time
        self.assertFalse(r["ok"])
        self.assertIn("Private", r["error"])

    def test_probe_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()                                        # nothing listens on this port now
        with patch.dict(os.environ, {"ALLOW_PRIVATE": "1"}):
            r = core.probe(core.parse_target(f"http://127.0.0.1:{port}"), timeout=2)
        self.assertFalse(r["ok"])
        self.assertTrue(r["error"])

    # ---- store ----
    def _store(self, **kw):
        tmp = tempfile.mkdtemp()
        return core.MonitorStore(Path(tmp) / "m.json", **kw), Path(tmp) / "m.json"

    def test_store_stats_and_persistence(self):
        store, path = self._store()
        m = store.add("demo", "https://example.com")
        ok = lambda ms: {"t": 1, "ok": True, "status": 200, "ms": ms, "error": None}
        store.record(m["id"], ok(100))
        store.record(m["id"], ok(200))
        store.record(m["id"], {"t": 2, "ok": False, "status": 500, "ms": 50, "error": None})
        v = core.view(store.get(m["id"]))
        self.assertEqual(v["uptime"], 66.67)
        self.assertEqual(v["avgMs"], 150)
        self.assertEqual(v["status"], "down")
        self.assertEqual(v["lastError"], "HTTP 500")
        self.assertEqual(v["checks"], 3)
        reloaded = core.MonitorStore(path)               # survives a restart
        self.assertEqual(core.view(reloaded.get(m["id"]))["checks"], 3)

    def test_store_pending_before_first_check(self):
        store, _ = self._store()
        v = core.view(store.add("new", "https://example.com"))
        self.assertEqual((v["status"], v["uptime"], v["avgMs"]), ("pending", None, None))

    def test_store_limit_and_delete(self):
        store, _ = self._store(max_monitors=2)
        a = store.add("a", "https://a.example")
        store.add("b", "https://b.example")
        with self.assertRaises(core.ValidationError):
            store.add("c", "https://c.example")
        self.assertTrue(store.remove(a["id"]))
        self.assertFalse(store.remove(a["id"]))
        store.add("c", "https://c.example")               # room again

    def test_history_is_trimmed(self):
        store, _ = self._store()
        m = store.add("x", "https://example.com")
        for i in range(core.HISTORY_LIMIT + 25):
            store.record(m["id"], {"t": i, "ok": True, "status": 200, "ms": 1, "error": None})
        self.assertEqual(len(store.get(m["id"])["history"]), core.HISTORY_LIMIT)

    def test_record_for_deleted_monitor_is_ignored(self):
        store, _ = self._store()
        m = store.add("x", "https://example.com")
        store.remove(m["id"])
        store.record(m["id"], {"t": 1, "ok": True, "status": 200, "ms": 1, "error": None})  # no crash


if __name__ == "__main__":
    unittest.main()
