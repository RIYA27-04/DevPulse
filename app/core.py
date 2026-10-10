"""DevPulse core logic (standard library only).

* SSRF-safe URL validation
* A prober that connects to a *validated, pinned* IP address (defeats DNS rebinding)
* A small thread-safe JSON-backed store with uptime/latency statistics
"""
import copy
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

PROBE_TIMEOUT = 8       # seconds
HISTORY_LIMIT = 100     # checks kept per monitor
MAX_URL_LEN = 2048


class ValidationError(ValueError):
    """An input problem that is safe to show to the user."""


def allow_private() -> bool:
    """Only for local development and tests. Never enable in production."""
    return os.environ.get("ALLOW_PRIVATE") == "1"


# --------------------------------------------------------------------------- #
# SSRF protection
# --------------------------------------------------------------------------- #
def is_private_ip(ip: str) -> bool:
    """True for loopback, private LAN, link-local (incl. cloud metadata), CGNAT, reserved, multicast."""
    addr = ipaddress.ip_address(ip.split("%")[0])
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (not addr.is_global) or addr.is_multicast


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str
    url: str


def parse_target(raw: str) -> Target:
    raw = str(raw).strip()
    if not raw or len(raw) > MAX_URL_LEN:
        raise ValidationError("Invalid URL")
    try:
        u = urlsplit(raw)
        port = u.port
    except ValueError:
        raise ValidationError("Invalid URL")
    if u.scheme not in ("http", "https"):
        raise ValidationError("Only http:// and https:// URLs are allowed")
    if not u.hostname:
        raise ValidationError("Invalid URL")
    if u.username or u.password:
        raise ValidationError("Credentials in URLs are not allowed")
    try:
        literal_ip = ipaddress.ip_address(u.hostname)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and not allow_private() and is_private_ip(str(literal_ip)):
        raise ValidationError("Private/internal addresses are not allowed")
    port = port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return Target(u.scheme, u.hostname, port, path, raw)


def resolve_public(host: str, port: int) -> list:
    """Resolve a hostname and refuse private/internal results. Raises OSError if it can't resolve."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = [info[4][0] for info in infos]
    if not ips:
        raise OSError("hostname did not resolve")
    if not allow_private() and any(is_private_ip(ip) for ip in ips):
        raise ValidationError("Private/internal addresses are not allowed")
    return ips


# --------------------------------------------------------------------------- #
# Prober: connect to the already-validated IP, keep Host header / TLS SNI correct
# --------------------------------------------------------------------------- #
class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout):
        self._ctx = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._ctx)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


def failure(message: str) -> dict:
    return {"t": int(time.time() * 1000), "ok": False, "status": 0, "ms": 0, "error": message}


def probe(target: Target, timeout: float = PROBE_TIMEOUT) -> dict:
    """Blocking HTTP GET. Never raises; returns a result dict."""
    t0 = time.perf_counter()

    def done(ok, status=0, error=None):
        return {"t": int(time.time() * 1000), "ok": ok, "status": status,
                "ms": round((time.perf_counter() - t0) * 1000), "error": error}

    conn = None
    try:
        ip = resolve_public(target.host, target.port)[0]   # validate right before connecting
        cls = _PinnedHTTPS if target.scheme == "https" else _PinnedHTTP
        conn = cls(target.host, target.port, ip, timeout)
        conn.request("GET", target.path, headers={"User-Agent": "DevPulse/1.0", "Accept": "*/*"})
        status = conn.getresponse().status
        return done(status < 400, status)
    except ValidationError as e:
        return done(False, 0, str(e))
    except TimeoutError:
        return done(False, 0, "timeout")
    except Exception as e:  # noqa: BLE001 - a probe must never crash the scheduler
        return done(False, 0, f"{type(e).__name__}: {e}"[:200])
    finally:
        if conn is not None:
            conn.close()


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
class MonitorStore:
    def __init__(self, path, max_monitors: int = 20):
        self.path = Path(path)
        self.max = max_monitors
        self._lock = threading.RLock()
        self._monitors: dict = {}
        self._load()

    def _load(self):
        try:
            self._monitors = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._monitors = {}

    def flush(self):
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self._monitors), encoding="utf-8")
                os.replace(tmp, self.path)          # atomic: no half-written files
            except OSError as e:
                print(f"save failed: {e}")

    def add(self, name: str, url: str) -> dict:
        with self._lock:
            if len(self._monitors) >= self.max:
                raise ValidationError(f"Limit of {self.max} monitors reached")
            m = {"id": secrets.token_hex(5), "name": name, "url": url,
                 "createdAt": int(time.time() * 1000), "history": []}
            self._monitors[m["id"]] = m
            self.flush()
            return copy.deepcopy(m)

    def get(self, mid: str):
        with self._lock:
            m = self._monitors.get(mid)
            return copy.deepcopy(m) if m else None

    def all(self) -> list:
        with self._lock:
            return [copy.deepcopy(m) for m in self._monitors.values()]

    def remove(self, mid: str) -> bool:
        with self._lock:
            existed = self._monitors.pop(mid, None) is not None
            if existed:
                self.flush()
            return existed

    def record(self, mid: str, result: dict):
        with self._lock:
            m = self._monitors.get(mid)
            if m is None:                  # deleted while the check was running
                return
            m["history"].append(result)
            del m["history"][:-HISTORY_LIMIT]
            self.flush()


def view(m: dict) -> dict:
    """API representation with computed statistics."""
    h = m["history"]
    last = h[-1] if h else None
    ok_runs = [x for x in h if x["ok"]]
    return {
        "id": m["id"], "name": m["name"], "url": m["url"], "createdAt": m["createdAt"],
        "status": ("up" if last["ok"] else "down") if last else "pending",
        "uptime": round(len(ok_runs) / len(h) * 100, 2) if h else None,
        "avgMs": round(sum(x["ms"] for x in ok_runs) / len(ok_runs)) if ok_runs else None,
        "lastCheck": last["t"] if last else None,
        "lastStatus": last["status"] if last else None,
        "lastError": (last["error"] or f"HTTP {last['status']}") if last and not last["ok"] else None,
        "checks": len(h),
        "history": [[x["ms"], 1 if x["ok"] else 0] for x in h[-50:]],
    }
