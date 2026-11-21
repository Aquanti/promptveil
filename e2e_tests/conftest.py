"""Pytest fixtures and browser/server lifecycle management for PromptVeil E2E."""

from __future__ import annotations

import base64
import functools
import http.server
import importlib.util
import json
import mimetypes
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest
from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    Route,
    sync_playwright,
)

from locators import PromptVeilUI
from monitors import (
    ConsoleErrorMonitor,
    NetworkMonitor,
    fetch_http_response,
    verify_health_endpoint,
)


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
E2E_DIR = Path(__file__).resolve().parent
TEST_CASES_PATH = E2E_DIR / "test_cases.json"
STATIC_APP_DIR = WORKSPACE_ROOT / "app" / "static"

NETLIFY_CSP_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; frame-ancestors 'none'"
)


@dataclass
class TempIODirs:
    """Per-test isolated upload and download directories."""

    root: Path
    uploads: Path
    downloads: Path


@dataclass
class E2ESession:
    """Bundled per-test page, opaque-box UI adapter, and telemetry monitors."""

    page: Page
    ui: PromptVeilUI
    net: NetworkMonitor
    console: ConsoleErrorMonitor
    base_url: str
    io: TempIODirs


class _StaticAppRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Static HTTP handler simulating Netlify hosting (app/static/, no /health route)."""

    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "application/javascript; charset=utf-8",
        ".mjs": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".woff2": "font/woff2",
        ".woff": "font/woff",
        ".json": "application/json; charset=utf-8",
        ".webmanifest": "application/manifest+json; charset=utf-8",
        ".xml": "application/xml; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".zip": "application/zip",
    }

    def guess_type(self, path: str) -> str:
        clean_path = urllib.parse.urlsplit(path).path.lower()
        if clean_path.endswith(".webmanifest"):
            return "application/manifest+json; charset=utf-8"
        return super().guess_type(path)

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", NETLIFY_CSP_POLICY)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        req_path = urllib.parse.urlsplit(self.path).path
        if req_path.startswith("/dist/"):
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        elif req_path == "/sw.js":
            self.send_header("Cache-Control", "no-cache")
        elif req_path == "/manifest.webmanifest":
            self.send_header("Cache-Control", "public, max-age=300")
        elif (
            req_path == "/styles.css"
            or req_path.startswith("/js/")
            or req_path.startswith("/css/")
            or req_path.startswith("/fonts/")
            or (req_path.startswith("/downloads/") and req_path.lower().endswith(".zip"))
        ):
            self.send_header("Cache-Control", "public, max-age=300")
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        req_path = parsed.path
        if req_path == "/health":
            payload = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        sw_provider = getattr(self.server, "sw_body_provider", None)
        if req_path == "/sw.js" and callable(sw_provider):
            override = sw_provider()
            if override is not None:
                payload = override.encode("utf-8") if isinstance(override, str) else bytes(override)
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
        if req_path == "/en" and (Path(self.directory) / "en" / "index.html").is_file():
            self.path = "/en/index.html" + (f"?{parsed.query}" if parsed.query else "")
        super().do_GET()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        _ = (format, args)


class _ThreadingStaticServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 128
    allow_reuse_address = True


@contextmanager
def start_static_dir_server(
    static_dir: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    sw_body_provider: Callable[[], str | bytes | None] | None = None,
) -> Iterator[str]:
    """Serve static_dir (default app/static/) with netlify.toml headers and NO /health route."""
    target = static_dir if static_dir is not None else STATIC_APP_DIR
    if not target.is_dir():
        raise RuntimeError(f"Static app directory does not exist: {target}")
    if not (target / "index.html").is_file():
        raise RuntimeError(f"Static app directory is missing index.html: {target}")
    mimetypes.add_type("font/woff2", ".woff2")
    mimetypes.add_type("application/zip", ".zip")
    handler = functools.partial(_StaticAppRequestHandler, directory=str(target))
    server = _ThreadingStaticServer((host, port), handler)
    setattr(server, "sw_body_provider", sw_body_provider)
    bound_port = int(server.server_address[1])
    url = f"http://{host}:{bound_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, _ = fetch_http_response(f"{url}/")
        if status != 200:
            raise RuntimeError(f"Static server readiness check failed: GET {url}/ returned {status}")
        yield url
    finally:
        server.shutdown()
        server.server_close()


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register CLI flags for PromptVeil E2E runs."""
    parser.addoption(
        "--base-url",
        action="store",
        default=os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8000"),
        help="Target PromptVeil base URL (default: http://127.0.0.1:8000)",
    )
    parser.addoption(
        "--browser",
        action="store",
        default="auto",
        choices=["auto", "chrome", "msedge", "chromium"],
        help="Chromium channel or bundled chromium to launch (auto tries chrome, msedge, then chromium)",
    )
    parser.addoption(
        "--headed",
        action="store_true",
        default=False,
        help="Run browser in headed (visible window) mode",
    )
    parser.addoption(
        "--start-server",
        action="store_true",
        default=False,
        help="Spawn local FastAPI uvicorn server via root .venv for the test session",
    )
    parser.addoption(
        "--static-only",
        action="store_true",
        default=False,
        help="Serve app/static/ directly via static HTTP server (no /health route, Netlify parity)",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register tier and acceptance markers."""
    config.addinivalue_line("markers", "tier1: Tier 1 isolated feature coverage tests")
    config.addinivalue_line("markers", "tier2: Tier 2 boundary and corner-case tests")
    config.addinivalue_line("markers", "tier3: Tier 3 cross-feature combination tests")
    config.addinivalue_line("markers", "tier4: Tier 4 real-world end-to-end scenarios")
    config.addinivalue_line("markers", "tier5: Tier 5 white-box adversarial and coverage tests")
    config.addinivalue_line("markers", "acceptance: R1/R2/R3 Product Acceptance Gate tests")


@pytest.fixture(scope="session")
def test_cases_data() -> dict[str, object]:
    """Load structured synthetic test vectors from test_cases.json (UTF-8)."""
    raw = TEST_CASES_PATH.read_text(encoding="utf-8")
    data: dict[str, object] = json.loads(raw)
    return data


def _kill_process_tree(proc: subprocess.Popen[bytes]) -> None:
    """Terminate spawned uvicorn server tree cleanly on Windows."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                check=False,
                timeout=10,
            )
            return
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        proc.kill()


def _resolve_server_python() -> Path:
    """Resolve Python interpreter for --start-server across Windows and POSIX CI."""
    candidates: list[Path] = []
    if os.name == "nt":
        candidates.extend(
            [
                WORKSPACE_ROOT / ".venv" / "Scripts" / "python.exe",
                WORKSPACE_ROOT / ".venv" / "bin" / "python",
            ]
        )
    else:
        candidates.extend(
            [
                WORKSPACE_ROOT / ".venv" / "bin" / "python",
                WORKSPACE_ROOT / ".venv" / "bin" / "python3",
                WORKSPACE_ROOT / ".venv" / "Scripts" / "python.exe",
            ]
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    if importlib.util.find_spec("uvicorn") is not None:
        return Path(sys.executable)
    raise RuntimeError(
        "--start-server requested, but neither workspace .venv interpreter "
        f"(checked {', '.join(str(c) for c in candidates)}) nor uvicorn in {sys.executable} was found"
    )


@pytest.fixture(scope="session")
def base_url(request: pytest.FixtureRequest) -> Iterator[str]:
    """Return active base URL, optionally managing FastAPI uvicorn or static-only server."""
    static_only = bool(request.config.getoption("--static-only"))
    if static_only:
        with start_static_dir_server(STATIC_APP_DIR) as static_url:
            yield static_url
        return

    url = str(request.config.getoption("--base-url")).rstrip("/")
    start_server = bool(request.config.getoption("--start-server"))
    if not start_server:
        yield url
        return

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8000
    venv_python = _resolve_server_python()

    stderr_log = tempfile.NamedTemporaryFile(
        mode="w+b",
        prefix="pv_uvicorn_",
        suffix=".log",
        delete=False,
    )
    stderr_log_path = Path(stderr_log.name)

    def _read_stderr_log() -> str:
        try:
            stderr_log.flush()
            return stderr_log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return ""

    proc = subprocess.Popen(
        [
            str(venv_python),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            host,
            "--port",
            str(port),
        ],
        cwd=str(WORKSPACE_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=stderr_log,
    )
    try:
        deadline = time.monotonic() + 15.0
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr_out = _read_stderr_log()
                raise RuntimeError(f"uvicorn exited prematurely ({proc.returncode}): {stderr_out}")
            try:
                verify_health_endpoint(url)
                last_err = None
                break
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(0.25)
        if last_err is not None:
            stderr_tail = _read_stderr_log()[-2000:]
            raise RuntimeError(
                f"Timed out waiting for {url}/health: {last_err}\nServer stderr:\n{stderr_tail}"
            )
        yield url
    finally:
        try:
            _kill_process_tree(proc)
        finally:
            try:
                stderr_log.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                stderr_log_path.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass


def _launch_browser(pw: Playwright, preference: str, headed: bool) -> Browser:
    """Launch Chrome/Edge or bundled Playwright Chromium (CI fallback)."""
    if preference == "chromium":
        return pw.chromium.launch(headless=not headed)
    channels = ["chrome", "msedge"] if preference == "auto" else [preference]
    errors: list[str] = []
    for channel in channels:
        try:
            return pw.chromium.launch(channel=channel, headless=not headed)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{channel}: {exc}")
    if preference == "auto":
        try:
            return pw.chromium.launch(headless=not headed)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"chromium: {exc}")
    raise RuntimeError("Failed to launch browser via Playwright: " + " | ".join(errors))


@pytest.fixture(scope="session")
def playwright_browser(request: pytest.FixtureRequest) -> Iterator[Browser]:
    """Session-scoped Chromium browser instance."""
    pref = str(request.config.getoption("--browser"))
    headed = bool(request.config.getoption("--headed"))
    pw = sync_playwright().start()
    browser = _launch_browser(pw, pref, headed)
    try:
        yield browser
    finally:
        try:
            browser.close()
        finally:
            pw.stop()


@pytest.fixture()
def temp_io_dir() -> Iterator[TempIODirs]:
    """Per-test temporary uploads/downloads directory in %TEMP%."""
    with tempfile.TemporaryDirectory(prefix="pv_e2e_io_") as tmp:
        root = Path(tmp)
        uploads = root / "uploads"
        downloads = root / "downloads"
        uploads.mkdir(parents=True, exist_ok=True)
        downloads.mkdir(parents=True, exist_ok=True)
        yield TempIODirs(root=root, uploads=uploads, downloads=downloads)


@pytest.fixture()
def browser_context(playwright_browser: Browser) -> Iterator[BrowserContext]:
    """Fresh incognito BrowserContext per test (1440x900 desktop viewport)."""
    try:
        ctx = playwright_browser.new_context(
            accept_downloads=True,
            viewport={"width": 1440, "height": 900},
            permissions=["clipboard-read", "clipboard-write"],
        )
    except Exception:  # noqa: BLE001
        ctx = playwright_browser.new_context(
            accept_downloads=True,
            viewport={"width": 1440, "height": 900},
        )
    try:
        yield ctx
    finally:
        ctx.close()


@pytest.fixture()
def raw_session(
    browser_context: BrowserContext,
    base_url: str,
    temp_io_dir: TempIODirs,
) -> Iterator[E2ESession]:
    """Provide a fresh Page + monitors without pre-navigating (for custom URL/seed tests)."""
    page = browser_context.new_page()
    net = NetworkMonitor(page=page)
    console = ConsoleErrorMonitor(page=page)
    net.attach()
    console.attach()
    session = E2ESession(
        page=page,
        ui=PromptVeilUI(page),
        net=net,
        console=console,
        base_url=base_url,
        io=temp_io_dir,
    )
    try:
        yield session
        console.assert_no_errors()
    finally:
        console.detach()
        net.detach()
        page.close()


@pytest.fixture()
def e2e_session(raw_session: E2ESession) -> E2ESession:
    """Navigate to base_url, verify clean initial load, and switch monitor to interactive."""
    raw_session.page.goto(f"{raw_session.base_url}/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()
    return raw_session


# ---------------------------------------------------------------------------
# Ephemeral Ed25519 Pro License Test Harness (zero secrets, zero globalThis)
# ---------------------------------------------------------------------------

_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_PRO_PUBLIC_KEY_RE = re.compile(
    r"""export\s+const\s+PRO_PUBLIC_KEY_B64U\s*=\s*(['"`])([A-Za-z0-9_-]{43,59})\1"""
)

_NODE_KEYGEN_SCRIPT = (
    "const c = require('node:crypto');"
    "const { publicKey, privateKey } = c.generateKeyPairSync('ed25519');"
    "const spki = publicKey.export({ type: 'spki', format: 'der' });"
    "const raw32 = spki.subarray(spki.length - 32).toString('base64url');"
    "const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'pem' });"
    "process.stdout.write(JSON.stringify({ raw32, spkiB64u: spki.toString('base64url'), pkcs8 }));"
)

_NODE_SIGN_SCRIPT = (
    "const fs = require('node:fs');"
    "const c = require('node:crypto');"
    "const { pem, payload } = JSON.parse(fs.readFileSync(0, 'utf8'));"
    "const pk = c.createPrivateKey(pem);"
    "const p = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');"
    "const sig = c.sign(null, Buffer.from('PV1.' + p, 'utf8'), pk).toString('base64url');"
    "process.stdout.write('PV1.' + p + '.' + sig);"
)


def _resolve_node_exe() -> Path:
    """Locate Node.js binary via NODE_EXE, standard Windows install path, or PATH."""
    env_node = os.environ.get("NODE_EXE", "").strip()
    if env_node:
        candidate = Path(env_node)
        if candidate.is_file():
            return candidate
    if os.name == "nt":
        for win_candidate in (
            Path(r"C:\Program Files\nodejs\node.exe"),
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe",
        ):
            if win_candidate.is_file():
                return win_candidate
    which_node = shutil.which("node")
    if which_node:
        candidate = Path(which_node)
        if candidate.is_file():
            return candidate
    raise RuntimeError(
        "Node.js binary not found (checked NODE_EXE, C:\\Program Files\\nodejs\\node.exe, and PATH)."
    )


def _b64u_decode(data: str) -> bytes:
    """Decode unpadded base64url string to raw bytes."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64u_encode(raw: bytes) -> str:
    """Encode raw bytes to unpadded base64url string."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sign_pv1_token(
    private_key_pkcs8_pem: str,
    payload: dict[str, Any],
    *,
    node_exe: Path | None = None,
) -> str:
    """Sign an arbitrary payload dict into PV1.<payloadB64U>.<sigB64U> via node:crypto."""
    exe = node_exe if node_exe is not None else _resolve_node_exe()
    stdin_data = json.dumps({"pem": private_key_pkcs8_pem, "payload": payload})
    proc = subprocess.run(
        [str(exe), "-e", _NODE_SIGN_SCRIPT],
        input=stdin_data,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Node Ed25519 sign failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


@dataclass(frozen=True)
class EphemeralProKeys:
    """Ephemeral per-test-session Ed25519 keypair generated via node:crypto."""

    node_exe: Path
    public_key_b64u: str
    public_key_spki_b64u: str
    private_key_pkcs8_pem: str

    def sign_raw_payload(self, payload: dict[str, Any]) -> str:
        """Sign an arbitrary payload dict as a PV1.* token."""
        return sign_pv1_token(
            self.private_key_pkcs8_pem,
            payload,
            node_exe=self.node_exe,
        )

    def issue_token(
        self,
        *,
        tier: str = "pro",
        key_id: str = "PV-E2E-01",
        label: str = "PromptVeil E2E Test",
        issued_at: str = "2026-11-21T00:00:00.000Z",
        exp: str | int | None = None,
    ) -> str:
        """Issue a valid PV1.* license token signed by this ephemeral keypair."""
        payload: dict[str, Any] = {
            "v": 1,
            "tier": tier,
            "keyId": key_id,
            "label": label,
            "issuedAt": issued_at,
        }
        if exp is not None:
            payload["exp"] = exp
        return self.sign_raw_payload(payload)


def generate_ephemeral_pro_keys() -> EphemeralProKeys:
    """Generate a fresh in-memory Ed25519 keypair via Node.js node:crypto."""
    node_exe = _resolve_node_exe()
    proc = subprocess.run(
        [str(node_exe), "-e", _NODE_KEYGEN_SCRIPT],
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Node Ed25519 keygen failed ({proc.returncode}): {proc.stderr.strip()}")
    parsed = json.loads(proc.stdout)
    return EphemeralProKeys(
        node_exe=node_exe,
        public_key_b64u=str(parsed["raw32"]),
        public_key_spki_b64u=str(parsed["spkiB64u"]),
        private_key_pkcs8_pem=str(parsed["pkcs8"]),
    )


def _adapt_public_key_format(ephemeral_pub_b64u: str, target_len: int) -> str:
    """Convert between 43-char raw 32-byte key and 59-char SPKI DER base64url to match JS literal."""
    decoded = _b64u_decode(ephemeral_pub_b64u)
    if len(decoded) == 44 and decoded.startswith(_ED25519_SPKI_PREFIX):
        raw32 = decoded[len(_ED25519_SPKI_PREFIX) :]
    elif len(decoded) == 32:
        raw32 = decoded
    else:
        raise ValueError(f"Unsupported Ed25519 public key length ({len(decoded)} bytes)")

    if target_len == 43:
        return _b64u_encode(raw32)
    if target_len == 59:
        return _b64u_encode(_ED25519_SPKI_PREFIX + raw32)
    raise ValueError(f"Unsupported PRO_PUBLIC_KEY_B64U target literal length: {target_len}")


def install_pro_key_route(browser_context: BrowserContext, ephemeral_pub_b64u: str) -> bool:
    """Swap PRO_PUBLIC_KEY_B64U literal in served JS bundles on browser_context.

    NOTE: Callers creating a custom BrowserContext that performs page.reload() must set
    service_workers='block' so Service Worker CacheStorage does not serve unpatched JS.
    """
    pro_license_js = STATIC_APP_DIR / "js" / "pro-license.js"
    if not pro_license_js.is_file():
        return False
    source_text = pro_license_js.read_text(encoding="utf-8")
    match = _PRO_PUBLIC_KEY_RE.search(source_text)
    if match is None:
        return False

    prod_pub = match.group(2)
    target_pub = _adapt_public_key_format(ephemeral_pub_b64u, len(prod_pub))

    def _swap_pro_key(route: Route) -> None:
        try:
            resp = route.fetch()
        except Exception:  # noqa: BLE001
            try:
                route.continue_()
            except Exception:  # noqa: BLE001
                pass
            return
        body_bytes = resp.body()
        if resp.status == 200:
            text = body_bytes.decode("utf-8", errors="replace")
            if prod_pub in text:
                body_bytes = text.replace(prod_pub, target_pub).encode("utf-8")
        headers = {
            k: v
            for k, v in resp.headers.items()
            if k.lower() not in ("content-length", "content-encoding")
        }
        try:
            route.fulfill(status=resp.status, headers=headers, body=body_bytes)
        except Exception:  # noqa: BLE001
            pass

    browser_context.route("**/dist/*.js", _swap_pro_key)
    browser_context.route("**/js/pro-license.js", _swap_pro_key)
    return True


@dataclass(frozen=True)
class ProLicenseEnv:
    """Per-test ephemeral Ed25519 helper for custom BrowserContexts (e.g. mobile 390x844)."""

    keys: EphemeralProKeys

    def sign_token(self, payload: dict[str, Any]) -> str:
        """Sign an arbitrary payload dict into a PV1.* token."""
        return self.keys.sign_raw_payload(payload)

    def issue_token(
        self,
        *,
        tier: str = "pro",
        key_id: str = "PV-E2E-01",
        label: str = "PromptVeil E2E Test",
        issued_at: str = "2026-11-21T00:00:00.000Z",
        exp: str | int | None = None,
    ) -> str:
        """Issue a valid PV1.* license token signed by the session ephemeral keypair."""
        return self.keys.issue_token(
            tier=tier,
            key_id=key_id,
            label=label,
            issued_at=issued_at,
            exp=exp,
        )

    def install_route(self, browser_context: BrowserContext) -> bool:
        """Install public-key swap route on browser_context (use service_workers='block' for reloads)."""
        return install_pro_key_route(browser_context, self.keys.public_key_b64u)


@pytest.fixture(scope="session")
def ephemeral_pro_keys() -> EphemeralProKeys:
    """Session-scoped ephemeral Ed25519 keypair (never touches .secrets/ or repo files)."""
    return generate_ephemeral_pro_keys()


@pytest.fixture()
def pro_license_env(ephemeral_pro_keys: EphemeralProKeys) -> ProLicenseEnv:
    """Per-test ephemeral Ed25519 signer and BrowserContext route installer."""
    return ProLicenseEnv(keys=ephemeral_pro_keys)


@pytest.fixture()
def pro_browser_context(
    playwright_browser: Browser,
    ephemeral_pro_keys: EphemeralProKeys,
) -> Iterator[BrowserContext]:
    """Fresh incognito BrowserContext with service_workers='block' and ephemeral Pro public key route."""
    try:
        ctx = playwright_browser.new_context(
            accept_downloads=True,
            viewport={"width": 1440, "height": 900},
            permissions=["clipboard-read", "clipboard-write"],
            service_workers="block",
        )
    except Exception:  # noqa: BLE001
        ctx = playwright_browser.new_context(
            accept_downloads=True,
            viewport={"width": 1440, "height": 900},
            service_workers="block",
        )
    install_pro_key_route(ctx, ephemeral_pro_keys.public_key_b64u)
    try:
        yield ctx
    finally:
        ctx.close()


@pytest.fixture()
def pro_raw_session(
    pro_browser_context: BrowserContext,
    base_url: str,
    temp_io_dir: TempIODirs,
) -> Iterator[E2ESession]:
    """Provide a fresh Page + monitors with ephemeral Pro public-key route (pre-navigation)."""
    page = pro_browser_context.new_page()
    net = NetworkMonitor(page=page)
    console = ConsoleErrorMonitor(page=page)
    net.attach()
    console.attach()
    session = E2ESession(
        page=page,
        ui=PromptVeilUI(page),
        net=net,
        console=console,
        base_url=base_url,
        io=temp_io_dir,
    )
    try:
        yield session
        console.assert_no_errors()
    finally:
        console.detach()
        net.detach()
        page.close()


@pytest.fixture()
def pro_e2e_session(pro_raw_session: E2ESession) -> E2ESession:
    """Navigate to base_url with ephemeral Pro key active, verify clean load, start interactive phase."""
    pro_raw_session.page.goto(f"{pro_raw_session.base_url}/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    return pro_raw_session
