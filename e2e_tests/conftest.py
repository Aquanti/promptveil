"""Pytest fixtures and browser/server lifecycle management for PromptVeil E2E."""

from __future__ import annotations

import functools
import http.server
import json
import mimetypes
import os
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright

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
    }

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", NETLIFY_CSP_POLICY)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        req_path = urllib.parse.urlsplit(self.path).path
        if (
            req_path == "/styles.css"
            or req_path.startswith("/js/")
            or req_path.startswith("/css/")
            or req_path.startswith("/fonts/")
        ):
            self.send_header("Cache-Control", "public, max-age=300")
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802
        req_path = urllib.parse.urlsplit(self.path).path
        if req_path == "/health":
            payload = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
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
) -> Iterator[str]:
    """Serve static_dir (default app/static/) with netlify.toml headers and NO /health route."""
    target = static_dir if static_dir is not None else STATIC_APP_DIR
    if not target.is_dir():
        raise RuntimeError(f"Static app directory does not exist: {target}")
    if not (target / "index.html").is_file():
        raise RuntimeError(f"Static app directory is missing index.html: {target}")
    mimetypes.add_type("font/woff2", ".woff2")
    handler = functools.partial(_StaticAppRequestHandler, directory=str(target))
    server = _ThreadingStaticServer((host, port), handler)
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
        choices=["auto", "chrome", "msedge"],
        help="System Chromium channel to launch (auto tries chrome then msedge)",
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
    venv_python = WORKSPACE_ROOT / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        raise RuntimeError(
            f"--start-server requested, but root venv interpreter not found at {venv_python}"
        )

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
    """Launch system Chrome with automatic Edge fallback (zero 150 MB download)."""
    channels = ["chrome", "msedge"] if preference == "auto" else [preference]
    errors: list[str] = []
    for channel in channels:
        try:
            return pw.chromium.launch(channel=channel, headless=not headed)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{channel}: {exc}")
    raise RuntimeError("Failed to launch system Chrome/Edge via Playwright: " + " | ".join(errors))


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
