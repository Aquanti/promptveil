"""Server, CSP security header, zero-egress, and static bundle hygiene tests."""

import asyncio
from collections.abc import Mapping
from pathlib import Path
import re
import tomllib

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.config import CSP_POLICY, Settings, load_settings
from app.main import app, create_app
from app.schemas import HealthResponse

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "app" / "static"

EXPECTED_SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": CSP_POLICY,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}

FORBIDDEN_LEAK_SUBSTRINGS: tuple[str, ...] = (
    "Traceback",
    'File "',
    "starlette",
    "fastapi",
    "uvicorn",
    "StaticFiles",
    "app/main",
    "app\\main",
    "C:\\",
)


def _assert_security_headers(headers: Mapping[str, str]) -> None:
    """Assert all 5 strict security headers match expected values and CORS is absent."""
    for key, expected in EXPECTED_SECURITY_HEADERS.items():
        assert headers.get(key) == expected, f"Header {key!r} mismatch: {headers.get(key)!r}"
    assert "access-control-allow-origin" not in headers


def test_load_settings_defaults_and_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify typed defaults and strict validation errors on invalid env vars."""
    empty_env = tmp_path / ".env"
    empty_env.write_text("", encoding="utf-8")

    for var in ("APP_HOST", "APP_PORT", "LOG_LEVEL", "APP_VERSION"):
        monkeypatch.delenv(var, raising=False)

    defaults = load_settings(env_file=empty_env)
    assert defaults.app_host == "127.0.0.1"
    assert defaults.app_port == 8000
    assert defaults.log_level == "info"
    assert defaults.app_version == "1.0.0"

    monkeypatch.setenv("APP_PORT", "abc")
    with pytest.raises(ValueError, match="APP_PORT"):
        load_settings(env_file=empty_env)

    monkeypatch.setenv("APP_PORT", "0")
    with pytest.raises(ValueError, match="APP_PORT"):
        load_settings(env_file=empty_env)

    monkeypatch.setenv("APP_PORT", "65536")
    with pytest.raises(ValueError, match="APP_PORT"):
        load_settings(env_file=empty_env)

    monkeypatch.setenv("APP_PORT", "70000")
    with pytest.raises(ValueError, match="APP_PORT"):
        load_settings(env_file=empty_env)

    monkeypatch.setenv("APP_PORT", "1")
    assert load_settings(env_file=empty_env).app_port == 1

    monkeypatch.setenv("APP_PORT", "65535")
    assert load_settings(env_file=empty_env).app_port == 65535

    monkeypatch.setenv("APP_PORT", "8000")
    monkeypatch.setenv("LOG_LEVEL", "verbose")
    with pytest.raises(ValueError, match="LOG_LEVEL"):
        load_settings(env_file=empty_env)

    monkeypatch.setenv("LOG_LEVEL", " WARNING ")
    assert load_settings(env_file=empty_env).log_level == "warning"

    monkeypatch.setenv("LOG_LEVEL", "info")
    monkeypatch.setenv("APP_HOST", "   ")
    with pytest.raises(ValueError, match="APP_HOST"):
        load_settings(env_file=empty_env)

    monkeypatch.setenv("APP_HOST", "127.0.0.1")
    monkeypatch.setenv("APP_VERSION", "   ")
    with pytest.raises(ValueError, match="APP_VERSION"):
        load_settings(env_file=empty_env)


def test_load_settings_populated_env_and_override_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify populated .env loading respects process env precedence (override=False)."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "APP_HOST=0.0.0.0\nAPP_PORT=9123\nLOG_LEVEL=WARNING\nAPP_VERSION=2.1.0\n",
        encoding="utf-8",
    )
    for var in ("APP_HOST", "APP_PORT", "LOG_LEVEL", "APP_VERSION"):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("APP_PORT", "8443")
    loaded = load_settings(env_file=env_file)
    assert loaded.app_host == "0.0.0.0"
    assert loaded.app_port == 8443
    assert loaded.log_level == "warning"
    assert loaded.app_version == "2.1.0"


def test_health_response_schema_immutability_and_literals() -> None:
    """Verify HealthResponse enforces frozen immutability and Literal fields."""
    resp = HealthResponse(version="1.2.3")
    assert resp.status == "ok"
    assert resp.mode == "client-side-zero-egress"
    assert resp.version == "1.2.3"

    with pytest.raises(ValidationError):
        resp.version = "9.9.9"  # type: ignore[misc]

    with pytest.raises(ValidationError):
        HealthResponse(status="fail", version="1.0.0")  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        HealthResponse(mode="server-side", version="1.0.0")  # type: ignore[arg-type]


def test_create_app_with_custom_settings() -> None:
    """Verify create_app honors injected custom Settings."""
    custom = Settings(
        app_host="127.0.0.1",
        app_port=9090,
        log_level="warning",
        app_version="9.9.9-custom",
        static_dir=STATIC_DIR,
        csp_policy=CSP_POLICY,
    )
    custom_app = create_app(custom)
    client = TestClient(custom_app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["version"] == "9.9.9-custom"
    assert custom_app.version == "9.9.9-custom"


def test_health_endpoint_and_security_headers() -> None:
    """Verify GET/HEAD /health returns client-side zero-egress status and strict security headers."""
    client = TestClient(app)
    for method in ("GET", "HEAD"):
        response = client.request(method, "/health")
        assert response.status_code == 200
        if method == "GET":
            payload = response.json()
            assert payload == {
                "status": "ok",
                "mode": "client-side-zero-egress",
                "version": app.state.settings.app_version,
            }
        else:
            assert response.content == b""
        _assert_security_headers(response.headers)


def test_disallowed_methods_docs_directory_and_traversal_hardening() -> None:
    """Verify 405 on mutating methods, 404 on disabled docs/dir listing/traversal, and headers on all."""
    client = TestClient(app)

    for path in ("/", "/health"):
        for method in ("POST", "PUT", "DELETE"):
            resp = client.request(method, path)
            assert resp.status_code == 405, f"{method} {path} returned {resp.status_code}"
            assert resp.headers["content-security-policy"] == CSP_POLICY
            assert resp.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"

    for hidden_path in (
        "/docs",
        "/redoc",
        "/openapi.json",
        "/js/",
        "/.env",
        "/../.env",
        "/%2e%2e/app/config.py",
        "/%2e%2e/.env",
    ):
        resp = client.get(hidden_path)
        assert resp.status_code == 404, f"Expected 404 for {hidden_path}, got {resp.status_code}"
        _assert_security_headers(resp.headers)


def test_root_serves_index_html_with_relative_assets_and_csp() -> None:
    """Verify GET / serves index.html with bundled /dist/ asset links and CSP/COOP/CORP headers."""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    _assert_security_headers(response.headers)
    body = response.text
    assert 'href="/favicon.svg"' in body
    assert 'href="/apple-touch-icon.png"' in body
    assert 'href="/manifest.webmanifest"' in body
    assert './favicon.svg"' not in body
    assert './styles.css"' not in body
    assert './js/app.js"' not in body
    css_match = re.search(r'<link\s+rel="stylesheet"\s+href="(/dist/styles\.[A-Za-z0-9_-]+\.css)"', body)
    js_match = re.search(r'<script\s+type="module"\s+src="(/dist/app\.[A-Za-z0-9_-]+\.js)"', body)
    ru_preload_match = re.search(
        r'<link\s+rel="modulepreload"\s+href="(/dist/i18n-ru-[A-Za-z0-9_-]+\.js)"',
        body,
    )
    assert css_match is not None, "Expected root-relative /dist/styles.<hash>.css in index.html"
    assert js_match is not None, "Expected root-relative /dist/app.<hash>.js in index.html"
    assert ru_preload_match is not None, "Expected index.html to modulepreload /dist/i18n-ru-*.js"
    assert "i18n-en-" not in body, "index.html must not preload English dictionary"
    assert client.get(css_match.group(1)).status_code == 200
    assert client.get(js_match.group(1)).status_code == 200
    assert client.get(ru_preload_match.group(1)).status_code == 200


def test_en_route_serves_english_index_with_root_assets_and_headers() -> None:
    """Verify GET/HEAD /en/ serves en/index.html with matching /dist/ assets, hreflang, and security headers."""
    client = TestClient(app)
    root_body = client.get("/").text
    root_css = re.search(r'href="(/dist/styles\.[A-Za-z0-9_-]+\.css)"', root_body)
    root_js = re.search(r'src="(/dist/app\.[A-Za-z0-9_-]+\.js)"', root_body)
    assert root_css is not None and root_js is not None

    for method in ("GET", "HEAD"):
        response = client.request(method, "/en/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        _assert_security_headers(response.headers)
        if method == "HEAD":
            assert response.content == b""
        else:
            body = response.text
            assert '<html lang="en">' in body
            assert 'href="/favicon.svg"' in body
            assert 'href="/styles.css"' not in body
            assert 'src="/js/app.js"' not in body
            assert f'href="{root_css.group(1)}"' in body
            assert f'src="{root_js.group(1)}"' in body
            assert re.search(
                r'<link\s+rel="modulepreload"\s+href="(/dist/i18n-en-[A-Za-z0-9_-]+\.js)"',
                body,
            ) is not None, "Expected en/index.html to modulepreload /dist/i18n-en-*.js"
            assert "i18n-ru-" not in body, "en/index.html must not preload Russian dictionary"
            assert 'href="/manifest.webmanifest"' in body
            assert 'rel="canonical" href="https://promptveil.netlify.app/en/"' in body
            assert 'hreflang="ru" href="https://promptveil.netlify.app/"' in body
            assert 'hreflang="en" href="https://promptveil.netlify.app/en/"' in body
            assert 'hreflang="x-default" href="https://promptveil.netlify.app/"' in body


def test_static_assets_served_from_root() -> None:
    """Verify CSS, SVG favicon, ES6 modules, and any static assets resolve with expected MIME & headers."""
    client = TestClient(app)

    css_resp = client.get("/styles.css")
    assert css_resp.status_code == 200
    assert "text/css" in css_resp.headers["content-type"]

    fav_resp = client.get("/favicon.svg")
    assert fav_resp.status_code == 200
    assert "image/svg+xml" in fav_resp.headers["content-type"]

    for js_file in ("detector.js", "vault.js", "storage.js", "presets.js", "app.js"):
        js_resp = client.get(f"/js/{js_file}")
        assert js_resp.status_code == 200, f"Failed serving /js/{js_file}"
        assert "javascript" in js_resp.headers["content-type"]

    expected_mime = {
        ".js": "javascript",
        ".css": "text/css",
        ".svg": "image/svg+xml",
        ".woff2": "font/woff2",
    }
    seen_counts = {suffix: 0 for suffix in expected_mime}
    for asset_path in sorted(STATIC_DIR.rglob("*")):
        if not asset_path.is_file() or asset_path.suffix.lower() not in expected_mime:
            continue
        suffix = asset_path.suffix.lower()
        rel_url = "/" + asset_path.relative_to(STATIC_DIR).as_posix()
        resp = client.get(rel_url)
        assert resp.status_code == 200, f"Failed serving {rel_url}"
        assert expected_mime[suffix] in resp.headers["content-type"], (
            f"Unexpected MIME type for {rel_url}: {resp.headers['content-type']}"
        )
        assert resp.headers["content-security-policy"] == CSP_POLICY
        assert resp.headers["x-content-type-options"] == "nosniff"
        seen_counts[suffix] += 1

    assert seen_counts[".js"] >= 5
    assert seen_counts[".css"] >= 1
    assert seen_counts[".svg"] >= 1

    dist_css = sorted((STATIC_DIR / "dist").glob("*.css"))
    dist_js = sorted((STATIC_DIR / "dist").glob("*.js"))
    assert len(dist_css) == 1, f"Expected single bundled dist CSS, found {dist_css}"
    assert len(dist_js) >= 4, f"Expected entry + i18n + lazy pro-documents dist JS chunks, found {dist_js}"
    assert len(list((STATIC_DIR / "dist").glob("pro-documents-*.js"))) == 1
    assert "@import" not in dist_css[0].read_text(encoding="utf-8")


def test_static_css_subdir_and_woff2_mime_headers(tmp_path: Path) -> None:
    """Verify nested css/*.css and fonts/*.woff2 assets are served with exact MIME types and all 5 security headers."""
    (tmp_path / "css").mkdir()
    (tmp_path / "fonts").mkdir()
    (tmp_path / "css" / "tokens.css").write_text(":root { --pv-bg: #fff; }\n", encoding="utf-8")
    (tmp_path / "fonts" / "test.woff2").write_bytes(b"wOF2\x00\x01\x00\x00")

    custom_app = create_app(
        Settings(
            app_host="127.0.0.1",
            app_port=8000,
            log_level="info",
            app_version="1.0.0",
            static_dir=tmp_path,
            csp_policy=CSP_POLICY,
        )
    )
    client = TestClient(custom_app)

    for path, mime_substring in (
        ("/css/tokens.css", "text/css"),
        ("/fonts/test.woff2", "font/woff2"),
    ):
        resp = client.get(path)
        assert resp.status_code == 200
        assert mime_substring in resp.headers["content-type"]
        _assert_security_headers(resp.headers)


def test_zero_egress_no_sanitize_or_rehydrate_endpoints() -> None:
    """Ensure zero server-side /api/sanitize or /api/rehydrate routes exist."""
    route_paths = [getattr(route, "path", "") for route in app.routes]
    assert "/api/sanitize" not in route_paths
    assert "/api/rehydrate" not in route_paths

    client = TestClient(app)
    for endpoint in ("/api/sanitize", "/api/rehydrate"):
        get_resp = client.get(endpoint)
        assert get_resp.status_code == 404
        post_resp = client.post(endpoint, json={"text": "secret@example.com"})
        assert post_resp.status_code in (404, 405)


def test_csp_strict_no_external_urls_or_inline_code() -> None:
    """Verify static HTML/CSS/JS comply with strict CSP and zero-network guarantees."""
    allowlisted_external_links = {
        "https://t.me/supv1rus",
        "https://github.com/Aquanti",
        "https://github.com/Aquanti/promptveil",
        "https://chatgpt.com/",
        "https://chat.deepseek.com/",
        "https://giga.chat/",
        "https://alice.yandex.ru/",
        "https://claude.ai/",
        "https://gemini.google.com/app",
    }
    for html_path in (STATIC_DIR / "index.html", STATIC_DIR / "en" / "index.html", STATIC_DIR / "404.html"):
        html_src = html_path.read_text(encoding="utf-8")
        rel_html = html_path.relative_to(STATIC_DIR).as_posix()

        for link_match in re.finditer(r"<a\b([^>]*)>", html_src, re.IGNORECASE | re.DOTALL):
            attrs = link_match.group(1)
            href_match = re.search(r"""href\s*=\s*['"]([^'"]+)['"]""", attrs, re.IGNORECASE)
            if not href_match:
                continue
            href = href_match.group(1)
            if re.match(r"^(?:https?|wss?)://", href, re.IGNORECASE):
                assert href in allowlisted_external_links, f"Disallowed external <a href> in {rel_html}: {href!r}"
                assert re.search(r"""target\s*=\s*['"]_blank['"]""", attrs, re.IGNORECASE), (
                    f"External link {href!r} in {rel_html} must open in new tab target='_blank'"
                )
                rel_match = re.search(r"""rel\s*=\s*['"]([^'"]+)['"]""", attrs, re.IGNORECASE)
                rel_tokens = set((rel_match.group(1) if rel_match else "").lower().split())
                assert {"noopener", "noreferrer"}.issubset(rel_tokens), (
                    f"External link {href!r} in {rel_html} must include rel='noopener noreferrer'"
                )

        html_cleaned = re.sub(
            r"""xmlns\s*=\s*['"]http://www\.w3\.org/2000/svg['"]""",
            "",
            html_src,
            flags=re.IGNORECASE,
        )
        html_cleaned = re.sub(
            r"""<(?:link|meta)\b[^>]*(?:rel\s*=\s*['"](?:canonical|alternate)['"]|property\s*=\s*['"]og:(?:url|image)['"]|name\s*=\s*['"]twitter:image['"])[^>]*https://promptveil\.netlify\.app/(?:en/|og-image\.png)?['"][^>]*>""",
            "",
            html_cleaned,
            flags=re.IGNORECASE | re.DOTALL,
        )
        for allowed_href in allowlisted_external_links:
            html_cleaned = html_cleaned.replace(f'href="{allowed_href}"', 'href=""')
        assert not re.search(r"(?:https?|wss?)://", html_cleaned, re.IGNORECASE), (
            f"External http(s)/ws(s) URL found in app/static/{rel_html}"
        )
        # Every <script> tag must have src= and empty inline body.
        for script_match in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html_src, re.IGNORECASE | re.DOTALL):
            attrs, body = script_match.groups()
            assert re.search(r"\bsrc\s*=", attrs, re.IGNORECASE), (
                f"Inline <script> without src is forbidden by CSP in {rel_html}"
            )
            assert body.strip() == "", f"Non-empty <script> body is forbidden by CSP in {rel_html}"
        # No <style> tags, inline style attributes, or inline event handlers.
        assert not re.search(r"<style\b", html_src, re.IGNORECASE), f"<style> found in {rel_html}"
        assert not re.search(r"\bstyle\s*=", html_src, re.IGNORECASE), f"style= found in {rel_html}"
        assert not re.search(r"\bon[a-z]+\s*=", html_src, re.IGNORECASE), f"on*= found in {rel_html}"

    favicon_without_svg_ns = re.sub(
        r"""xmlns\s*=\s*['"]http://www\.w3\.org/2000/svg['"]""",
        "",
        (STATIC_DIR / "favicon.svg").read_text(encoding="utf-8"),
        flags=re.IGNORECASE,
    )
    assert not re.search(r"(?:https?|wss?)://", favicon_without_svg_ns, re.IGNORECASE), (
        "External http(s)/ws(s) URL found in app/static/favicon.svg"
    )

    # No external http(s)/ws(s) or protocol-relative URLs in any CSS file.
    all_css = sorted(STATIC_DIR.rglob("*.css"))
    assert all_css, "Expected at least one CSS file in app/static"
    for css_path in all_css:
        css_text = css_path.read_text(encoding="utf-8")
        assert not re.search(r"(?:https?|wss?)://", css_text, re.IGNORECASE), (
            f"External URL found in {css_path.relative_to(STATIC_DIR)}"
        )
        assert not re.search(r"(?:url\(\s*['\"]?|@import\s+['\"])//", css_text, re.IGNORECASE), (
            f"Protocol-relative URL found in {css_path.relative_to(STATIC_DIR)}"
        )

    # Client JS (both source modules and bundled dist chunks) must remain 100% XSS-safe and zero-egress.
    all_js = sorted((STATIC_DIR / "js").rglob("*.js")) + sorted((STATIC_DIR / "dist").rglob("*.js"))
    assert all_js, "Expected at least one JS module in app/static/js"
    for js_path in all_js:
        source = js_path.read_text(encoding="utf-8")
        rel_js = js_path.relative_to(STATIC_DIR).as_posix()
        assert not re.search(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b", source), (
            f"Forbidden unsafe HTML sink in {rel_js}"
        )
        assert not re.search(r"\beval\s*\(", source), f"Forbidden eval() in {rel_js}"
        assert not re.search(r"\bnew\s+Function\s*\(", source), f"Forbidden new Function() in {rel_js}"
        assert not re.search(r"\bfetch\s*\(", source), f"Forbidden fetch() in {rel_js}"
        assert "XMLHttpRequest" not in source, f"Forbidden XMLHttpRequest in {rel_js}"
        assert "sendBeacon" not in source, f"Forbidden sendBeacon in {rel_js}"
        assert not re.search(r"\bnew\s+WebSocket\s*\(", source), f"Forbidden WebSocket in {rel_js}"
        assert not re.search(r"\bEventSource\b", source), f"Forbidden EventSource in {rel_js}"
        assert not re.search(r"""(['"`])(?:https?|wss?)://""", source, re.IGNORECASE), (
            f"Forbidden external URL string literal in {rel_js}"
        )


def test_netlify_toml_matches_publish_dir_and_csp() -> None:
    """Verify netlify.toml publishes app/static with matching CSP, COOP, CORP, and immutable /dist/* headers."""
    netlify_path = BASE_DIR / "netlify.toml"
    data = tomllib.loads(netlify_path.read_text(encoding="utf-8"))
    assert data["build"]["command"] == "npm run build"
    assert data["build"]["publish"] == "app/static"

    root_headers = next((h for h in data["headers"] if h.get("for") == "/*"), None)
    assert root_headers is not None
    values = root_headers["values"]
    assert values["Content-Security-Policy"] == CSP_POLICY
    assert values["X-Content-Type-Options"] == "nosniff"
    assert values["X-Frame-Options"] == "DENY"
    assert values["Referrer-Policy"] == "no-referrer"
    assert values["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert values["Cross-Origin-Opener-Policy"] == "same-origin"
    assert values["Cross-Origin-Resource-Policy"] == "same-origin"

    dist_headers = next((h for h in data["headers"] if h.get("for") == "/dist/*"), None)
    assert dist_headers is not None, "Missing [[headers]] block for /dist/* in netlify.toml"
    assert dist_headers["values"]["Cache-Control"] == "public, max-age=31536000, immutable"

    for cached_path in ("/js/*", "/styles.css", "/css/*", "/fonts/*"):
        cache_headers = next((h for h in data["headers"] if h.get("for") == cached_path), None)
        assert cache_headers is not None, f"Missing [[headers]] block for {cached_path} in netlify.toml"
        assert cache_headers["values"]["Cache-Control"] == "public, max-age=300"


def test_path_traversal_probes_client_and_raw_asgi() -> None:
    """Verify encoded TestClient traversal probes and raw unnormalized ASGI path probes all return 404 + security headers."""
    client = TestClient(app)
    client_probes = (
        "/../app/main.py",
        "/..%2fapp/main.py",
        "/%2e%2e%2fapp%2fmain.py",
        "/js/../../app/main.py",
        "/js/%2e%2e/%2e%2e/app/main.py",
        "/%252e%252e%252fapp%252fmain.py",
        "/..\\app\\main.py",
        "/%2e%2e%5capp%5cmain.py",
        "/css/",
        "/js/",
    )
    def _assert_clean_404_body(body_text: str, probe: str) -> None:
        is_json_404 = body_text.strip() in ('{"detail":"Not Found"}', '{"detail": "Not Found"}')
        is_branded_404 = "Страница не найдена" in body_text and "PromptVeil" in body_text
        assert is_json_404 or is_branded_404, (
            f"Unexpected 404 body for {probe!r}: {body_text[:120]!r}"
        )
        for marker in FORBIDDEN_LEAK_SUBSTRINGS:
            assert marker not in body_text, f"Leak marker {marker!r} in 404 body for {probe!r}"

    for probe in client_probes:
        resp = client.get(probe)
        assert resp.status_code == 404, f"Expected 404 for {probe!r}, got {resp.status_code}"
        _assert_clean_404_body(resp.text, probe)
        _assert_security_headers(resp.headers)

    async def _raw_asgi_get(raw_path: str) -> tuple[int, dict[str, str], bytes]:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": raw_path,
            "raw_path": raw_path.encode("latin-1"),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"127.0.0.1:8000")],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8000),
        }
        sent = False
        done_event = asyncio.Event()
        status_code = 0
        raw_headers: list[tuple[bytes, bytes]] = []
        body_chunks: list[bytes] = []

        async def _receive() -> dict[str, object]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await done_event.wait()
            return {"type": "http.disconnect"}

        async def _send(message: dict[str, object]) -> None:
            nonlocal status_code, raw_headers
            if message["type"] == "http.response.start":
                status_code = int(message["status"])  # type: ignore[arg-type]
                raw_headers = list(message.get("headers", []))  # type: ignore[arg-type]
            elif message["type"] == "http.response.body":
                body_chunks.append(bytes(message.get("body", b"")))  # type: ignore[arg-type]
                if not message.get("more_body", False):
                    done_event.set()

        await app(scope, _receive, _send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in raw_headers}
        return status_code, headers, b"".join(body_chunks)

    raw_probes = (
        "/../app/main.py",
        "/js/../../app/main.py",
        "/..\\app\\main.py",
        "/../../.env",
        "/\x00",
    )
    for raw_probe in raw_probes:
        status, asgi_headers, body = asyncio.run(_raw_asgi_get(raw_probe))
        assert status == 404, f"Raw ASGI probe {raw_probe!r} returned {status}"
        body_text = body.decode("utf-8", errors="replace")
        is_json_404 = body_text.strip() in ('{"detail":"Not Found"}', '{"detail": "Not Found"}')
        is_branded_404 = "Страница не найдена" in body_text and "PromptVeil" in body_text
        assert is_json_404 or is_branded_404, f"Unexpected raw ASGI 404 body for {raw_probe!r}: {body!r}"
        for marker in FORBIDDEN_LEAK_SUBSTRINGS:
            assert marker not in body_text, f"Leak marker {marker!r} in raw ASGI 404 for {raw_probe!r}"
        _assert_security_headers(asgi_headers)


def test_disallowed_http_methods_and_options_head_matrix() -> None:
    """Verify POST/PUT/DELETE/PATCH/OPTIONS/TRACE return 405 with Allow: GET, HEAD and HEAD returns 200 empty body."""
    client = TestClient(app)

    for path in ("/", "/health", "/styles.css", "/js/app.js", "/favicon.svg", "/nonexistent"):
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"):
            resp = client.request(method, path)
            assert resp.status_code == 405, f"{method} {path} returned {resp.status_code}"
            assert resp.json() == {"detail": "Method Not Allowed"}
            assert resp.headers.get("allow") == "GET, HEAD", f"{method} {path} Allow={resp.headers.get('allow')!r}"
            _assert_security_headers(resp.headers)

    head_expectations = (
        ("/", "text/html"),
        ("/health", "application/json"),
        ("/styles.css", "text/css"),
        ("/css/tokens.css", "text/css"),
        ("/js/app.js", "text/javascript"),
        ("/favicon.svg", "image/svg+xml"),
    )
    for path, expected_mime_prefix in head_expectations:
        resp = client.head(path)
        assert resp.status_code == 200, f"HEAD {path} returned {resp.status_code}"
        assert resp.content == b"", f"HEAD {path} returned non-empty body"
        assert resp.headers["content-type"].startswith(expected_mime_prefix), (
            f"HEAD {path} unexpected content-type {resp.headers['content-type']!r}"
        )
        _assert_security_headers(resp.headers)


def test_all_routes_security_headers_and_strict_mime_types() -> None:
    """Verify all 5 security headers on /, /health, and every static asset with strict MIME prefixes and counts."""
    client = TestClient(app)

    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert root_resp.headers["content-type"].startswith("text/html")
    _assert_security_headers(root_resp.headers)

    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.headers["content-type"].startswith("application/json")
    _assert_security_headers(health_resp.headers)

    seen_counts = {".js": 0, ".css": 0, ".svg": 0}
    for asset_path in sorted(STATIC_DIR.rglob("*")):
        if not asset_path.is_file():
            continue
        suffix = asset_path.suffix.lower()
        if suffix not in seen_counts:
            continue
        rel_url = "/" + asset_path.relative_to(STATIC_DIR).as_posix()
        resp = client.get(rel_url)
        assert resp.status_code == 200, f"Failed serving {rel_url}"
        _assert_security_headers(resp.headers)
        content_type = resp.headers["content-type"]
        if suffix == ".js":
            assert content_type.startswith("text/javascript"), f"{rel_url}: {content_type!r}"
        elif suffix == ".css":
            assert content_type.startswith("text/css"), f"{rel_url}: {content_type!r}"
        elif suffix == ".svg":
            assert content_type == "image/svg+xml", f"{rel_url}: {content_type!r}"
        seen_counts[suffix] += 1

    assert seen_counts[".js"] >= 9, f"Expected >= 9 .js files, saw {seen_counts['.js']}"
    assert seen_counts[".css"] >= 5, f"Expected >= 5 .css files, saw {seen_counts['.css']}"
    assert seen_counts[".svg"] >= 1, f"Expected >= 1 .svg files, saw {seen_counts['.svg']}"


def test_unknown_routes_404_no_stack_trace_leakage() -> None:
    """Verify unknown routes return clean 404 JSON with all 5 security headers and zero stack/path leaks."""
    client = TestClient(app)
    unknown_routes = (
        "/nonexistent-route-probe",
        "/static/index.html",
        "/static/js/app.js",
        "/api/v1/secret",
        "/favicon.ico",
        "/admin/debug",
    )
    for route in unknown_routes:
        resp = client.get(route)
        assert resp.status_code == 404, f"Expected 404 for {route!r}, got {resp.status_code}"
        is_json_404 = resp.text.strip() in ('{"detail":"Not Found"}', '{"detail": "Not Found"}')
        is_branded_404 = "Страница не найдена" in resp.text and "PromptVeil" in resp.text
        assert is_json_404 or is_branded_404, f"Unexpected 404 page for {route!r}: {resp.text[:120]!r}"
        _assert_security_headers(resp.headers)
        for marker in FORBIDDEN_LEAK_SUBSTRINGS:
            assert marker not in resp.text, f"Leak marker {marker!r} found in 404 response for {route!r}"


def test_cache_control_and_netlify_parity() -> None:
    """Verify netlify.toml cache rules and FastAPI non-public Cache-Control behavior (Option A)."""
    netlify_path = BASE_DIR / "netlify.toml"
    data = tomllib.loads(netlify_path.read_text(encoding="utf-8"))
    header_blocks = data["headers"]
    assert {block["for"] for block in header_blocks} == {
        "/*",
        "/dist/*",
        "/js/*",
        "/styles.css",
        "/css/*",
        "/fonts/*",
        "/sw.js",
        "/manifest.webmanifest",
        "/downloads/*.zip",
    }

    dist_block = next(block for block in header_blocks if block["for"] == "/dist/*")
    assert dist_block["values"]["Cache-Control"] == "public, max-age=31536000, immutable"

    sw_block = next(block for block in header_blocks if block["for"] == "/sw.js")
    assert sw_block["values"]["Cache-Control"] == "no-cache"

    manifest_block = next(block for block in header_blocks if block["for"] == "/manifest.webmanifest")
    assert manifest_block["values"]["Content-Type"] == "application/manifest+json; charset=utf-8"
    assert manifest_block["values"]["Cache-Control"] == "public, max-age=300"

    downloads_block = next(block for block in header_blocks if block["for"] == "/downloads/*.zip")
    assert downloads_block["values"]["Content-Type"] == "application/zip"
    assert downloads_block["values"]["Cache-Control"] == "public, max-age=300"

    root_block = next(block for block in header_blocks if block["for"] == "/*")
    assert "Cache-Control" not in root_block["values"]
    assert "Access-Control-Allow-Origin" not in root_block["values"]

    for cached_target in ("/js/*", "/styles.css", "/css/*", "/fonts/*"):
        block = next(block for block in header_blocks if block["for"] == cached_target)
        assert block["values"]["Cache-Control"] == "public, max-age=300"

    client = TestClient(app)
    for route in ("/", "/health", "/nonexistent"):
        resp = client.get(route)
        cache_control = resp.headers.get("cache-control")
        assert "public" not in (cache_control or "").lower()
        assert cache_control is None


def test_r1_geometric_brand_emblem_without_shield_or_check() -> None:
    """Verify favicon.svg and header/footer brand SVGs use geometric prism/veil polygons with zero shields/checks."""
    favicon_svg = (STATIC_DIR / "favicon.svg").read_text(encoding="utf-8")
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    old_shield_path = "M16 5L25 9v7"
    old_check_path = "M12 16l3 3 5-6"
    assert old_shield_path not in favicon_svg
    assert old_check_path not in favicon_svg
    assert old_shield_path not in index_html
    assert old_check_path not in index_html

    assert "<polygon" in favicon_svg
    for color in ("#051C12", "#072F1F", "#B4F105", "#FFFFFF"):
        assert color in favicon_svg, f"Missing Spark Admin color {color} in favicon.svg"
        assert color in index_html, f"Missing Spark Admin color {color} in index.html"

    assert 'class="brand-emblem"' in index_html
    assert 'class="footer-brand-emblem"' in index_html
    assert "footer-spark-icon" not in index_html


def test_r2_obsolete_local_browser_nagging_removed() -> None:
    """Verify obsolete repetitive local-browser/server-warning copy is removed from HTML and i18n."""
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    i18n_sources = "\n".join(
        (STATIC_DIR / "js" / name).read_text(encoding="utf-8")
        for name in ("i18n.js", "i18n-ru.js", "i18n-en.js")
    )

    obsolete_phrases = (
        "Только в браузере",
        "Все проверки выполняются локально в вашем браузере",
        "ничего не отправляется на сервер",
        "Browser-local only",
        "All checks run locally in your browser",
        "nothing leaves your browser",
    )
    for phrase in obsolete_phrases:
        assert phrase not in index_html, f"Obsolete phrase {phrase!r} still in index.html"
        assert phrase not in i18n_sources, f"Obsolete phrase {phrase!r} still in i18n modules"


def test_r2_r3_r4_r5_contracts_and_centralized_contacts() -> None:
    """Verify Zero-Retention Proof, UX paste/combo controls, honest waitlist pricing, trust footer, and Stage D contracts."""
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    en_html = (STATIC_DIR / "en" / "index.html").read_text(encoding="utf-8")
    not_found_html = (STATIC_DIR / "404.html").read_text(encoding="utf-8")
    i18n_js = (STATIC_DIR / "js" / "i18n.js").read_text(encoding="utf-8")
    i18n_ru_js = (STATIC_DIR / "js" / "i18n-ru.js").read_text(encoding="utf-8")
    i18n_en_js = (STATIC_DIR / "js" / "i18n-en.js").read_text(encoding="utf-8")
    i18n_all = f"{i18n_js}\n{i18n_ru_js}\n{i18n_en_js}"
    contacts_js = (STATIC_DIR / "js" / "contacts.js").read_text(encoding="utf-8")
    proof_js = (STATIC_DIR / "js" / "privacy-proof.js").read_text(encoding="utf-8")
    pricing_js = (STATIC_DIR / "js" / "pricing.js").read_text(encoding="utf-8")
    app_js = (STATIC_DIR / "js" / "app.js").read_text(encoding="utf-8")

    for hook in (
        'id="open-proof-btn"',
        'id="footer-open-proof-btn"',
        'id="modal-privacy-proof"',
        'id="run-proof-check-btn"',
        'id="reset-session-btn"',
        'id="quick-reset-session-btn"',
        'id="paste-raw-btn"',
        'id="paste-rehydrate-btn"',
        'id="copy-goto-step2-btn"',
        'id="goto-rehydrate-btn"',
        'data-testid="preset-btn-ru_requisites"',
        'id="pricing-section"',
        'id="open-pro-modal-btn"',
        'id="open-team-modal-btn"',
        'id="modal-plan-request"',
        'id="modal-privacy-policy"',
        'id="open-terms-btn"',
        'id="modal-terms"',
        'id="footer-repo-link"',
        'id="proof-repo-link"',
        'id="detect-uuid-toggle"',
        'id="audit-persist-toggle"',
        'id="toggle-reveal-btn"',
        'id="add-rule-form"',
        'id="theme-toggle-btn"',
        'id="sw-update-banner"',
        'id="sw-update-btn"',
        'id="tpl-modal-privacy-proof"',
        'id="tpl-modal-plan-request"',
        'id="tpl-modal-privacy-policy"',
        'id="tpl-modal-terms"',
        'id="tpl-modal-pro-license"',
        'id="tpl-modal-pro-downloads"',
        'id="open-pro-license-btn"',
        'data-testid="open-pro-license-btn"',
        'id="open-pro-downloads-btn"',
        'data-testid="open-pro-downloads-btn"',
        'id="pro-license-downloads-btn"',
        'data-testid="pro-license-downloads-btn"',
        'id="modal-pro-downloads"',
        'data-testid="modal-pro-downloads"',
        'id="download-extension-zip-btn"',
        'data-testid="download-extension-zip-btn"',
        'href="/downloads/promptveil-pro-extension.zip"',
        'id="pricing-activate-pro-btn"',
        'id="modal-pro-license"',
        'id="pro-license-status-card"',
        'id="pro-license-key-input"',
        'id="pro-license-activate-btn"',
        'id="pro-license-remove-btn"',
        'id="file-pro-upgrade-banner"',
        'data-testid="file-pro-upgrade-banner"',
        'id="file-pro-upgrade-btn"',
        'data-testid="file-pro-upgrade-btn"',
        'id="batch-queue-panel"',
        'data-testid="batch-queue-panel"',
        'id="batch-queue-list"',
        'data-testid="batch-queue-list"',
        'id="batch-clear-btn"',
        'data-testid="batch-clear-btn"',
        'id="batch-download-txt-btn"',
        'data-testid="batch-download-txt-btn"',
        'id="batch-download-zip-btn"',
        'data-testid="batch-download-zip-btn"',
        'id="batch-rehydrate-btn"',
        'data-testid="batch-rehydrate-btn"',
        'accept=".txt,.md,.csv,.json,.log,.env,.docx,.pdf,.xlsx"',
    ):
        assert hook in index_html, f"Missing required hook {hook} in index.html"
        assert hook in en_html, f"Missing required hook {hook} in en/index.html"

    assert index_html.count("<template ") >= 6
    assert en_html.count("<template ") >= 6
    assert re.search(r'href="/dist/styles\.[A-Za-z0-9_-]+\.css"', not_found_html)

    pro_license_js = (STATIC_DIR / "js" / "pro-license.js").read_text(encoding="utf-8")
    assert "promptveil_pro_license_v1" in pro_license_js
    assert "PRO_LICENSE_STORAGE_KEY" in proof_js
    assert "__PV_TEST_" not in pro_license_js
    assert "Получить ключ (Telegram / Почта)" in index_html
    assert "Уже есть ключ • Активировать" in index_html
    assert "Get Key (Telegram / Email)" in en_html
    assert "Have a key? • Activate" in en_html

    # Unimplemented billing claims and Stage D removed dead code must not remain.
    for forbidden_claim in ("30 дней бесплатно", "30 days free", "490 ₽", "390 ₽", "1 990 ₽", "1 590 ₽", "billing-month-btn"):
        assert forbidden_claim not in index_html, f"Unexpected unimplemented pricing claim {forbidden_claim!r} in index.html"
        assert forbidden_claim not in en_html, f"Unexpected unimplemented pricing claim {forbidden_claim!r} in en/index.html"
        assert forbidden_claim not in i18n_all, f"Unexpected unimplemented pricing claim {forbidden_claim!r} in i18n"

    for dead_symbol in ("billingCycle", "renderPricingSection"):
        assert dead_symbol not in pricing_js, f"Dead code {dead_symbol!r} still in pricing.js"
        assert dead_symbol not in app_js, f"Dead code {dead_symbol!r} still in app.js"

    assert (STATIC_DIR / "js" / "notifications.js").is_file()
    assert (STATIC_DIR / "js" / "pipeline.js").is_file()
    assert (STATIC_DIR / "js" / "pro-documents.js").is_file()
    assert "./notifications.js" in app_js and "./pipeline.js" in app_js
    assert len(app_js.splitlines()) < 750
    assert "Очистить все (батч)" in index_html
    assert "Clear all (batch)" in en_html

    assert "0 логов ваших текстов" in index_html
    assert "0 Text Logs" in en_html
    assert "0 логов ваших текстов" in i18n_ru_js
    assert "0 Text Logs" in i18n_en_js

    free_card_match = re.search(
        r'data-testid="pricing-card-free".*?</article>',
        en_html,
        re.DOTALL,
    )
    assert free_card_match is not None
    en_free_card = free_card_match.group(0)
    assert "$0" in en_free_card
    for ru_only_term in ("INN", "SNILS", "ИНН", "СНИЛС"):
        assert ru_only_term not in en_free_card, f"EN Free card must not mention {ru_only_term!r}"

    for contact_literal in ("@supv1rus", "kilkauciha@gmail.com", "github.com/Aquanti", "SupV1rus"):
        assert contact_literal in contacts_js, f"Missing owner contact {contact_literal!r} in contacts.js"
        assert contact_literal in index_html, f"Missing fallback owner contact {contact_literal!r} in index.html"
        assert contact_literal in en_html, f"Missing fallback owner contact {contact_literal!r} in en/index.html"

    assert 'href="mailto:kilkauciha@gmail.com"' in index_html
    assert 'href="mailto:kilkauciha@gmail.com"' in en_html
    assert "runZeroRetentionSelfTest" in proof_js
    assert "securitypolicyviolation" in proof_js


def test_seo_pwa_static_assets_and_meta_tags() -> None:
    """Verify SEO/OG meta tags and robots.txt, sitemap.xml, 404.html, manifest, and branded PNG assets."""
    client = TestClient(app)
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    en_html = (STATIC_DIR / "en" / "index.html").read_text(encoding="utf-8")
    not_found_html = (STATIC_DIR / "404.html").read_text(encoding="utf-8")
    manifest_src = (STATIC_DIR / "manifest.webmanifest").read_text(encoding="utf-8")

    for meta_snippet in (
        'name="description"',
        'name="theme-color" content="#051C12"',
        'rel="canonical" href="https://promptveil.netlify.app/"',
        'rel="alternate" hreflang="ru" href="https://promptveil.netlify.app/"',
        'rel="alternate" hreflang="en" href="https://promptveil.netlify.app/en/"',
        'rel="alternate" hreflang="x-default" href="https://promptveil.netlify.app/"',
        'rel="manifest" href="/manifest.webmanifest"',
        'rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png"',
        'property="og:type" content="website"',
        'property="og:url" content="https://promptveil.netlify.app/"',
        'property="og:image" content="https://promptveil.netlify.app/og-image.png"',
        'property="og:image:alt"',
        'name="twitter:card" content="summary_large_image"',
        'name="twitter:image" content="https://promptveil.netlify.app/og-image.png"',
    ):
        assert meta_snippet in index_html, f"Missing SEO/OG tag {meta_snippet!r} in index.html"

    assert 'property="og:image:alt"' in en_html
    assert 'name="robots" content="noindex"' in not_found_html
    assert 'href="/favicon.svg"' in not_found_html
    assert 'href="/en/"' in not_found_html
    assert './favicon.svg"' not in not_found_html
    assert "any maskable" not in manifest_src
    assert '"purpose": "any"' in manifest_src
    assert '"purpose": "maskable"' in manifest_src

    routes = (
        ("/robots.txt", "text/plain", b"Sitemap: https://promptveil.netlify.app/sitemap.xml"),
        ("/sitemap.xml", "application/xml", b"<loc>https://promptveil.netlify.app/</loc>"),
        ("/sitemap.xml", "application/xml", b"<loc>https://promptveil.netlify.app/en/</loc>"),
        ("/sitemap.xml", "application/xml", b'hreflang="en"'),
        ("/404.html", "text/html", b"404"),
        ("/manifest.webmanifest", "application/manifest+json", b'"short_name": "PromptVeil"'),
    )
    for route, mime_prefix, expected_bytes in routes:
        resp = client.get(route)
        assert resp.status_code == 200, f"GET {route} failed: {resp.status_code}"
        assert resp.headers["content-type"].startswith(mime_prefix), (
            f"Unexpected MIME for {route}: {resp.headers['content-type']!r}"
        )
        _assert_security_headers(resp.headers)
        assert expected_bytes in resp.content, f"Expected payload missing in {route}"

    for png_route, exp_w, exp_h in (
        ("/og-image.png", 1200, 630),
        ("/apple-touch-icon.png", 180, 180),
        ("/icon-192.png", 192, 192),
        ("/icon-512.png", 512, 512),
    ):
        resp = client.get(png_route)
        assert resp.status_code == 200, f"GET {png_route} failed: {resp.status_code}"
        assert resp.headers["content-type"] == "image/png"
        _assert_security_headers(resp.headers)
        data = resp.content
        assert data.startswith(b"\x89PNG\r\n\x1a\n"), f"{png_route} missing PNG signature"
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        assert (width, height) == (exp_w, exp_h), f"{png_route} size {width}x{height} != {exp_w}x{exp_h}"


def test_service_worker_and_stage2_p1_contracts() -> None:
    """Verify /sw.js strict static-only caching, AI launchers, clickable links, and dark theme hooks."""
    client = TestClient(app)
    sw_resp = client.get("/sw.js")
    assert sw_resp.status_code == 200
    assert "javascript" in sw_resp.headers["content-type"]
    _assert_security_headers(sw_resp.headers)

    sw_src = (STATIC_DIR / "sw.js").read_text(encoding="utf-8")
    assert not re.search(r"(?:https?|wss?)://", sw_src, re.IGNORECASE)
    assert "event.request.method !== \"GET\"" in sw_src or "req.method !== \"GET\"" in sw_src
    assert "origin !== self.location.origin" in sw_src
    assert "innerHTML" not in sw_src
    assert "eval(" not in sw_src
    assert 'CACHE_NAME = "promptveil-build-' in sw_src
    assert "/dist/styles." in sw_src and "/dist/app." in sw_src
    assert "/dist/pro-documents-" in sw_src
    assert '"/downloads/promptveil-pro-extension.zip"' not in sw_src
    assert '"/og-image.png"' not in sw_src
    assert "SKIP_WAITING" in sw_src
    assert "self.clients.claim()" in sw_src
    install_block = re.search(r'addEventListener\("install".*?\}\);', sw_src, re.DOTALL)
    assert install_block is not None and "skipWaiting" not in install_block.group(0)

    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    tokens_css = (STATIC_DIR / "css" / "tokens.css").read_text(encoding="utf-8")
    proof_js = (STATIC_DIR / "js" / "privacy-proof.js").read_text(encoding="utf-8")

    for hook in (
        'id="theme-toggle-btn"',
        'id="ai-launchers-bar"',
        'data-testid="ai-launcher-chatgpt"',
        'data-testid="ai-launcher-deepseek"',
        'data-testid="ai-launcher-gigachat"',
        'data-testid="ai-launcher-alice"',
        'data-testid="ai-launcher-claude"',
        'data-testid="ai-launcher-gemini"',
        'href="https://gemini.google.com/app"',
        'href="https://t.me/supv1rus"',
        'href="https://github.com/Aquanti"',
        'id="proof-offline-card"',
        'id="proof-offline-metric"',
    ):
        assert hook in index_html, f"Missing Stage 2 hook {hook} in index.html"

    en_html = (STATIC_DIR / "en" / "index.html").read_text(encoding="utf-8")
    for html_name, html_src in (("index.html", index_html), ("en/index.html", en_html)):
        assert 'data-testid="ai-launcher-gemini"' in html_src, f"Missing Gemini launcher in {html_name}"
        assert 'href="https://gemini.google.com/app"' in html_src, f"Missing Gemini href in {html_name}"
        sanitize_match = re.search(
            r'<section\s+id="panel-sanitize".*?<section\s+id="panel-rehydrate"',
            html_src,
            re.DOTALL,
        )
        rehydrate_match = re.search(
            r'<section\s+id="panel-rehydrate".*?<div\s+id="ai-launchers-bar"',
            html_src,
            re.DOTALL,
        )
        assert sanitize_match is not None and 'id="ai-launchers-bar"' not in sanitize_match.group(0), (
            f"#ai-launchers-bar must reside outside #panel-sanitize in {html_name}"
        )
        assert rehydrate_match is not None, (
            f"#ai-launchers-bar must reside after #panel-rehydrate in {html_name}"
        )

    modals_js = (STATIC_DIR / "js" / "modals.js").read_text(encoding="utf-8")
    assert 'register("/sw.js")' in modals_js
    assert 'register("./sw.js")' not in modals_js

    assert '[data-theme="dark"]' in tokens_css
    assert "prefers-color-scheme: dark" in tokens_css
    assert "prefers-reduced-motion: reduce" in tokens_css
    assert "THEME_STORAGE_KEY" in proof_js


def test_stage_c_mobile_ux_contracts() -> None:
    """Verify M3 Mobile UX HTML hooks, RU/EN parity, and zero 100vw overflow in CSS."""
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    en_html = (STATIC_DIR / "en" / "index.html").read_text(encoding="utf-8")

    required_hooks = (
        'id="lang-mobile-toggle"',
        'data-testid="lang-mobile-toggle"',
        'id="mobile-more-btn"',
        'data-testid="mobile-more-btn"',
        'id="mobile-more-menu"',
        'data-testid="mobile-more-menu"',
        'id="mobile-open-rulebook-btn"',
        'data-testid="mobile-open-rulebook-btn"',
        'id="mobile-open-audit-btn"',
        'data-testid="mobile-open-audit-btn"',
        'id="mobile-pricing-btn"',
        'data-testid="mobile-pricing-btn"',
        'id="mobile-rulebook-count"',
        'id="mobile-audit-count"',
        'class="brand-badge-lock"',
        'class="brand-badge-dot"',
        'class="brand-badge-text"',
        'id="mode-btn-rehydrate"',
        'data-testid="mode-rehydrate"',
        'class="tab-label-short"',
        'class="tab-label-tail"',
        'id="vault-section"',
        'id="vault-collapse-btn"',
        'data-testid="vault-collapse-btn"',
        'id="vault-collapsible-body"',
        'id="mobile-sticky-cta"',
        'data-testid="mobile-sticky-cta"',
        'id="mobile-sticky-copy-btn"',
        'data-testid="mobile-sticky-copy-btn"',
    )
    for hook in required_hooks:
        assert hook in index_html, f"Missing M3 hook {hook} in index.html"
        assert hook in en_html, f"Missing M3 hook {hook} in en/index.html"

    # #mobile-more-menu items must not use role="menuitem" so Playwright get_by_role("button") matches.
    for html_name, html_src in (("index.html", index_html), ("en/index.html", en_html)):
        menu_match = re.search(
            r'id="mobile-more-menu".*?</div>\s*</div>',
            html_src,
            re.DOTALL,
        )
        assert menu_match is not None, f"Could not locate #mobile-more-menu block in {html_name}"
        assert 'role="menuitem"' not in menu_match.group(0), (
            f'Unexpected role="menuitem" inside #mobile-more-menu in {html_name}'
        )
        assert html_src.count('data-i18n="nav.step2"') == 1, (
            f"Expected single [data-i18n='nav.step2'] in {html_name}"
        )

    for css_path in sorted((STATIC_DIR / "css").glob("*.css")):
        css_text = css_path.read_text(encoding="utf-8")
        assert "100vw" not in css_text, f"Forbidden 100vw width found in {css_path.name}"

    components_css = (STATIC_DIR / "css" / "components.css").read_text(encoding="utf-8")
    desktop_hide_blocks = re.findall(
        r"@media\s*\(\s*min-width:\s*640px\s*\)\s*\{([^}]*display\s*:\s*none[^}]*)\}",
        components_css,
        re.DOTALL,
    )
    assert desktop_hide_blocks, "components.css must hide mobile-only controls at @media (min-width: 640px)"
    last_desktop_hide_pos = components_css.rfind(desktop_hide_blocks[-1])
    after_desktop_hide = components_css[last_desktop_hide_pos + len(desktop_hide_blocks[-1]):]
    assert ".lang-mobile-toggle" in desktop_hide_blocks[-1], (
        "components.css @media (min-width: 640px) must hide .lang-mobile-toggle so it does not override layout.css"
    )
    for mobile_only_cls in (".mobile-more-wrap", ".mobile-more-btn", ".vault-collapse-btn", ".mobile-sticky-cta"):
        assert mobile_only_cls in desktop_hide_blocks[-1], (
            f"components.css @media (min-width: 640px) must hide {mobile_only_cls}"
        )
    assert ".lang-mobile-toggle" not in after_desktop_hide, (
        "components.css must not re-declare .lang-mobile-toggle after the @media (min-width: 640px) hide block"
    )


def test_stage_e_growth_contracts() -> None:
    """Verify M5 Stage E UI hooks, RU/EN parity, and rulebook pack separation."""
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    en_html = (STATIC_DIR / "en" / "index.html").read_text(encoding="utf-8")

    required_m5_hooks = (
        'id="sensitivity-normal-btn"',
        'data-testid="sensitivity-normal-btn"',
        'id="sensitivity-strict-btn"',
        'data-testid="sensitivity-strict-btn"',
        'id="how-it-works"',
        'data-testid="how-it-works-section"',
        'id="honest-limits"',
        'data-testid="honest-limits-section"',
        'id="limits-open-rulebook-btn"',
        'data-testid="limits-open-rulebook-btn"',
        'data-testid="word-packs-box"',
        'data-testid="word-pack-legal"',
        'data-testid="word-pack-hr"',
        'data-testid="word-pack-medical"',
        'data-testid="word-pack-accounting"',
        'id="plan-req-telegram-link"',
        'data-testid="plan-req-telegram-link"',
        'data-testid="plan-fallback-box"',
        'id="plan-req-email-direct"',
        'id="plan-req-copy-email-btn"',
        'id="plan-req-copy-tg-btn"',
        'class="footer-contact-note"',
    )
    for hook in required_m5_hooks:
        assert hook in index_html, f"Missing M5 hook {hook} in index.html"
        assert hook in en_html, f"Missing M5 hook {hook} in en/index.html"

    for html_name, html_src in (("index.html", index_html), ("en/index.html", en_html)):
        rules_ul_match = re.search(
            r'<ul id="rulebook-list"[^>]*>.*?</ul>',
            html_src,
            re.DOTALL,
        )
        assert rules_ul_match is not None, f"Could not locate #rulebook-list in {html_name}"
        assert "word-pack-" not in rules_ul_match.group(0), (
            f"Word pack buttons must stay outside #rulebook-list in {html_name}"
        )


def test_m3_profiles_packs_and_templates_contracts() -> None:
    """Verify M3 (R5) profiles, extended Pro packs, prompt templates, and drawer invariants."""
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    en_html = (STATIC_DIR / "en" / "index.html").read_text(encoding="utf-8")
    storage_js = (STATIC_DIR / "js" / "storage.js").read_text(encoding="utf-8")
    proof_js = (STATIC_DIR / "js" / "privacy-proof.js").read_text(encoding="utf-8")
    presets_js = (STATIC_DIR / "js" / "presets.js").read_text(encoding="utf-8")

    m3_hooks = (
        'id="profile-select"',
        'data-testid="profile-select"',
        'id="profile-name-input"',
        'data-testid="profile-name-input"',
        'id="profile-create-btn"',
        'data-testid="profile-create-btn"',
        'id="profile-rename-btn"',
        'data-testid="profile-rename-btn"',
        'id="profile-delete-btn"',
        'data-testid="profile-delete-btn"',
        'id="rulebook-pro-upgrade-banner"',
        'data-testid="rulebook-pro-upgrade-banner"',
        'id="rulebook-pro-upgrade-btn"',
        'data-testid="word-pack-corporate_ma"',
        'data-testid="word-pack-devsecops"',
        'data-testid="word-pack-banking_fintech"',
        'data-testid="word-pack-crossborder_nda"',
        'id="prompt-templates-bar"',
        'data-testid="prompt-templates-bar"',
        'data-testid="prompt-template-contract_review"',
        'data-testid="prompt-template-nda_redline"',
        'data-testid="prompt-template-code_security_review"',
        'id="prompt-template-preview"',
        'id="prompt-template-upgrade-btn"',
    )
    for hook in m3_hooks:
        assert hook in index_html, f"Missing M3 hook {hook} in index.html"
        assert hook in en_html, f"Missing M3 hook {hook} in en/index.html"

    for html_name, html_src in (("index.html", index_html), ("en/index.html", en_html)):
        drawer_match = re.search(
            r'<aside\s+id="drawer-rulebook".*?</aside>',
            html_src,
            re.DOTALL,
        )
        assert drawer_match is not None, f"Could not locate #drawer-rulebook in {html_name}"
        drawer_html = drawer_match.group(0)
        assert len(re.findall(r'<input\b[^>]*type="file"', drawer_html)) == 1, (
            f"#drawer-rulebook must contain strictly one file input (#import-rules-input) in {html_name}"
        )
        assert 'role="switch"' not in drawer_html, (
            f"Static #drawer-rulebook HTML must contain zero role='switch' in {html_name}"
        )
        packs_pos = drawer_html.find('data-testid="word-packs-box"')
        rules_ul_pos = drawer_html.find('id="rulebook-list"')
        assert 0 <= packs_pos < rules_ul_pos, (
            f".word-packs-box must stay before and outside #rulebook-list in {html_name}"
        )

    assert "promptveil_profiles_v1" in storage_js
    assert "PROFILES_STORAGE_KEY" in proof_js
    assert "key === RULES_STORAGE_KEY || key === PROFILES_STORAGE_KEY" in proof_js
    for pack_id in ("corporate_ma", "devsecops", "banking_fintech", "crossborder_nda"):
        assert pack_id in presets_js
    for tpl_id in ("contract_review", "nda_redline", "code_security_review"):
        assert tpl_id in presets_js


def test_m4b_extension_zip_endpoint_and_security_headers() -> None:
    """Verify /downloads/promptveil-pro-extension.zip MIME, security headers, archive integrity, and traversal 404."""
    import io
    import zipfile

    client = TestClient(app)

    head_resp = client.head("/downloads/promptveil-pro-extension.zip")
    assert head_resp.status_code == 200
    assert head_resp.headers["content-type"].startswith("application/zip")
    assert head_resp.headers.get("cache-control") == "public, max-age=300"
    _assert_security_headers(head_resp.headers)
    assert head_resp.content == b""

    get_resp = client.get("/downloads/promptveil-pro-extension.zip")
    assert get_resp.status_code == 200
    assert get_resp.headers["content-type"].startswith("application/zip")
    assert get_resp.headers.get("cache-control") == "public, max-age=300"
    _assert_security_headers(get_resp.headers)
    assert get_resp.content.startswith(b"PK\x03\x04")

    with zipfile.ZipFile(io.BytesIO(get_resp.content), "r") as zf:
        assert zf.testzip() is None
        names = set(zf.namelist())
        expected = {
            "manifest.json",
            "popup.html",
            "popup.css",
            "content.css",
            "dist/content.bundle.js",
            "dist/popup.bundle.js",
            "icons/icon-16.png",
            "icons/icon-48.png",
            "icons/icon-128.png",
        }
        assert names == expected
        for entry_name in names:
            data = zf.read(entry_name)
            if not entry_name.endswith(".png"):
                text = data.decode("utf-8")
                for marker in FORBIDDEN_LEAK_SUBSTRINGS:
                    assert marker not in text, f"Leak marker {marker!r} in ZIP entry {entry_name}"
                assert "PV-CLIENT-" not in text
                assert not re.search(r"PV1\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}", text)

    for missing_route in ("/downloads/nonexistent.zip", "/downloads/..%2F..%2Fapp/main.py"):
        miss_resp = client.get(missing_route)
        assert miss_resp.status_code == 404
        _assert_security_headers(miss_resp.headers)
        for marker in FORBIDDEN_LEAK_SUBSTRINGS:
            assert marker not in miss_resp.text



