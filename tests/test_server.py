"""Server, CSP security header, zero-egress, and static bundle hygiene tests."""

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
        assert response.headers["content-security-policy"] == CSP_POLICY
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"


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
        assert resp.headers["content-security-policy"] == CSP_POLICY
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "no-referrer"
        assert resp.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"


def test_root_serves_index_html_with_relative_assets_and_csp() -> None:
    """Verify GET / serves index.html with relative asset links and CSP header."""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert response.headers["content-security-policy"] == CSP_POLICY
    body = response.text
    assert './favicon.svg"' in body
    assert './styles.css"' in body
    assert './js/app.js"' in body


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
        assert resp.headers["content-security-policy"] == CSP_POLICY
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "no-referrer"
        assert resp.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"


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
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    # No external http(s) URLs in HTML resource tags.
    assert not re.search(r"<(?:script|link|img)\b[^>]*\b(?:src|href)\s*=\s*['\"]https?://", index_html, re.IGNORECASE)
    # Every <script> tag must have src= and empty inline body.
    for script_match in re.finditer(r"<script\b([^>]*)>(.*?)</script>", index_html, re.IGNORECASE | re.DOTALL):
        attrs, body = script_match.groups()
        assert re.search(r"\bsrc\s*=", attrs, re.IGNORECASE), "Inline <script> without src is forbidden by CSP"
        assert body.strip() == "", "Non-empty <script> body is forbidden by CSP"
    # No <style> tags, inline style attributes, or inline event handlers.
    assert not re.search(r"<style\b", index_html, re.IGNORECASE)
    assert not re.search(r"\bstyle\s*=", index_html, re.IGNORECASE)
    assert not re.search(r"\bon[a-z]+\s*=", index_html, re.IGNORECASE)

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

    # Client JS must remain 100% XSS-safe and zero-egress across all nested modules.
    all_js = sorted((STATIC_DIR / "js").rglob("*.js"))
    assert all_js, "Expected at least one JS module in app/static/js"
    for js_path in all_js:
        source = js_path.read_text(encoding="utf-8")
        assert not re.search(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b", source), (
            f"Forbidden unsafe HTML sink in {js_path.name}"
        )
        assert not re.search(r"\beval\s*\(", source), f"Forbidden eval() in {js_path.name}"
        assert not re.search(r"\bnew\s+Function\s*\(", source), f"Forbidden new Function() in {js_path.name}"
        assert not re.search(r"\bfetch\s*\(", source), f"Forbidden fetch() in {js_path.name}"
        assert "XMLHttpRequest" not in source, f"Forbidden XMLHttpRequest in {js_path.name}"
        assert "sendBeacon" not in source, f"Forbidden sendBeacon in {js_path.name}"
        assert not re.search(r"\bnew\s+WebSocket\s*\(", source), f"Forbidden WebSocket in {js_path.name}"
        assert not re.search(r"\bEventSource\b", source), f"Forbidden EventSource in {js_path.name}"
        assert not re.search(r"""(['"`])(?:https?|wss?)://""", source, re.IGNORECASE), (
            f"Forbidden external URL string literal in {js_path.name}"
        )


def test_netlify_toml_matches_publish_dir_and_csp() -> None:
    """Verify netlify.toml publishes app/static with matching CSP and security headers."""
    netlify_path = BASE_DIR / "netlify.toml"
    data = tomllib.loads(netlify_path.read_text(encoding="utf-8"))
    assert data["build"]["publish"] == "app/static"

    root_headers = next((h for h in data["headers"] if h.get("for") == "/*"), None)
    assert root_headers is not None
    values = root_headers["values"]
    assert values["Content-Security-Policy"] == CSP_POLICY
    assert values["X-Content-Type-Options"] == "nosniff"
    assert values["X-Frame-Options"] == "DENY"
    assert values["Referrer-Policy"] == "no-referrer"
    assert values["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"

    for cached_path in ("/js/*", "/styles.css", "/css/*", "/fonts/*"):
        cache_headers = next((h for h in data["headers"] if h.get("for") == cached_path), None)
        assert cache_headers is not None, f"Missing [[headers]] block for {cached_path} in netlify.toml"
        assert cache_headers["values"]["Cache-Control"] == "public, max-age=300"
