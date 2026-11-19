"""Runtime telemetry monitors for PromptVeil E2E tests.

Provides:
- NetworkMonitor: Phase-aware request tracker enforcing 0 http(s)/ws(s) egress
  during interactive workflows while cleanly exempting client-side blob:/data:
  export downloads.
- ConsoleErrorMonitor: Captures console.error, assert, uncaught pageerror, and
  CDP Log.entryAdded errors (with explicit opt-in suppression for negative CSP tests).
- verify_health_endpoint / verify_csp_and_security_headers: Validates GET /health
  JSON & strict CSP/security headers matching app/config.py and netlify.toml.
- verify_responsive_layout / verify_no_overlap_or_clipping: Checks 1440x900 and
  390x844 viewports for 0 horizontal overflow, 0 clipping, and 0 unintended overlap.
- capture_viewport_screenshot: Saves deterministic viewport PNGs for visual review.
- verify_russian_purity: Enforces <html lang="ru"> and zero English/technical jargon
  in visible UI chrome.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from playwright.sync_api import (
    CDPSession,
    ConsoleMessage,
    Dialog,
    Page,
    Request,
    Response,
    WebSocket,
)


_EGRESS_SCHEMES = ("http://", "https://", "ws://", "wss://")
_LOCAL_DOWNLOAD_SCHEMES = ("blob:", "data:")

_DEFAULT_SCREENSHOT_DIR = Path(__file__).resolve().parent / "artifacts" / "screenshots"

FORBIDDEN_RU_PHRASES: tuple[str, ...] = (
    "Sanitize Prompt",
    "Re-Hydrate Reply",
    "Zero Egress",
    "Vault Mappings",
    "Entity Vault Ledger",
    "Vault Ledger",
    "Rulebook",
    "Audit Receipts",
    "Sanitize",
    "Re-Hydrate",
    "Rehydrate",
)

# All 11 internal detector category codes that must never leak raw outside
# [TOKEN_N] brackets in Russian UI chrome. Accepted Russian banking phrases
# ("Счета (IBAN)" in app/static/js/i18n.js and "счётом IBAN"/"счетами IBAN" in
# app/static/js/presets.js) are explicitly exempted in verify_russian_purity().
FORBIDDEN_RU_DEV_CODES: tuple[str, ...] = (
    "API_KEY",
    "JWT",
    "CREDIT_CARD",
    "IBAN",
    "SSN",
    "ENV_SECRET",
    "CUSTOM",
    "EMAIL",
    "PHONE",
    "IPV4",
    "HIGH_ENTROPY",
)


@dataclass(frozen=True)
class RecordedRequest:
    """Snapshot of an observed browser network request."""

    phase: str
    url: str
    method: str
    resource_type: str
    post_data: str | None = None


@dataclass
class NetworkMonitor:
    """Two-phase network request & zero-egress monitor."""

    page: Page
    phase: str = "load"
    requests: list[RecordedRequest] = field(default_factory=list)
    failed_requests: list[tuple[str, str]] = field(default_factory=list)
    http_errors: list[tuple[int, str]] = field(default_factory=list)
    _attached: bool = False

    def attach(self) -> None:
        """Attach Playwright request/response/requestfailed/websocket listeners."""
        if self._attached:
            return
        self.page.on("request", self._on_request)
        self.page.on("requestfailed", self._on_request_failed)
        self.page.on("response", self._on_response)
        self.page.on("websocket", self._on_websocket)
        self._attached = True

    def detach(self) -> None:
        """Detach listeners cleanly."""
        if not self._attached:
            return
        self.page.remove_listener("request", self._on_request)
        self.page.remove_listener("requestfailed", self._on_request_failed)
        self.page.remove_listener("response", self._on_response)
        self.page.remove_listener("websocket", self._on_websocket)
        self._attached = False

    def _on_request(self, req: Request) -> None:
        post_data: str | None = None
        try:
            post_data = req.post_data
        except Exception:  # noqa: BLE001
            post_data = None
        self.requests.append(
            RecordedRequest(
                phase=self.phase,
                url=req.url,
                method=req.method,
                resource_type=req.resource_type,
                post_data=post_data,
            )
        )

    def _on_request_failed(self, req: Request) -> None:
        failure = req.failure or "unknown failure"
        self.failed_requests.append((req.url, str(failure)))

    def _on_response(self, res: Response) -> None:
        if res.status >= 400:
            self.http_errors.append((res.status, res.url))

    def _on_websocket(self, ws: WebSocket) -> None:
        self.requests.append(
            RecordedRequest(
                phase=self.phase,
                url=ws.url,
                method="WEBSOCKET",
                resource_type="websocket",
                post_data=None,
            )
        )

    def start_interactive_phase(self) -> None:
        """Transition monitor from initial page load to interactive workflow phase."""
        self.phase = "interactive"

    def interactive_egress_requests(self) -> list[RecordedRequest]:
        """Return interactive-phase requests using http(s):// or ws(s):// schemes."""
        egress: list[RecordedRequest] = []
        for req in self.requests:
            if req.phase != "interactive":
                continue
            low = req.url.lower()
            if low.startswith(_LOCAL_DOWNLOAD_SCHEMES):
                continue
            if low.startswith(_EGRESS_SCHEMES):
                egress.append(req)
        return egress

    def assert_clean_load(self) -> None:
        """Assert zero failed requests and zero 4xx/5xx responses during initial load."""
        assert not self.failed_requests, f"Failed requests during load: {self.failed_requests}"
        assert not self.http_errors, f"HTTP >=400 responses during load: {self.http_errors}"

    def assert_zero_egress(self, forbidden_substrings: list[str] | None = None) -> None:
        """Assert strictly 0 http(s)/ws(s) requests during interactive phase."""
        egress = self.interactive_egress_requests()
        assert not egress, (
            "Zero-egress violation: outbound network requests detected during interactive phase: "
            + json.dumps([r.__dict__ for r in egress], ensure_ascii=False)
        )
        if forbidden_substrings:
            for req in self.requests:
                if req.phase != "interactive":
                    continue
                haystack = f"{req.url}\n{req.post_data or ''}"
                for secret in forbidden_substrings:
                    assert secret not in haystack, (
                        f"Secret substring {secret!r} leaked in request {req.url!r}"
                    )


@dataclass
class ConsoleErrorMonitor:
    """Captures console errors, uncaught pageerrors, unexpected dialogs, and CDP logs."""

    page: Page
    console_errors: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    cdp_errors: list[str] = field(default_factory=list)
    unexpected_dialogs: list[str] = field(default_factory=list)
    _cdp: CDPSession | None = None
    _suppress_csp: bool = False
    _track_dialogs: bool = True
    _allow_confirm_accept: bool = False
    _attached: bool = False

    def attach(self) -> None:
        """Attach Playwright and CDP error listeners."""
        if self._attached:
            return
        setattr(self.page, "_pv_console_monitor", self)
        self.page.on("console", self._on_console)
        self.page.on("pageerror", self._on_page_error)
        self.page.on("dialog", self._on_dialog)
        try:
            self._cdp = self.page.context.new_cdp_session(self.page)
            self._cdp.send("Log.enable")
            self._cdp.on("Log.entryAdded", self._on_cdp_log)
        except Exception:  # noqa: BLE001
            self._cdp = None
        self._attached = True

    def detach(self) -> None:
        """Detach listeners and close CDP session cleanly."""
        if not self._attached:
            return
        if getattr(self.page, "_pv_console_monitor", None) is self:
            try:
                delattr(self.page, "_pv_console_monitor")
            except Exception:  # noqa: BLE001
                setattr(self.page, "_pv_console_monitor", None)
        self.page.remove_listener("console", self._on_console)
        self.page.remove_listener("pageerror", self._on_page_error)
        self.page.remove_listener("dialog", self._on_dialog)
        if self._cdp is not None:
            try:
                self._cdp.detach()
            except Exception:  # noqa: BLE001
                pass
            self._cdp = None
        self._attached = False

    @staticmethod
    def _is_csp_message(text: str) -> bool:
        low = text.lower()
        return "content security policy" in low or "content-security-policy" in low or "refused to connect" in low

    def _on_console(self, msg: ConsoleMessage) -> None:
        if msg.type in ("error", "assert"):
            if self._suppress_csp and self._is_csp_message(msg.text):
                return
            self.console_errors.append(f"[{msg.type}] {msg.text}")

    def _on_page_error(self, exc: Exception) -> None:
        self.page_errors.append(str(exc))

    def _on_cdp_log(self, event: dict[str, Any]) -> None:
        entry = event.get("entry", {})
        if entry.get("level") == "error":
            text = str(entry.get("text", ""))
            if self._suppress_csp and self._is_csp_message(text):
                return
            self.cdp_errors.append(f"[{entry.get('source', 'log')}] {text}")

    def _on_dialog(self, dialog: Dialog) -> None:
        if dialog.type == "confirm" and self._allow_confirm_accept:
            try:
                dialog.accept()
            except Exception:  # noqa: BLE001
                pass
            return
        # Record unexpected alert/prompt dialogs (XSS detection) and dismiss safely.
        if dialog.type == "alert" or (self._track_dialogs and dialog.type != "confirm"):
            self.unexpected_dialogs.append(f"{dialog.type}: {dialog.message}")
        try:
            dialog.dismiss()
        except Exception:  # noqa: BLE001
            pass

    @contextmanager
    def allow_confirm_accept(self) -> Iterator[None]:
        """Temporarily accept confirm() dialogs once without dismissing or failing."""
        prev = self._allow_confirm_accept
        self._allow_confirm_accept = True
        try:
            yield
        finally:
            self._allow_confirm_accept = prev

    @contextmanager
    def allow_expected_csp_errors(self) -> Iterator[None]:
        """Temporarily allow browser-generated CSP violation console/CDP errors."""
        prev = self._suppress_csp
        self._suppress_csp = True
        try:
            yield
        finally:
            try:
                self.page.wait_for_timeout(50)
            except Exception:  # noqa: BLE001
                pass
            self._suppress_csp = prev

    def assert_no_errors(self) -> None:
        """Assert zero console errors, zero uncaught exceptions, and zero alert dialogs."""
        errors: list[str] = []
        if self.console_errors:
            errors.append(f"console_errors={self.console_errors}")
        if self.page_errors:
            errors.append(f"page_errors={self.page_errors}")
        if self.cdp_errors:
            errors.append(f"cdp_errors={self.cdp_errors}")
        if self.unexpected_dialogs:
            errors.append(f"unexpected_dialogs={self.unexpected_dialogs}")
        assert not errors, "Runtime browser errors detected: " + "; ".join(errors)


def fetch_http_response(url: str, timeout_s: float = 5.0) -> tuple[int, dict[str, str], str]:
    """Perform a stdlib HTTP GET request returning (status, lowercased_headers, body)."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = int(resp.status)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read().decode("utf-8", errors="replace")
            return status, headers, body
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return int(exc.code), headers, body


def verify_health_endpoint(base_url: str) -> dict[str, Any]:
    """Verify GET /health returns HTTP 200 and expected JSON contract."""
    health_url = f"{base_url.rstrip('/')}/health"
    status, _, body = fetch_http_response(health_url)
    assert status == 200, f"Expected HTTP 200 from {health_url}, got {status}: {body}"
    data = json.loads(body)
    assert data.get("status") == "ok", f"Unexpected /health status field: {data}"
    assert data.get("mode") == "client-side-zero-egress", f"Unexpected /health mode field: {data}"
    assert "version" in data and data["version"], f"Missing /health version field: {data}"
    return dict(data)


def parse_csp_directives(csp_header: str) -> dict[str, list[str]]:
    """Parse semicolon-delimited CSP header into {directive_name: [lowercased_tokens]}."""
    directives: dict[str, list[str]] = {}
    for part in csp_header.split(";"):
        stripped = part.strip()
        if not stripped:
            continue
        tokens = stripped.split()
        name = tokens[0].lower()
        directives[name] = [tok.lower() for tok in tokens[1:]]
    return directives


def verify_csp_and_security_headers(base_url: str) -> dict[str, str]:
    """Verify GET / returns strict CSP and all 5 security hardening headers."""
    root_url = f"{base_url.rstrip('/')}/"
    status, headers, _ = fetch_http_response(root_url)
    assert status == 200, f"Expected HTTP 200 from {root_url}, got {status}"

    csp = headers.get("content-security-policy", "")
    directives = parse_csp_directives(csp)
    for directive, expected in (
        ("default-src", ["'self'"]),
        ("script-src", ["'self'"]),
        ("style-src", ["'self'"]),
        ("font-src", ["'self'"]),
        ("img-src", ["'self'", "data:"]),
        ("connect-src", ["'self'"]),
        ("object-src", ["'none'"]),
        ("base-uri", ["'self'"]),
        ("frame-ancestors", ["'none'"]),
    ):
        assert directives.get(directive) == expected, (
            f"CSP {directive} must equal {expected!r}, got {directives.get(directive)!r} in {csp!r}"
        )

    assert headers.get("x-content-type-options", "").lower() == "nosniff", (
        f"Unexpected X-Content-Type-Options: {headers.get('x-content-type-options')!r}"
    )
    assert headers.get("x-frame-options", "").upper() == "DENY", (
        f"Unexpected X-Frame-Options: {headers.get('x-frame-options')!r}"
    )
    assert "no-referrer" in headers.get("referrer-policy", "").lower(), (
        f"Unexpected Referrer-Policy: {headers.get('referrer-policy')!r}"
    )
    permissions_policy = headers.get("permissions-policy", "").lower()
    assert permissions_policy and "camera=()" in permissions_policy, (
        f"Unexpected or missing Permissions-Policy: {headers.get('permissions-policy')!r}"
    )
    return headers


def verify_no_overlap_or_clipping(page: Page) -> dict[str, Any]:
    """Verify visible controls have zero horizontal/vertical clipping and zero unintended overlap."""
    report: dict[str, Any] = page.evaluate(
        """() => {
            const innerWidth = window.innerWidth;
            const selector = [
                'button',
                '[role="tab"]',
                '[role="button"]',
                '[role="switch"]',
                'input:not([type="file"]):not([type="hidden"])',
                'textarea',
                'select',
                'label[for]',
                '[data-testid="upload-file-btn"]',
                '[data-testid="brand-badge"]',
                '[data-testid="hero-summary"]',
                '[data-testid="vault-item"]',
                '[data-testid="status-banner"]'
            ].join(', ');

            const isVisible = (el) => {
                if (!el || !el.isConnected) return false;
                if (el.closest('[hidden], [aria-hidden="true"], dialog:not([open])')) return false;
                let cur = el;
                while (cur && cur.nodeType === 1) {
                    const st = window.getComputedStyle(cur);
                    if (
                        st.display === 'none' ||
                        st.visibility === 'hidden' ||
                        parseFloat(st.opacity || '1') === 0
                    ) {
                        return false;
                    }
                    cur = cur.parentElement;
                }
                const rect = el.getBoundingClientRect();
                if (rect.width <= 2 || rect.height <= 2) return false;
                return true;
            };

            const seen = new Set();
            const visibleEls = [];
            for (const el of document.querySelectorAll(selector)) {
                if (seen.has(el)) continue;
                seen.add(el);
                if (isVisible(el)) visibleEls.push(el);
            }

            const clipped = [];
            const boxItems = [];
            const nonScrollableTags = new Set(['button', 'a', 'span', 'div', 'label', 'section', 'p', 'header', 'li']);
            const clipVals = new Set(['auto', 'scroll', 'hidden', 'clip']);
            const clipRectToAncestors = (el, baseRect) => {
                let left = baseRect.left;
                let top = baseRect.top;
                let right = baseRect.right;
                let bottom = baseRect.bottom;
                let cur = el;
                while (cur && cur.nodeType === 1) {
                    const curSt = window.getComputedStyle(cur);
                    if (curSt.position === 'fixed') {
                        break;
                    }
                    const anc = cur.parentElement;
                    if (!anc || anc === document.body || anc === document.documentElement) {
                        break;
                    }
                    const ast = window.getComputedStyle(anc);
                    if (ast.display !== 'contents' && ast.display !== 'inline') {
                        const clipX = clipVals.has(ast.overflowX);
                        const clipY = clipVals.has(ast.overflowY);
                        if (clipX || clipY) {
                            const ar = anc.getBoundingClientRect();
                            if (clipX) {
                                const cLeft = ar.left + anc.clientLeft;
                                const cRight = cLeft + anc.clientWidth;
                                left = Math.max(left, cLeft);
                                right = Math.min(right, cRight);
                            }
                            if (clipY) {
                                const cTop = ar.top + anc.clientTop;
                                const cBottom = cTop + anc.clientHeight;
                                top = Math.max(top, cTop);
                                bottom = Math.min(bottom, cBottom);
                            }
                        }
                    }
                    cur = anc;
                }
                return { left, top, right, bottom };
            };
            for (const el of visibleEls) {
                const rect = el.getBoundingClientRect();
                const tag = el.tagName.toLowerCase();
                const role = (el.getAttribute('role') || '').toLowerCase();
                const tid = el.getAttribute('data-testid') || '';
                const desc = tid || el.id || `${tag}:${(el.textContent || '').trim().slice(0, 32)}`;
                const st = window.getComputedStyle(el);

                if (rect.left < -1 || rect.right > innerWidth + 1) {
                    clipped.push({
                        desc,
                        reason: 'out-of-viewport',
                        left: Math.round(rect.left),
                        right: Math.round(rect.right),
                        innerWidth
                    });
                }
                if (
                    nonScrollableTags.has(tag) &&
                    el.clientWidth > 0 &&
                    el.scrollWidth > el.clientWidth + 2
                ) {
                    if (st.overflowX !== 'auto' && st.overflowX !== 'scroll') {
                        clipped.push({
                            desc,
                            reason: 'inner-scroll-clip',
                            scrollWidth: el.scrollWidth,
                            clientWidth: el.clientWidth
                        });
                    }
                }
                if (
                    (nonScrollableTags.has(tag) || role === 'button' || role === 'tab') &&
                    el.clientHeight > 0 &&
                    el.scrollHeight > el.clientHeight + 2 &&
                    (st.overflowY === 'hidden' || st.overflowY === 'clip')
                ) {
                    clipped.push({
                        desc,
                        reason: 'inner-vertical-clip',
                        scrollHeight: el.scrollHeight,
                        clientHeight: el.clientHeight
                    });
                }
                if (
                    tag === 'button' ||
                    tag === 'label' ||
                    role === 'button' ||
                    role === 'tab' ||
                    tid === 'upload-file-btn'
                ) {
                    for (const child of el.querySelectorAll('span, strong, small, label')) {
                        if (child.hasAttribute('hidden') || child.closest('[hidden]')) continue;
                        const cst = window.getComputedStyle(child);
                        if (
                            cst.display === 'none' ||
                            cst.visibility === 'hidden' ||
                            parseFloat(cst.opacity || '1') === 0 ||
                            child.clientWidth <= 2 ||
                            child.clientHeight <= 2 ||
                            cst.clip === 'rect(0px, 0px, 0px, 0px)' ||
                            (cst.clipPath || '').startsWith('inset(50%)')
                        ) {
                            continue;
                        }
                        if (
                            (cst.overflowX === 'hidden' || cst.overflowX === 'clip') &&
                            child.scrollWidth > child.clientWidth + 2
                        ) {
                            clipped.push({
                                desc: `${desc} > ${child.tagName.toLowerCase()}`,
                                reason: 'inner-child-scroll-clip',
                                scrollWidth: child.scrollWidth,
                                clientWidth: child.clientWidth
                            });
                        }
                        if (
                            (cst.overflowY === 'hidden' || cst.overflowY === 'clip') &&
                            child.scrollHeight > child.clientHeight + 2
                        ) {
                            clipped.push({
                                desc: `${desc} > ${child.tagName.toLowerCase()}`,
                                reason: 'inner-child-vertical-clip',
                                scrollHeight: child.scrollHeight,
                                clientHeight: child.clientHeight
                            });
                        }
                    }
                }
                if (
                    tag === 'button' ||
                    tag === 'input' ||
                    tag === 'textarea' ||
                    tag === 'select' ||
                    (tag === 'label' && el.hasAttribute('for')) ||
                    role === 'tab' ||
                    role === 'switch' ||
                    role === 'button' ||
                    tid === 'brand-badge' ||
                    tid === 'upload-file-btn' ||
                    tid === 'status-banner' ||
                    tid === 'hero-summary' ||
                    tid === 'vault-item'
                ) {
                    const visibleRect = clipRectToAncestors(el, rect);
                    if (visibleRect.right - visibleRect.left > 2 && visibleRect.bottom - visibleRect.top > 2) {
                        boxItems.push({
                            el,
                            desc,
                            rect: visibleRect,
                            inDialog: Boolean(el.closest('[role="dialog"], dialog[open], [data-drawer]'))
                        });
                    }
                }
            }

            const overlaps = [];
            for (let i = 0; i < boxItems.length; i++) {
                const a = boxItems[i];
                for (let j = i + 1; j < boxItems.length; j++) {
                    const b = boxItems[j];
                    if (a.inDialog !== b.inDialog) continue;
                    if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
                    const ix = Math.max(0, Math.min(a.rect.right, b.rect.right) - Math.max(a.rect.left, b.rect.left));
                    const iy = Math.max(0, Math.min(a.rect.bottom, b.rect.bottom) - Math.max(a.rect.top, b.rect.top));
                    if (ix > 2 && iy > 2) {
                        overlaps.push({
                            a: a.desc,
                            b: b.desc,
                            ix: Math.round(ix),
                            iy: Math.round(iy)
                        });
                    }
                }
            }
            return { checkedCount: visibleEls.length, clipped, overlaps };
        }"""
    )
    assert not report["clipped"], (
        f"Clipped/out-of-viewport UI controls detected: {json.dumps(report['clipped'], ensure_ascii=False)}"
    )
    assert not report["overlaps"], (
        f"Overlapping UI controls detected: {json.dumps(report['overlaps'], ensure_ascii=False)}"
    )
    return report


def verify_responsive_layout(page: Page, width: int, height: int) -> dict[str, Any]:
    """Verify zero horizontal overflow, zero clipping, and zero overlap at target dimensions."""
    page.set_viewport_size({"width": width, "height": height})
    page.wait_for_timeout(150)
    metrics: dict[str, Any] = page.evaluate(
        """() => ({
            innerWidth: window.innerWidth,
            clientWidth: document.documentElement.clientWidth,
            scrollWidth: document.documentElement.scrollWidth,
            bodyScrollWidth: document.body ? document.body.scrollWidth : 0
        })"""
    )
    assert metrics["innerWidth"] == width, (
        f"Viewport innerWidth={metrics['innerWidth']} != {width} (missing viewport meta?)"
    )
    assert metrics["scrollWidth"] <= metrics["innerWidth"], (
        f"Horizontal overflow at {width}x{height}: scrollWidth={metrics['scrollWidth']} > innerWidth={metrics['innerWidth']}"
    )
    assert metrics["scrollWidth"] <= metrics["clientWidth"], (
        f"Horizontal overflow at {width}x{height}: scrollWidth={metrics['scrollWidth']} > clientWidth={metrics['clientWidth']}"
    )
    assert metrics["bodyScrollWidth"] <= metrics["innerWidth"], (
        f"Body horizontal overflow at {width}x{height}: bodyScrollWidth={metrics['bodyScrollWidth']} > innerWidth={metrics['innerWidth']}"
    )
    geometry = verify_no_overlap_or_clipping(page)
    metrics["geometry"] = geometry
    return metrics


def capture_viewport_screenshot(
    page: Page,
    name: str,
    width: int,
    height: int,
    output_dir: Path | None = None,
    full_page: bool = True,
) -> Path:
    """Resize viewport, wait for fonts/layout settle, and capture a PNG screenshot."""
    target_dir = output_dir if output_dir is not None else _DEFAULT_SCREENSHOT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    page.set_viewport_size({"width": width, "height": height})
    page.evaluate(
        """async () => {
            if (document.fonts && document.fonts.ready) {
                try { await document.fonts.ready; } catch (_e) {}
            }
        }"""
    )
    page.wait_for_timeout(150)
    filename = name if name.endswith(".png") else f"{name}_{width}x{height}.png"
    dest = target_dir / filename
    page.screenshot(path=str(dest), full_page=full_page)
    return dest


def verify_russian_purity(page: Page) -> dict[str, Any]:
    """Verify <html lang='ru'> and absence of forbidden English/jargon terms in visible UI chrome."""
    snapshot: dict[str, Any] = page.evaluate(
        """() => {
            const lang = document.documentElement.lang || '';
            const title = document.title || '';
            const skipSelectors = [
                'script', 'style', 'noscript', 'textarea', 'input',
                '[data-testid="sanitized-output"]',
                '[data-testid="restored-output"]',
                'mark[data-token]',
                'mark.restored-token',
                '[data-testid="vault-value"]',
                '[data-testid="vault-token"]'
            ].join(', ');

            const isHidden = (el) => {
                if (!el) return true;
                if (el.hasAttribute('hidden') || el.getAttribute('aria-hidden') === 'true') return true;
                if (el.tagName === 'DIALOG' && !el.hasAttribute('open')) return true;
                const st = window.getComputedStyle(el);
                return st.display === 'none' || st.visibility === 'hidden';
            };
            const isInClosedDetails = (el) => {
                const closedDetails = el.closest('details:not([open])');
                if (!closedDetails) return false;
                const sum = el.closest('summary');
                return !(sum && closedDetails.contains(sum) && sum.closest('details') === closedDetails);
            };

            const chunks = [];
            const walker = document.createTreeWalker(
                document.body,
                NodeFilter.SHOW_TEXT,
                {
                    acceptNode(node) {
                        const txt = (node.nodeValue || '').trim();
                        if (!txt) return NodeFilter.FILTER_REJECT;
                        const parent = node.parentElement;
                        if (!parent) return NodeFilter.FILTER_REJECT;
                        if (parent.closest(skipSelectors)) return NodeFilter.FILTER_REJECT;
                        if (isInClosedDetails(parent)) return NodeFilter.FILTER_REJECT;
                        let cur = parent;
                        while (cur && cur !== document.body) {
                            if (isHidden(cur)) return NodeFilter.FILTER_REJECT;
                            cur = cur.parentElement;
                        }
                        return NodeFilter.FILTER_ACCEPT;
                    }
                }
            );
            let n;
            while ((n = walker.nextNode())) {
                chunks.push((n.nodeValue || '').trim());
            }

            const isElHidden = (el) => {
                if (isInClosedDetails(el)) return true;
                let cur = el;
                while (cur && cur !== document.body && cur !== document.documentElement) {
                    if (isHidden(cur)) return true;
                    cur = cur.parentElement;
                }
                return false;
            };
            const dataAttrSkip = [
                'script', 'style', 'noscript',
                'mark[data-token]', 'mark.restored-token',
                '[data-testid="vault-value"]', '[data-testid="vault-token"]'
            ].join(', ');
            for (const el of document.body.querySelectorAll('*')) {
                if (isElHidden(el)) continue;
                const tag = el.tagName.toLowerCase();
                if (tag === 'script' || tag === 'style' || tag === 'noscript') continue;

                const ph = (el.getAttribute('placeholder') || '').trim();
                if (ph) chunks.push(ph);

                const inDataContainer = Boolean(el.closest(dataAttrSkip)) || (
                    Boolean(el.closest('[data-testid="sanitized-output"], [data-testid="restored-output"]')) &&
                    el.getAttribute('data-testid') !== 'sanitized-output' &&
                    el.getAttribute('data-testid') !== 'restored-output'
                );
                if (!inDataContainer) {
                    const ariaLbl = (el.getAttribute('aria-label') || '').trim();
                    if (ariaLbl) chunks.push(ariaLbl);
                    const titleAttr = (el.getAttribute('title') || '').trim();
                    if (titleAttr) chunks.push(titleAttr);
                    if (tag === 'optgroup') {
                        const optLbl = (el.getAttribute('label') || '').trim();
                        if (optLbl) chunks.push(optLbl);
                    }
                    if (tag === 'img') {
                        const altAttr = (el.getAttribute('alt') || '').trim();
                        if (altAttr) chunks.push(altAttr);
                    }
                }

                if (tag === 'input') {
                    const inputType = (el.getAttribute('type') || '').toLowerCase();
                    if (inputType === 'button' || inputType === 'submit' || inputType === 'reset') {
                        const btnVal = (el.value || el.getAttribute('value') || '').trim();
                        if (btnVal) chunks.push(btnVal);
                    }
                }
            }
            return { lang, title, chromeText: chunks.join(' \\n ') };
        }"""
    )

    assert snapshot["lang"].lower() == "ru", (
        f"Expected <html lang='ru'> on default Russian UI, got lang={snapshot['lang']!r}"
    )

    # Strip legitimate bracketed masked tokens like [ENV_SECRET_1] before jargon scan,
    # and exempt exact accepted Russian banking phrases referencing IBAN:
    # - "Счета (IBAN)" (app/static/js/i18n.js:155)
    # - "счётом IBAN" / "счетами IBAN" (app/static/js/presets.js:15,57 preset tooltips)
    raw_chrome = f"{snapshot['title']}\n{snapshot['chromeText']}"
    cleaned_chrome = re.sub(r"\[[A-Z_]+_\d+\]", " ", raw_chrome)
    for localized_iban_phrase in ("Счета (IBAN)", "счётом IBAN", "счетами IBAN"):
        cleaned_chrome = cleaned_chrome.replace(localized_iban_phrase, " ")

    violations: list[str] = []
    for phrase in FORBIDDEN_RU_PHRASES:
        pat = re.compile(rf"(?<![A-Za-zА-Яа-яЁё0-9_]){re.escape(phrase)}(?![A-Za-zА-Яа-яЁё0-9_])", re.I)
        if pat.search(cleaned_chrome):
            violations.append(phrase)

    for code in FORBIDDEN_RU_DEV_CODES:
        pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(code)}(?![A-Za-z0-9_])", re.I)
        if pat.search(cleaned_chrome):
            violations.append(code)

    assert not violations, (
        f"Forbidden English/jargon terms found in Russian UI chrome: {violations!r}\n"
        f"Scanned chrome text excerpt: {cleaned_chrome[:500]!r}"
    )
    return snapshot
