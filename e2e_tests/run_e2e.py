"""Dual-mode CLI runner for PromptVeil Opaque-Box E2E Suite.

Modes:
- --mode self-test: Runs py_compile, verifies pytest collects all 143 tests
  (109 Tiers 1-4 + 29 Tier 5 + 5 Acceptance), launches an in-process contract-mock
  HTTP server (e2e_tests/fixtures/), and runs real Playwright + headless Chrome/Edge
  self-tests including positive Russian-first contract checks and negative monitor checks.
- --mode live: Runs the pytest suite against --base-url (default http://127.0.0.1:8000)
  or --static-only (app/static/ without /health), with optional --start-server,
  --tier (1|2|3|4|5|acceptance|all), --filter, --browser, --headed, and --report-json.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import py_compile
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from playwright.sync_api import Browser, Playwright, sync_playwright

from locators import PromptVeilUI
from monitors import (
    ConsoleErrorMonitor,
    NetworkMonitor,
    verify_csp_and_security_headers,
    verify_health_endpoint,
    verify_no_overlap_or_clipping,
    verify_responsive_layout,
    verify_russian_purity,
)


E2E_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = E2E_DIR / "fixtures"

_CSP_HEADER = (
    "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; frame-ancestors 'none'"
)


class _SmokeRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Serves e2e_tests/fixtures/ with /health and strict CSP/security headers."""

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", _CSP_HEADER)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            payload = json.dumps(
                {
                    "status": "ok",
                    "mode": "client-side-zero-egress",
                    "version": "1.0.0",
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if self.path == "/" or self.path.startswith("/?"):
            self.path = "/smoke_contract.html"
        super().do_GET()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        _ = (format, args)


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 128
    allow_reuse_address = True


def _launch_browser(pw: Playwright, preference: str, headed: bool) -> Browser:
    channels = ["chrome", "msedge"] if preference == "auto" else [preference]
    errors: list[str] = []
    for channel in channels:
        try:
            return pw.chromium.launch(channel=channel, headless=not headed)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{channel}: {exc}")
    raise RuntimeError("Could not launch Chrome/Edge: " + " | ".join(errors))


def _step_py_compile() -> None:
    py_files = sorted(E2E_DIR.glob("*.py"))
    for path in py_files:
        py_compile.compile(str(path), doraise=True)
    print(f"[self-test] py_compile OK ({len(py_files)} files)")


def _collect_marker_ids(marker_expr: str | None = None) -> list[str]:
    cmd = [sys.executable, "-m", "pytest", str(E2E_DIR), "--collect-only", "-q"]
    if marker_expr:
        cmd.extend(["-m", marker_expr])
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"pytest --collect-only ({marker_expr or 'all'}) failed:\n{proc.stdout}\n{proc.stderr}")
    return [ln.strip() for ln in proc.stdout.splitlines() if "::test_" in ln]


def _step_collect_only() -> None:
    t1_4_lines = _collect_marker_ids("tier1 or tier2 or tier3 or tier4")
    if len(t1_4_lines) != 109 or len(set(t1_4_lines)) != 109:
        raise RuntimeError(
            f"Expected 109 unique Tiers 1-4 tests, got {len(t1_4_lines)} (unique={len(set(t1_4_lines))})."
        )
    t5_lines = _collect_marker_ids("tier5")
    if len(t5_lines) != 29 or len(set(t5_lines)) != 29:
        raise RuntimeError(
            f"Expected 29 unique Tier 5 tests, got {len(t5_lines)} (unique={len(set(t5_lines))})."
        )
    acc_lines = _collect_marker_ids("acceptance")
    if len(acc_lines) != 5 or len(set(acc_lines)) != 5:
        raise RuntimeError(
            f"Expected 5 unique Acceptance tests, got {len(acc_lines)} (unique={len(set(acc_lines))})."
        )
    all_lines = _collect_marker_ids()
    expected_total = len(t1_4_lines) + len(t5_lines) + len(acc_lines)
    if len(all_lines) != len(set(all_lines)) or len(all_lines) != expected_total:
        raise RuntimeError(
            f"Unexpected total collected tests: total={len(all_lines)}, unique={len(set(all_lines))}, expected={expected_total}"
        )
    print(
        f"[self-test] pytest --collect-only OK "
        f"({len(t1_4_lines)} Tier 1-4 + {len(t5_lines)} Tier 5 + {len(acc_lines)} Acceptance = {len(all_lines)} unique tests)"
    )


def _run_positive_smoke_checks(browser: Browser, base_url: str) -> None:
    verify_health_endpoint(base_url)
    verify_csp_and_security_headers(base_url)

    with tempfile.TemporaryDirectory(prefix="pv_selftest_io_") as tmp:
        io_root = Path(tmp)
        try:
            ctx = browser.new_context(
                accept_downloads=True,
                viewport={"width": 1440, "height": 900},
                permissions=["clipboard-read", "clipboard-write"],
            )
        except Exception:  # noqa: BLE001
            ctx = browser.new_context(accept_downloads=True, viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        net = NetworkMonitor(page=page)
        console = ConsoleErrorMonitor(page=page)
        net.attach()
        console.attach()
        try:
            page.goto(f"{base_url}/", wait_until="networkidle")
            net.assert_clean_load()
            net.start_interactive_phase()

            ui = PromptVeilUI(page)
            assert ui.get_document_lang() == "ru"
            verify_russian_purity(page)
            assert ui.get_hero_summary_text()
            assert ui.get_zero_egress_pill().is_visible()
            assert ui.get_vault_empty_state_text()

            # Sanitize + Vault toggle + Category chip + Copy + Telemetry
            out = ui.sanitize_text("Email a@example.com and IP 192.0.2.10")
            assert "[EMAIL_1]" in out and "[IP_1]" in out
            assert ui.get_category_chip_count("EMAIL") == 1
            assert ui.get_telemetry_masked_count() == 2
            verify_russian_purity(page)

            ui.click_copy_output()
            clip = ui.read_clipboard_text()
            fb = ui.get_copy_feedback_text()
            assert (clip is not None and "[EMAIL_1]" in clip) or bool(fb)

            ui.toggle_hide_values()
            assert "a@example.com" not in ui.get_vault_rows()[0].raw_text
            ui.toggle_vault_entity("[EMAIL_1]")
            assert "a@example.com" in ui.get_sanitize_output_text()
            ui.toggle_vault_entity("[EMAIL_1]")
            assert "[EMAIL_1]" in ui.get_sanitize_output_text()
            ui.toggle_hide_values()

            # 0-count category chip read (IBAN) must NOT expand collapsed category chips
            iban_was_hidden = page.locator("[data-testid='category-chips'] [data-category='IBAN']").evaluate(
                "el => el.classList.contains('hidden') || el.hidden"
            )
            assert iban_was_hidden, "Expected IBAN chip to start hidden in smoke_contract"
            assert ui.get_category_chip_count("IBAN") == 0
            iban_still_hidden = page.locator("[data-testid='category-chips'] [data-category='IBAN']").evaluate(
                "el => el.classList.contains('hidden') || el.hidden"
            )
            assert iban_still_hidden, "get_category_chip_count('IBAN') must not mutate collapsed chip visibility"

            # Re-Hydrate + unresolved token + CTA navigation
            ui.click_go_rehydrate()
            restored = ui.rehydrate_text("Reply [EMAIL_1] and [JWT_99]")
            assert "a@example.com" in restored
            assert "[JWT_99]" in ui.get_unresolved_tokens()
            ui.click_back_sanitize()

            # Preset pill + Clear input
            ui.select_preset("bilingual_cis_hr")
            assert "[PHONE_1]" in ui.get_sanitize_output_text()
            ui.click_clear_input()
            assert ui.get_prompt_input().input_value() == ""
            assert ui.get_vault_rows() == []

            # FileReader upload
            up_file = io_root / "note.txt"
            up_file.write_text("File user file@example.com", encoding="utf-8")
            ui.upload_file(up_file)
            assert "[EMAIL_1]" in ui.get_sanitize_output_text()

            # Rulebook Badge + Add (with <select> category) / Export (blob:) / Delete / Import
            badge_before = ui.get_rulebook_badge_count()
            ui.add_custom_rule("ООО «Вектор»", label="ORG")
            assert ui.get_rulebook_badge_count() == badge_before + 1
            exported_rules = ui.export_rules_json(io_root)
            assert "ООО «Вектор»" in exported_rules.read_text(encoding="utf-8")
            ui.delete_custom_rule("ООО «Вектор»")
            ui.import_rules_json(exported_rules)
            assert "ООО «Вектор»" in ui.get_rulebook_text()
            ui.close_open_drawer()

            # Audit SHA-256 + Export (blob:) + Clear
            assert len(ui.get_audit_hashes()) >= 1
            exported_audit = ui.export_audit_json(io_root)
            assert "file@example.com" not in exported_audit.read_text(encoding="utf-8")
            ui.clear_audit_log()
            assert ui.get_audit_hashes() == []
            ui.close_open_drawer()

            net.assert_zero_egress(["a@example.com", "file@example.com"])

            # Language switcher RU | EN + persistence across reload
            ui.switch_language("en")
            assert ui.get_document_lang() == "en"
            assert ui.get_stored_language() == "en"
            net.phase = "load"
            page.reload(wait_until="networkidle")
            net.assert_clean_load()
            net.start_interactive_phase()
            assert ui.get_document_lang() == "en"
            ui.switch_language("ru")
            assert ui.get_document_lang() == "ru"
            assert ui.get_stored_language() == "ru"
            verify_russian_purity(page)

            # Responsive layout + overlap/clipping checks at 1440x900 & 390x844
            verify_responsive_layout(page, 1440, 900)
            verify_responsive_layout(page, 390, 844)

            net.assert_zero_egress()
            console.assert_no_errors()
        finally:
            console.detach()
            net.detach()
            ctx.close()
    print("[self-test] Positive smoke checks OK (RU-first contract, RU|EN persistence, 1440x900 & 390x844 overlap/clipping)")


def _run_isolation_check(browser: Browser, base_url: str) -> None:
    ctx1 = browser.new_context()
    p1 = ctx1.new_page()
    p1.goto(f"{base_url}/", wait_until="networkidle")
    PromptVeilUI(p1).add_custom_rule("IsolationSecretTerm")
    assert "IsolationSecretTerm" in p1.evaluate("() => localStorage.getItem('promptveil_rules_v1') || ''")
    ctx1.close()

    ctx2 = browser.new_context()
    p2 = ctx2.new_page()
    p2.goto(f"{base_url}/", wait_until="networkidle")
    leaked = p2.evaluate("() => localStorage.getItem('promptveil_rules_v1')")
    ctx2.close()
    assert leaked is None, f"BrowserContext isolation leaked localStorage: {leaked!r}"
    print("[self-test] BrowserContext localStorage isolation OK")


def _run_negative_monitor_checks(browser: Browser, base_url: str) -> None:
    # (a) Network leak detection + WebSocket + console/pageerror + overflow/overlap/clipping + RU purity
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    net = NetworkMonitor(page=page)
    console = ConsoleErrorMonitor(page=page)
    net.attach()
    console.attach()
    try:
        page.goto(f"{base_url}/", wait_until="networkidle")
        net.start_interactive_phase()
        page.evaluate("() => fetch('/api/leak', { method: 'POST', body: 'secret_leak' }).catch(() => {})")
        page.wait_for_timeout(150)
        caught_net = False
        try:
            net.assert_zero_egress()
        except AssertionError:
            caught_net = True
        assert caught_net, "Negative monitor check failed: NetworkMonitor did not catch /api/leak"

        # (a2) WebSocket ws:// egress detection
        ws_url = base_url.replace("http://", "ws://", 1) + "/ws-leak"
        net_ws = NetworkMonitor(page=page)
        net_ws.attach()
        net_ws.start_interactive_phase()
        try:
            page.evaluate("(u) => { try { new WebSocket(u); } catch (_e) {} }", ws_url)
            page.wait_for_timeout(150)
            caught_ws = False
            try:
                net_ws.assert_zero_egress()
            except AssertionError:
                caught_ws = True
            assert caught_ws, "Negative monitor check failed: NetworkMonitor did not catch ws:// egress"
        finally:
            net_ws.detach()

        # (b) console.error and uncaught exception detection
        page.evaluate(
            """() => {
                console.error('simulated_console_error');
                setTimeout(() => { throw new Error('simulated_uncaught_error'); }, 0);
            }"""
        )
        page.wait_for_timeout(150)
        caught_console = False
        try:
            console.assert_no_errors()
        except AssertionError:
            caught_console = True
        assert caught_console, "Negative monitor check failed: ConsoleErrorMonitor did not catch error"
        assert len(console.console_errors) >= 1 and len(console.page_errors) >= 1

        # (c) Mobile horizontal overflow detection
        page.evaluate(
            """() => {
                const div = document.createElement('div');
                div.id = 'neg-overflow';
                div.style.width = '700px';
                div.style.height = '10px';
                div.textContent = 'overflow';
                document.body.appendChild(div);
            }"""
        )
        caught_overflow = False
        try:
            verify_responsive_layout(page, 390, 844)
        except AssertionError:
            caught_overflow = True
        assert caught_overflow, "Negative monitor check failed: responsive check missed overflow"
        page.evaluate("() => document.getElementById('neg-overflow')?.remove()")

        # (c2) Overlapping sibling controls detection
        page.evaluate(
            """() => {
                const wrap = document.createElement('div');
                wrap.id = 'neg-overlap';
                wrap.style.position = 'relative';
                wrap.style.height = '60px';
                const b1 = document.createElement('button');
                b1.textContent = 'BtnA';
                b1.style.position = 'absolute';
                b1.style.left = '10px';
                b1.style.top = '10px';
                b1.style.width = '100px';
                const b2 = document.createElement('button');
                b2.textContent = 'BtnB';
                b2.style.position = 'absolute';
                b2.style.left = '30px';
                b2.style.top = '12px';
                b2.style.width = '100px';
                wrap.append(b1, b2);
                document.body.appendChild(wrap);
            }"""
        )
        caught_overlap = False
        try:
            verify_no_overlap_or_clipping(page)
        except AssertionError:
            caught_overlap = True
        assert caught_overlap, "Negative monitor check failed: verify_no_overlap_or_clipping missed overlapping buttons"
        page.evaluate("() => document.getElementById('neg-overlap')?.remove()")

        # (c2b) Scroll-container clipping: partially/fully scrolled-out button vs footer must NOT false-positive,
        # while genuinely overlapping visible buttons inside the scroll container MUST still fail.
        page.evaluate(
            """() => {
                const drawer = document.createElement('div');
                drawer.id = 'probe-scroll-drawer';
                drawer.setAttribute('role', 'dialog');
                drawer.style.cssText = 'position:fixed;right:0;top:0;width:300px;height:140px;display:flex;flex-direction:column;background:#fff;z-index:999;';
                const body = document.createElement('div');
                body.id = 'probe-scroll-body';
                body.style.cssText = 'position:relative;flex:1 1 auto;height:80px;overflow-y:auto;';
                const edgeBtn = document.createElement('button');
                edgeBtn.type = 'button';
                edgeBtn.textContent = 'Край';
                edgeBtn.style.cssText = 'position:absolute;left:8px;top:64px;height:36px;width:90px;';
                const offscreenBtn = document.createElement('button');
                offscreenBtn.type = 'button';
                offscreenBtn.textContent = 'Ниже';
                offscreenBtn.style.cssText = 'position:absolute;left:8px;top:150px;height:36px;width:90px;';
                body.append(edgeBtn, offscreenBtn);
                const footer = document.createElement('div');
                footer.style.cssText = 'height:60px;display:flex;align-items:center;padding:8px;';
                const footerBtn = document.createElement('button');
                footerBtn.type = 'button';
                footerBtn.textContent = 'Экспорт';
                footerBtn.style.cssText = 'height:36px;width:110px;';
                footer.appendChild(footerBtn);
                drawer.append(body, footer);
                document.body.appendChild(drawer);
            }"""
        )
        try:
            verify_no_overlap_or_clipping(page)
            page.evaluate(
                """() => {
                    const body = document.getElementById('probe-scroll-body');
                    const ov1 = document.createElement('button');
                    ov1.type = 'button';
                    ov1.textContent = 'ВидимаяА';
                    ov1.style.cssText = 'position:absolute;left:8px;top:10px;height:32px;width:100px;';
                    const ov2 = document.createElement('button');
                    ov2.type = 'button';
                    ov2.textContent = 'ВидимаяБ';
                    ov2.style.cssText = 'position:absolute;left:30px;top:14px;height:32px;width:100px;';
                    body.append(ov1, ov2);
                }"""
            )
            caught_scroll_overlap = False
            try:
                verify_no_overlap_or_clipping(page)
            except AssertionError:
                caught_scroll_overlap = True
            assert caught_scroll_overlap, (
                "Negative monitor check failed: verify_no_overlap_or_clipping missed genuine visible overlap inside scroll container"
            )
        finally:
            page.evaluate("() => document.getElementById('probe-scroll-drawer')?.remove()")

        # (c2c) [data-testid='vault-item'] (<li>) horizontal inner-scroll-clip detection
        page.evaluate(
            """() => {
                const ul = document.createElement('ul');
                ul.id = 'neg-vault-li-wrap';
                ul.style.cssText = 'width:120px;margin:0;padding:0;list-style:none;';
                const li = document.createElement('li');
                li.setAttribute('data-testid', 'vault-item');
                li.style.cssText = 'width:80px;overflow:hidden;white-space:nowrap;';
                li.textContent = 'VeryLongUnwrappedVaultItemValueThatOverflows80pxContainer';
                ul.appendChild(li);
                document.body.appendChild(ul);
            }"""
        )
        caught_vault_li_clip = False
        try:
            verify_no_overlap_or_clipping(page)
        except AssertionError:
            caught_vault_li_clip = True
        finally:
            page.evaluate("() => document.getElementById('neg-vault-li-wrap')?.remove()")
        assert caught_vault_li_clip, (
            "Negative monitor check failed: verify_no_overlap_or_clipping missed <li> vault-item inner-scroll-clip"
        )

        # (c3) Clipped control detection
        page.evaluate(
            """() => {
                const b = document.createElement('button');
                b.id = 'neg-clip';
                b.style.width = '40px';
                b.style.overflow = 'hidden';
                b.style.whiteSpace = 'nowrap';
                b.textContent = 'VeryLongClippedButtonLabelText';
                document.body.appendChild(b);
            }"""
        )
        caught_clip = False
        try:
            verify_no_overlap_or_clipping(page)
        except AssertionError:
            caught_clip = True
        assert caught_clip, "Negative monitor check failed: verify_no_overlap_or_clipping missed clipped button"
        page.evaluate("() => document.getElementById('neg-clip')?.remove()")

        # (c4) Russian purity jargon detection (text nodes + Vault Ledger + placeholder + aria-label + title + input button)
        purity_probes = [
            (
                "document.body.insertAdjacentHTML('beforeend', '<button id=\"neg-jargon\">Rulebook HIGH_ENTROPY</button>')",
                "text node jargon",
            ),
            (
                "document.body.insertAdjacentHTML('beforeend', '<button id=\"neg-jargon\">API_KEY</button>')",
                "raw dev code API_KEY",
            ),
            (
                "document.body.insertAdjacentHTML('beforeend', '<button id=\"neg-jargon\">IBAN</button>')",
                "raw dev code IBAN",
            ),
            (
                "document.body.insertAdjacentHTML('beforeend', '<button id=\"neg-jargon\">Vault Ledger</button>')",
                "Vault Ledger",
            ),
            (
                "document.body.insertAdjacentHTML('beforeend', '<textarea id=\"neg-jargon\" placeholder=\"Paste to Sanitize Prompt\"></textarea>')",
                "placeholder jargon",
            ),
            (
                "document.body.insertAdjacentHTML('beforeend', '<button id=\"neg-jargon\" aria-label=\"Rulebook\">?</button>')",
                "aria-label jargon",
            ),
            (
                "document.body.insertAdjacentHTML('beforeend', '<button id=\"neg-jargon\" title=\"Zero Egress\">?</button>')",
                "title attr jargon",
            ),
            (
                "document.body.insertAdjacentHTML('beforeend', '<input id=\"neg-jargon\" type=\"button\" value=\"Sanitize Prompt\">')",
                "input[type=button] value jargon",
            ),
        ]
        for js_inject, desc in purity_probes:
            page.evaluate(f"() => {{ {js_inject}; }}")
            caught_jargon = False
            try:
                verify_russian_purity(page)
            except AssertionError:
                caught_jargon = True
            assert caught_jargon, f"Negative monitor check failed: verify_russian_purity missed {desc}"
            page.evaluate("() => document.getElementById('neg-jargon')?.remove()")

        # Confirm accepted localized Russian IBAN label passes verify_russian_purity()
        page.evaluate(
            "() => { document.body.insertAdjacentHTML('beforeend', '<button id=\"pos-iban-label\">Счета (IBAN) (1)</button>'); }"
        )
        try:
            verify_russian_purity(page)
        finally:
            page.evaluate("() => document.getElementById('pos-iban-label')?.remove()")

        # (c5) Inner-<span> ellipsis clipping, vertical clipping, label[data-testid='upload-file-btn'] clipping, and opacity:0 non-FP
        page.evaluate(
            """() => {
                const b = document.createElement('button');
                b.id = 'neg-inner-span-clip';
                b.style.display = 'inline-flex';
                b.style.width = '60px';
                b.style.overflow = 'hidden';
                const sp = document.createElement('span');
                sp.style.minWidth = '0';
                sp.style.overflow = 'hidden';
                sp.style.textOverflow = 'ellipsis';
                sp.style.whiteSpace = 'nowrap';
                sp.textContent = 'VeryLongInnerSpanButtonLabel';
                b.appendChild(sp);
                document.body.appendChild(b);
            }"""
        )
        caught_inner_span_clip = False
        try:
            verify_no_overlap_or_clipping(page)
        except AssertionError:
            caught_inner_span_clip = True
        assert caught_inner_span_clip, "Negative monitor check failed: missed inner-<span> ellipsis clipping"
        page.evaluate("() => document.getElementById('neg-inner-span-clip')?.remove()")

        page.evaluate(
            """() => {
                const b = document.createElement('button');
                b.id = 'neg-vert-clip';
                b.style.width = '90px';
                b.style.height = '20px';
                b.style.overflow = 'hidden';
                b.style.whiteSpace = 'normal';
                b.style.lineHeight = '18px';
                b.textContent = 'Первая строка Вторая строка Третья строка';
                document.body.appendChild(b);
            }"""
        )
        caught_vert_clip = False
        try:
            verify_no_overlap_or_clipping(page)
        except AssertionError:
            caught_vert_clip = True
        assert caught_vert_clip, "Negative monitor check failed: missed vertical clipping"
        page.evaluate("() => document.getElementById('neg-vert-clip')?.remove()")

        page.evaluate(
            """() => {
                const wrap = document.createElement('div');
                wrap.id = 'neg-opacity-zero-wrap';
                wrap.style.opacity = '0';
                wrap.style.position = 'fixed';
                wrap.style.left = '12px';
                wrap.style.top = '12px';
                wrap.style.zIndex = '999';
                const b = document.createElement('button');
                b.textContent = 'Скрытая кнопка';
                wrap.appendChild(b);
                document.body.appendChild(wrap);
            }"""
        )
        try:
            verify_no_overlap_or_clipping(page)
        finally:
            page.evaluate("() => document.getElementById('neg-opacity-zero-wrap')?.remove()")

        # (c6) .sr-only span inside accessible icon <button> must NOT trigger false-positive clipping,
        # while a visible truncated <span> inside <button> MUST still fail.
        page.evaluate(
            """() => {
                const b = document.createElement('button');
                b.id = 'neg-sr-only-btn';
                b.type = 'button';
                b.setAttribute('aria-label', 'Закрыть');
                const sr = document.createElement('span');
                sr.className = 'sr-only';
                sr.style.cssText = 'position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;';
                sr.textContent = 'Закрыть окно настроек';
                const icon = document.createElement('span');
                icon.setAttribute('aria-hidden', 'true');
                icon.textContent = '×';
                b.append(sr, icon);
                document.body.appendChild(b);
            }"""
        )
        try:
            verify_no_overlap_or_clipping(page)
        finally:
            page.evaluate("() => document.getElementById('neg-sr-only-btn')?.remove()")

        page.evaluate(
            """() => {
                const b = document.createElement('button');
                b.id = 'neg-sr-only-control-trunc';
                b.type = 'button';
                b.style.cssText = 'display:inline-flex;width:60px;overflow:hidden;';
                const sp = document.createElement('span');
                sp.style.cssText = 'min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
                sp.textContent = 'Очень длинная обрезанная подпись кнопки';
                b.appendChild(sp);
                document.body.appendChild(b);
            }"""
        )
        caught_trunc_after_sr_check = False
        try:
            verify_no_overlap_or_clipping(page)
        except AssertionError:
            caught_trunc_after_sr_check = True
        finally:
            page.evaluate("() => document.getElementById('neg-sr-only-control-trunc')?.remove()")
        assert caught_trunc_after_sr_check, (
            "Negative monitor check failed: truncated <span> inside <button> was not caught"
        )
    finally:
        console.detach()
        net.detach()
        ctx.close()

    # (d) Exact CSP directive rejection check
    class _PermissiveCspHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; connect-src 'self' https://evil.com; object-src 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            _ = (format, args)

    bad_srv = _ThreadingServer(("127.0.0.1", 0), _PermissiveCspHandler)
    bad_port = int(bad_srv.server_address[1])
    bad_thread = threading.Thread(target=bad_srv.serve_forever, daemon=True)
    bad_thread.start()
    try:
        rejected_permissive_csp = False
        try:
            verify_csp_and_security_headers(f"http://127.0.0.1:{bad_port}")
        except AssertionError:
            rejected_permissive_csp = True
        assert rejected_permissive_csp, "Negative check failed: verify_csp_and_security_headers accepted permissive connect-src"
    finally:
        bad_srv.shutdown()
        bad_srv.server_close()

    # (e) Chip disambiguation (HIGH_ENTROPY vs ENV_SECRET), category-chips header scoping, vault row collision, telemetry, and <aside> file input exclusion
    ctx_dom = browser.new_context()
    p_dom = ctx_dom.new_page()
    try:
        p_dom.set_content(
            """<!doctype html><html><body>
            <aside data-drawer="rules"><input id="aside-file" type="file"></aside>
            <main>
              <button type="button">ENV_SECRET (1)</button>
              <button type="button">Secrets (0)</button>
              <button type="button">High-Entropy (3)</button>
              <input id="cb-phone" type="checkbox" aria-label="PHONE 2">
              <input id="wb-file" type="file">
            </main>
            </body></html>"""
        )
        ui_dom = PromptVeilUI(p_dom)
        assert ui_dom.get_category_chip_count("ENV_SECRET") == 1
        assert ui_dom.get_category_chip_count("HIGH_ENTROPY") == 0
        assert ui_dom.get_category_chip_count("PHONE") == 2
        assert ui_dom.get_workbench_file_input().get_attribute("id") == "wb-file"

        # Strict category-chips scoping (must not leak to <header> open-rulebook-btn 'Свои слова (2)'),
        # two-pass vault entity matching, <label><input> toggle detection, telemetry first-match,
        # and empty-placeholder stripping in sanitized-output.
        p_dom.set_content(
            """<!doctype html><html><body>
            <header>
              <button type="button" data-testid="open-rulebook-btn">Свои слова (2)</button>
            </header>
            <main data-testid="panel-sanitize">
              <div data-testid="category-chips">
                <button type="button" data-category="EMAIL" data-count="1">Почта (1)</button>
              </div>
              <span data-testid="telemetry-masked-count">Скрыто: 1 (пропущено: 0)</span>
              <div data-testid="sanitized-output"><span class="empty-placeholder">Здесь появится безопасный текст</span></div>
              <div data-testid="entity-vault-list">
                <div data-testid="vault-item" data-token="[EMAIL_1]">
                  <span>[EMAIL_1]</span>
                  <span data-testid="vault-value" data-value="ba@example.com">••••••••</span>
                  <label data-testid="vault-item-toggle"><input type="checkbox" checked></label>
                </div>
                <div data-testid="vault-item" data-token="[EMAIL_2]">
                  <span>[EMAIL_2]</span>
                  <span data-testid="vault-value" data-value="a@example.com">••••••••</span>
                  <label data-testid="vault-item-toggle"><input type="checkbox" checked></label>
                </div>
              </div>
            </main>
            </body></html>"""
        )
        p_dom.evaluate(
            """() => {
                document.querySelectorAll('[data-testid="vault-item-toggle"] input').forEach(cb => {
                    cb.addEventListener('change', () => {});
                });
            }"""
        )
        assert ui_dom.get_category_chip_count("CUSTOM") == 0
        assert ui_dom.get_telemetry_masked_count() == 1
        assert ui_dom.get_sanitize_output_text() == ""
        ui_dom.toggle_vault_entity("a@example.com")
        rows_dom = ui_dom.get_vault_rows()
        assert rows_dom[0].enabled is True and rows_dom[1].enabled is False
    finally:
        ctx_dom.close()

    print(
        "[self-test] Negative & edge monitor checks OK "
        "(http/ws egress, console/pageerror, 390x844 overflow, overlap/clipping, RU purity, exact CSP, chip disambiguation)"
    )


def run_self_test(browser_pref: str, headed: bool) -> int:
    """Execute full --mode self-test verification."""
    _step_py_compile()
    _step_collect_only()

    handler = functools.partial(_SmokeRequestHandler, directory=str(FIXTURES_DIR))
    server = _ThreadingServer(("127.0.0.1", 0), handler)
    port = int(server.server_address[1])
    base_url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    pw = sync_playwright().start()
    try:
        browser = _launch_browser(pw, browser_pref, headed)
        try:
            _run_positive_smoke_checks(browser, base_url)
            _run_isolation_check(browser, base_url)
            _run_negative_monitor_checks(browser, base_url)
        finally:
            browser.close()
    finally:
        pw.stop()
        server.shutdown()
        server.server_close()

    print("[self-test] ALL CHECKS PASSED")
    return 0


def run_live(args: argparse.Namespace) -> int:
    """Execute live pytest suite against running, auto-started FastAPI, or --static-only server."""
    cmd: list[str] = [
        sys.executable,
        "-m",
        "pytest",
        str(E2E_DIR),
        "-v",
        "--base-url",
        args.base_url,
        "--browser",
        args.browser,
    ]
    if args.headed:
        cmd.append("--headed")
    if args.start_server:
        cmd.append("--start-server")
    if args.static_only:
        cmd.append("--static-only")
    if args.tier == "acceptance":
        cmd.extend(["-m", "acceptance"])
    elif args.tier != "all":
        cmd.extend(["-m", f"tier{args.tier}"])
    if args.filter:
        normalized = args.filter.replace("-", "_")
        cmd.extend(["-k", normalized])

    t0 = time.monotonic()
    proc = subprocess.run(cmd, check=False)
    elapsed = round(time.monotonic() - t0, 3)

    if args.report_json:
        report_path = Path(args.report_json)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        summary: dict[str, Any] = {
            "mode": "live",
            "base_url": args.base_url,
            "static_only": bool(args.static_only),
            "tier": args.tier,
            "filter": args.filter,
            "browser": args.browser,
            "returncode": proc.returncode,
            "duration_seconds": elapsed,
            "status": "passed" if proc.returncode == 0 else "failed",
        }
        report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return int(proc.returncode)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PromptVeil Opaque-Box E2E Runner")
    parser.add_argument(
        "--mode",
        choices=["self-test", "live"],
        default="self-test",
        help="Execution mode (self-test against local smoke contract, or live against server)",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Target app URL")
    parser.add_argument(
        "--tier",
        choices=["all", "1", "2", "3", "4", "5", "acceptance"],
        default="all",
    )
    parser.add_argument("--filter", default="", help="Substring/test-ID filter (e.g. T1-F1-01)")
    parser.add_argument("--browser", choices=["auto", "chrome", "msedge"], default="auto")
    parser.add_argument("--headed", action="store_true", help="Launch visible browser window")
    parser.add_argument("--start-server", action="store_true", help="Auto-start local uvicorn")
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Serve app/static/ directly without /health (Netlify parity)",
    )
    parser.add_argument("--report-json", default="", help="Optional path for live summary JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.mode == "self-test":
        return run_self_test(args.browser, args.headed)
    return run_live(args)


if __name__ == "__main__":
    raise SystemExit(main())
