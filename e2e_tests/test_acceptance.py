"""Product Acceptance Gate Tests (R1/R2/R3 + Stages A-E: ACC-01..ACC-13)."""

from __future__ import annotations

import re
from typing import Any

import pytest
from playwright.sync_api import Browser

from conftest import E2E_DIR, E2ESession, STATIC_APP_DIR, TempIODirs, start_static_dir_server
from locators import PromptVeilUI
from monitors import (
    ConsoleErrorMonitor,
    NetworkMonitor,
    capture_viewport_screenshot,
    fetch_http_response,
    verify_csp_and_security_headers,
    verify_health_endpoint,
    verify_responsive_layout,
    verify_russian_purity,
)


pytestmark = [pytest.mark.acceptance]

ACCEPTANCE_SCREENSHOTS_DIR = E2E_DIR / "artifacts" / "acceptance"


def test_ACC_01_default_russian_ui_and_zero_jargon_purity(e2e_session: E2ESession) -> None:
    """R1: Default load uses <html lang='ru'>, natural Russian copy, and zero technical jargon."""
    page = e2e_session.page
    ui = e2e_session.ui

    assert ui.get_document_lang().lower() == "ru"
    assert ui.get_zero_egress_pill().is_visible()
    assert re.search(r"[А-Яа-яЁё]", ui.get_zero_egress_pill().inner_text())
    assert re.search(r"[А-Яа-яЁё]", ui.get_hero_summary_text())

    # R1 & R2: No shield/check paths and no obsolete local-browser nagging copy
    body_text = page.locator("body").inner_text()
    for obsolete in (
        "Только в браузере",
        "Все проверки выполняются локально в вашем браузере",
        "ничего не отправляется на сервер",
    ):
        assert obsolete not in body_text, f"Obsolete phrase {obsolete!r} visible in body"
    assert page.locator("svg.brand-emblem polygon").count() >= 2
    assert page.locator("svg.footer-brand-emblem polygon").count() >= 2
    assert "M16 5L25 9v7" not in page.content()

    for testid in (
        "mode-sanitize",
        "mode-rehydrate",
        "open-rulebook-btn",
        "open-audit-btn",
    ):
        el = page.locator(f"[data-testid='{testid}']").first
        assert el.is_visible(), f"Expected [data-testid='{testid}'] to be visible"
        assert re.search(r"[А-Яа-яЁё]", el.inner_text()), f"Expected Russian label on {testid}"

    verify_russian_purity(page)

    # Populate all sensitive categories and re-check UI chrome purity
    payload = (
        "Почта ivan@example.ru, тел +7 (916) 555-01-23, "
        "карта 4111 1111 1111 1111, IP 203.0.113.42, "
        "DB_PASS=Sup3rSynthPass!99, токен v9Kp2mQx7Rt4Lz8Nw3Yc6Bf1"
    )
    out = ui.sanitize_text(payload)
    assert "[EMAIL_1]" in out and "[PHONE_1]" in out and "[CARD_1]" in out
    verify_russian_purity(page)

    # Check Step 2 and both drawers for Russian purity
    ui.click_go_rehydrate()
    verify_russian_purity(page)
    ui.click_back_sanitize()

    ui.open_rulebook_drawer()
    verify_russian_purity(page)
    ui.close_open_drawer()

    ui.open_audit_drawer()
    verify_russian_purity(page)
    ui.close_open_drawer()

    # Check new R2/R4/R5 modals for Russian purity
    ui.open_privacy_proof_modal("header")
    verify_russian_purity(page)
    ui.close_active_modal()

    ui.open_plan_request_modal("pro")
    verify_russian_purity(page)
    ui.close_active_modal()

    ui.open_privacy_policy_modal()
    verify_russian_purity(page)
    ui.close_active_modal()

    e2e_session.console.assert_no_errors()


def test_ACC_02_language_switcher_ru_en_and_persistence(e2e_session: E2ESession) -> None:
    """R1 & Stage B: RU | EN toggle, hreflang, meta/OG/Twitter & theme aria-label sync, /en/ route, and mobile toggle."""
    page = e2e_session.page
    ui = e2e_session.ui

    assert page.locator("[data-testid='lang-switch']").first.is_visible()
    assert page.locator("[data-testid='lang-ru']").first.is_visible()
    assert page.locator("[data-testid='lang-en']").first.is_visible()
    assert ui.get_document_lang().lower() == "ru"

    for hreflang in ("ru", "en", "x-default"):
        assert page.locator(f"link[rel='alternate'][hreflang='{hreflang}']").count() >= 1

    def _meta_snapshot() -> dict[str, str]:
        return dict(
            page.evaluate(
                """() => ({
                    desc: document.querySelector("meta[name='description']")?.getAttribute('content') || '',
                    ogTitle: document.querySelector("meta[property='og:title']")?.getAttribute('content') || '',
                    ogDesc: document.querySelector("meta[property='og:description']")?.getAttribute('content') || '',
                    ogLocale: document.querySelector("meta[property='og:locale']")?.getAttribute('content') || '',
                    twDesc: document.querySelector("meta[name='twitter:description']")?.getAttribute('content') || '',
                    themeLabel: document.querySelector("[data-testid='theme-toggle-btn']")?.getAttribute('aria-label') || '',
                })"""
            )
        )

    ru_meta = _meta_snapshot()
    ru_tab_label = page.locator("[data-testid='mode-sanitize']").first.inner_text()
    page.evaluate("() => { window.__pvNoReloadMarker = 1; }")

    ui.switch_language("en")
    assert page.evaluate("() => window.__pvNoReloadMarker") == 1, "Language switch must not reload page"
    assert ui.get_document_lang().lower() == "en"
    assert ui.get_stored_language() == "en"
    en_tab_label = page.locator("[data-testid='mode-sanitize']").first.inner_text()
    assert en_tab_label != ru_tab_label
    assert re.search(r"[A-Za-z]", en_tab_label)

    en_meta = _meta_snapshot()
    assert en_meta["desc"] and en_meta["desc"] != ru_meta["desc"]
    assert en_meta["ogTitle"] != ru_meta["ogTitle"]
    assert en_meta["ogDesc"] != ru_meta["ogDesc"]
    assert en_meta["ogLocale"].lower().startswith("en")
    assert en_meta["twDesc"] != ru_meta["twDesc"]
    assert en_meta["themeLabel"] != ru_meta["themeLabel"]

    page.reload(wait_until="networkidle")
    assert ui.get_document_lang().lower() == "en"
    assert ui.get_stored_language() == "en"
    assert page.locator("[data-testid='mode-sanitize']").first.inner_text() == en_tab_label

    ui.switch_language("ru")
    assert ui.get_document_lang().lower() == "ru"
    assert ui.get_stored_language() == "ru"
    assert _meta_snapshot()["themeLabel"] == ru_meta["themeLabel"]
    verify_russian_purity(page)

    page.reload(wait_until="networkidle")
    assert ui.get_document_lang().lower() == "ru"
    assert ui.get_stored_language() == "ru"
    verify_russian_purity(page)

    # Mobile single toggle [data-testid='lang-mobile-toggle'] at 390x844
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_timeout(120)
    assert page.locator("[data-testid='lang-mobile-toggle']").is_visible()
    ui.switch_language("en")
    assert ui.get_document_lang().lower() == "en"
    ui.switch_language("ru")
    assert ui.get_document_lang().lower() == "ru"
    page.set_viewport_size({"width": 1440, "height": 900})

    # Static /en/ route check
    en_status, _, en_body = fetch_http_response(f"{e2e_session.base_url}/en/")
    assert en_status == 200
    assert '<html lang="en"' in en_body.lower()
    e2e_session.net.phase = "load"
    page.goto(f"{e2e_session.base_url}/en/", wait_until="networkidle")
    e2e_session.net.assert_clean_load()
    assert ui.get_document_lang().lower() == "en"
    e2e_session.console.assert_no_errors()


def test_ACC_03_beginner_full_cycle_all_pii_and_zero_egress(e2e_session: E2ESession) -> None:
    """R1 & R3: Full cycle with email, phone, card, API key, and custom word with 0 network egress."""
    ui = e2e_session.ui
    secrets = [
        "ivan.petrov@example.ru",
        "+7 (916) 555-01-23",
        "4111 1111 1111 1111",
        "sk-proj-TestSynthKey000111222333444",
        "ООО «Север»",
    ]

    ui.add_custom_rule("ООО «Север»")
    ui.close_open_drawer()

    raw_prompt = (
        "Привет! Компания ООО «Север», контакт ivan.petrov@example.ru, "
        "телефон +7 (916) 555-01-23, карта 4111 1111 1111 1111, "
        "ключ sk-proj-TestSynthKey000111222333444. Подготовь письмо."
    )
    masked = ui.sanitize_text(raw_prompt)
    for tok in ("[CUSTOM_1]", "[EMAIL_1]", "[PHONE_1]", "[CARD_1]", "[API_KEY_1]"):
        assert tok in masked, f"Missing expected token {tok} in {masked!r}"
    for secret in secrets:
        assert secret not in masked, f"Raw secret {secret!r} leaked in masked output"

    rows = ui.get_vault_rows()
    assert len(rows) == 5

    ui.click_copy_output()
    clip = ui.read_clipboard_text()
    fb = ui.get_copy_feedback_text()
    assert fb, "Expected visible copy confirmation feedback after clicking copy"
    assert clip is not None, (
        "Expected navigator.clipboard.readText() to succeed with granted clipboard permissions"
    )
    assert clip == masked, f"Clipboard content mismatch: expected {masked!r}, got {clip!r}"

    ui.click_go_rehydrate()
    assert ui.get_rehydrate_input().is_visible()

    ai_reply = f"Черновик ответа ИИ:\n{clip}"
    restored = ui.rehydrate_text(ai_reply)
    for secret in secrets:
        assert secret in restored, f"Original value {secret!r} missing in restored reply"
    assert ui.get_unresolved_tokens() == []

    e2e_session.net.assert_zero_egress(secrets)
    e2e_session.console.assert_no_errors()


def test_ACC_04_responsive_layout_no_overlap_clipping_and_screenshots(e2e_session: E2ESession) -> None:
    """R2: Desktop (1440x900) and mobile (390x844) have zero overflow/clipping/overlap + screenshots."""
    page = e2e_session.page
    ui = e2e_session.ui

    for label_prefix, width, height in (("desktop", 1440, 900), ("mobile", 390, 844)):
        ui.switch_mode("sanitize")
        if ui.get_prompt_input().input_value():
            ui.click_clear_input()
        verify_responsive_layout(page, width, height)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_empty",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
        )

        ui.select_preset("bilingual_cis_hr")
        verify_responsive_layout(page, width, height)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_step1_masked",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
        )

        masked = ui.get_sanitize_output_text()
        ui.click_go_rehydrate()
        ui.rehydrate_text(masked)
        verify_responsive_layout(page, width, height)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_step2_restored",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
        )

        # Verify Step 2 unresolved-warning banner layout at both viewports
        ui.rehydrate_text(f"{masked}\n[JWT_99] [API_KEY_88]")
        unresolved = ui.get_unresolved_tokens()
        assert "[JWT_99]" in unresolved and "[API_KEY_88]" in unresolved
        verify_responsive_layout(page, width, height)

        ui.switch_mode("sanitize")
        if ui.get_rulebook_badge_count() < 3:
            for term, tag in (
                ("ООО «Север-Консалтинг»", "ORG"),
                ("Проект «Горизонт-2026»", "PROJECT"),
                ("Екатерина Владимировна Соколова", "PERSON"),
            ):
                ui.add_custom_rule(term, label=tag)
        rulebook_drawer = ui.open_rulebook_drawer()
        assert rulebook_drawer.locator("[data-testid='rules-list'] > *").count() >= 3
        if width <= 639:
            rb_box = rulebook_drawer.bounding_box()
            assert rb_box is not None and rb_box["x"] >= -0.5 and (rb_box["x"] + rb_box["width"]) <= 390.5
        verify_responsive_layout(page, width, height)
        page.wait_for_timeout(250)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_rulebook_drawer",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
            full_page=False,
        )
        ui.close_open_drawer()

        audit_drawer = ui.open_audit_drawer()
        assert len(ui.get_audit_hashes()) >= 1
        assert audit_drawer.locator("[data-testid='audit-list'] > *").count() >= 1
        if width <= 639:
            ad_box = audit_drawer.bounding_box()
            assert ad_box is not None and ad_box["x"] >= -0.5 and (ad_box["x"] + ad_box["width"]) <= 390.5
        verify_responsive_layout(page, width, height)
        page.wait_for_timeout(250)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_audit_drawer",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
            full_page=False,
        )
        ui.close_open_drawer()

        # Verify compact mobile header <= 64px & Stage C mobile UX contracts
        if width <= 639:
            top_rail_h = page.locator("header.top-rail").evaluate("el => el.getBoundingClientRect().height")
            assert top_rail_h <= 64.5, f"Mobile top-rail height exceeded 64px: {top_rail_h}"
            proof_box = page.locator("[data-testid='brand-badge']").bounding_box()
            assert proof_box is not None and proof_box["width"] >= 43.5 and proof_box["height"] >= 43.5
            more_box = page.locator("[data-testid='mobile-more-btn']").bounding_box()
            assert more_box is not None and more_box["width"] >= 43.5 and more_box["height"] >= 43.5
            lang_m_box = page.locator("[data-testid='lang-mobile-toggle']").bounding_box()
            assert lang_m_box is not None and lang_m_box["width"] >= 43.5 and lang_m_box["height"] >= 43.5
            assert page.locator("[data-testid='mode-rehydrate'] [data-i18n='nav.step2']").inner_text().strip() == "2. Вернуть"

            ui.ensure_vault_expanded()
            h_expanded = page.evaluate("() => document.documentElement.scrollHeight")
            if not ui.is_vault_collapsed():
                ui.toggle_vault_collapse()
            assert ui.is_vault_collapsed() is True
            h_collapsed = page.evaluate("() => document.documentElement.scrollHeight")
            assert h_collapsed < h_expanded
            ui.ensure_vault_expanded()

            assert ui.get_mobile_sticky_cta().is_visible()
            for idx in range(page.locator(".ai-launcher-pill").count()):
                p_box = page.locator(".ai-launcher-pill").nth(idx).bounding_box()
                assert p_box is not None and p_box["height"] >= 43.5
            footer_controls = page.locator("footer a, footer button")
            for idx in range(footer_controls.count()):
                fc = footer_controls.nth(idx)
                if fc.is_visible():
                    f_box = fc.bounding_box()
                    assert f_box is not None and f_box["height"] >= 43.5

        # Pricing + Trust Footer viewport screenshot & layout check
        page.locator("[data-testid='pricing-section']").scroll_into_view_if_needed()
        page.wait_for_timeout(150)
        verify_responsive_layout(page, width, height)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_pricing_footer",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
            full_page=False,
        )

        # Zero-Retention Proof modal screenshot & layout check
        ui.open_privacy_proof_modal("footer")
        verify_responsive_layout(page, width, height)
        page.wait_for_timeout(200)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_proof_modal",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
            full_page=False,
        )
        ui.close_active_modal()

        # Plan Request modal screenshot & layout check
        ui.open_plan_request_modal("pro")
        page.locator("[data-testid='plan-req-name']").fill("ООО «Вектор»")
        page.locator("[data-testid='plan-req-contact']").fill("@supv1rus")
        page.locator("[data-testid='plan-req-submit-btn']").click()
        assert page.locator("[data-testid='plan-request-result']").is_visible()
        verify_responsive_layout(page, width, height)
        page.wait_for_timeout(200)
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_request_modal",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
            full_page=False,
        )
        ui.close_active_modal()

    e2e_session.net.assert_zero_egress()
    e2e_session.console.assert_no_errors()


def test_ACC_05_fastapi_and_static_only_netlify_parity(
    raw_session: E2ESession,
    playwright_browser: Browser,
    temp_io_dir: TempIODirs,
    request: pytest.FixtureRequest,
) -> None:
    """R3: Both FastAPI preview and static-only app/static/ (no /health) run with 0 console & 4xx/5xx errors."""
    # 1. Verify active FastAPI / base_url target
    raw_session.page.goto(f"{raw_session.base_url}/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.console.assert_no_errors()
    verify_csp_and_security_headers(raw_session.base_url)

    if request.config.getoption("--static-only"):
        health_status, _, _ = fetch_http_response(f"{raw_session.base_url}/health")
        assert health_status == 404, (
            f"Static-only mode must return 404 on /health, got {health_status}"
        )
    else:
        verify_health_endpoint(raw_session.base_url)

    # 2. Verify static-only app/static/ serving (simulating Netlify without /health)
    with start_static_dir_server(STATIC_APP_DIR) as static_url:
        st_health, _, _ = fetch_http_response(f"{static_url}/health")
        assert st_health == 404, f"Static-only server must not expose /health, got {st_health}"
        verify_csp_and_security_headers(static_url)

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
        page = ctx.new_page()
        net = NetworkMonitor(page=page)
        console = ConsoleErrorMonitor(page=page)
        net.attach()
        console.attach()
        try:
            page.goto(f"{static_url}/", wait_until="networkidle")
            net.assert_clean_load()
            console.assert_no_errors()
            net.start_interactive_phase()

            ui = PromptVeilUI(page)
            masked = ui.sanitize_text("Контакт static.user@example.ru тел +7 (916) 555-01-23")
            assert "[EMAIL_1]" in masked and "[PHONE_1]" in masked
            assert "static.user@example.ru" not in masked

            restored = ui.rehydrate_text("Ответ для [EMAIL_1] ([PHONE_1])")
            assert "static.user@example.ru" in restored
            assert "+7 (916) 555-01-23" in restored

            net.assert_zero_egress(["static.user@example.ru", "+7 (916) 555-01-23"])
            console.assert_no_errors()
        finally:
            console.detach()
            net.detach()
            ctx.close()
            _ = temp_io_dir


def test_ACC_06_zero_retention_proof_and_session_reset(e2e_session: E2ESession) -> None:
    """R2: Live Zero-Retention Proof scan, session reset to 0, and pagehide RAM/DOM scrub."""
    page = e2e_session.page
    ui = e2e_session.ui

    ui.add_custom_rule("ООО «Горизонт»")
    ui.close_open_drawer()
    secret_email = "proof.user@example.ru"
    masked = ui.sanitize_text(f"Компания ООО «Горизонт», почта {secret_email}")
    assert "[CUSTOM_1]" in masked and "[EMAIL_1]" in masked

    # Open from header and run live self-test
    modal = ui.open_privacy_proof_modal("header")
    ui.run_privacy_proof_check()
    modal_text = modal.inner_text()
    assert "0 запросов" in modal_text
    assert "connect-src 'self'" in modal_text
    assert "0 байт" in modal_text
    assert "0 трекеров" in modal_text
    assert "нарушений CSP в документе приложения: 0" in modal_text
    assert modal.locator("a[href='https://github.com/Aquanti/promptveil']").count() >= 1
    assert page.locator("[data-testid='site-footer'] a[href='https://github.com/Aquanti/promptveil']").count() >= 1
    ram_note = page.locator("[data-testid='proof-ram-note']").inner_text()
    assert "активных замен — 2" in ram_note

    # Instant reset session to 0 inside Proof modal (toast must render above modal/backdrop)
    ui.click_reset_session_to_zero("modal")
    assert page.locator("[data-testid='proof-ram-note']").inner_text().endswith("активных замен — 0.")
    z_layer = page.evaluate(
        """() => {
            const toast = document.querySelector("[data-testid='status-banner']");
            const modalEl = document.querySelector("[data-testid='modal-privacy-proof']");
            return {
                toastVisible: Boolean(toast && !toast.hidden),
                toastZ: toast ? Number(getComputedStyle(toast).zIndex || 0) : 0,
                modalZ: modalEl ? Number(getComputedStyle(modalEl).zIndex || 0) : 0,
            };
        }"""
    )
    assert z_layer["toastVisible"] is True
    assert z_layer["toastZ"] > z_layer["modalZ"]
    ui.close_active_modal()

    assert ui.get_prompt_input().input_value() == ""
    assert ui.get_sanitize_output_text() == ""
    assert ui.get_vault_rows() == []
    # Preferences & custom rules in localStorage remain preserved
    assert ui.get_rulebook_badge_count() == 1

    # Re-open from footer trigger and check pagehide + pageshow (bfcache) scrub
    ui.open_privacy_proof_modal("footer")
    ui.close_active_modal()
    ui.sanitize_text("Снова secret2@example.ru")
    assert len(ui.get_vault_rows()) == 1
    page.evaluate("() => window.dispatchEvent(new Event('pagehide'))")
    assert ui.get_prompt_input().input_value() == ""
    assert ui.get_sanitize_output_text() == ""
    assert ui.get_vault_rows() == []
    assert page.locator("[data-testid='telemetry-masked-count']").get_attribute("data-count") == "0"
    assert page.locator("[data-testid='copy-sanitized-btn']").is_disabled()
    assert page.locator("[data-testid='download-sanitized-btn']").is_disabled()
    assert page.locator("[data-testid='copy-goto-step2-btn']").is_disabled()

    # bfcache restoration via pageshow(persisted=true) also scrubs session while preserving localStorage prefs
    ui.sanitize_text("Снова secret3@example.ru")
    assert len(ui.get_vault_rows()) == 1
    assert not page.locator("[data-testid='copy-goto-step2-btn']").is_disabled()
    page.evaluate(
        """() => {
            const ev = new Event('pageshow');
            Object.defineProperty(ev, 'persisted', { value: true });
            window.dispatchEvent(ev);
        }"""
    )
    assert ui.get_prompt_input().input_value() == ""
    assert ui.get_sanitize_output_text() == ""
    assert ui.get_vault_rows() == []
    assert page.locator("[data-testid='telemetry-masked-count']").get_attribute("data-count") == "0"
    assert page.locator("[data-testid='copy-sanitized-btn']").is_disabled()
    assert page.locator("[data-testid='download-sanitized-btn']").is_disabled()
    assert page.locator("[data-testid='copy-goto-step2-btn']").is_disabled()
    assert ui.get_rulebook_badge_count() == 1
    assert page.evaluate("() => Boolean(localStorage.getItem('promptveil_rules_v1'))")

    # Dynamic tracker badge count on anomaly (RU pluralizeRu & EN singular/plural)
    page.evaluate("() => { window.gtag = () => {}; }")
    try:
        modal = ui.open_privacy_proof_modal("header")
        ru_modal_txt = modal.inner_text()
        assert "1 трекер" in ru_modal_txt
        assert "1 трекеров" not in ru_modal_txt
        assert page.locator("#proof-summary-card.proof-summary-card--warn").count() == 1
        ui.close_active_modal()

        # Multi-count pluralizeRu check (2 -> "2 трекера", 5 -> "5 трекеров")
        page.evaluate("() => { window.fbq = () => {}; }")
        modal = ui.open_privacy_proof_modal("header")
        assert "2 трекера" in modal.inner_text()
        ui.close_active_modal()

        ui.switch_language("en")
        modal = ui.open_privacy_proof_modal("header")
        en_modal_txt = modal.inner_text()
        assert "2 trackers" in en_modal_txt
        assert "CSP violations in app document: 0" in en_modal_txt
        ui.close_active_modal()

        page.evaluate("() => { delete window.fbq; }")
        modal = ui.open_privacy_proof_modal("header")
        assert "1 tracker" in modal.inner_text()
        assert "1 trackers" not in modal.inner_text()
        ui.close_active_modal()
    finally:
        page.evaluate("() => { delete window.gtag; delete window.fbq; }")
        ui.switch_language("ru")

    e2e_session.net.assert_zero_egress([secret_email, "secret2@example.ru", "secret3@example.ru"])
    e2e_session.console.assert_no_errors()


def test_ACC_07_ux_paste_and_copy_goto_step2(e2e_session: E2ESession) -> None:
    """R3: Step 1 & Step 2 Paste buttons (with fallback) and Copy & Go to Step 2 combo CTA."""
    page = e2e_session.page
    ui = e2e_session.ui

    sample = "Заявка от maria.ivanova@example.ru, тел +7 (916) 555-01-44"
    page.evaluate("async (txt) => await navigator.clipboard.writeText(txt)", sample)
    ui.click_paste_raw()
    assert ui.get_prompt_input().input_value() == sample
    masked = ui.get_sanitize_output_text()
    assert "[EMAIL_1]" in masked and "[PHONE_1]" in masked

    # Combo button copies masked output and switches to Step 2
    ui.click_copy_goto_step2()
    assert ui.get_rehydrate_input().is_visible()
    clip = ui.read_clipboard_text()
    assert clip == masked

    # Paste AI reply in Step 2 via Paste button and restore
    ai_reply = f"Готовый ответ для клиента:\n{masked}"
    page.evaluate("async (txt) => await navigator.clipboard.writeText(txt)", ai_reply)
    ui.click_paste_rehydrate()
    assert ui.get_rehydrate_input().input_value() == ai_reply

    restored = ui.rehydrate_text(ai_reply)
    assert "maria.ivanova@example.ru" in restored
    assert "+7 (916) 555-01-44" in restored

    # Fast-click (<140ms debounce) on #copy-goto-step2-btn must flush and copy fresh masked text
    ui.click_back_sanitize()
    page.evaluate(
        """() => {
            const inp = document.getElementById('raw-prompt-input');
            inp.value = 'Срочно для fast.click@example.ru';
            inp.dispatchEvent(new Event('input', { bubbles: true }));
            document.getElementById('copy-goto-step2-btn').click();
        }"""
    )
    page.wait_for_timeout(120)
    assert ui.get_rehydrate_input().is_visible()
    fast_clip = ui.read_clipboard_text() or ""
    assert "Срочно для [EMAIL_" in fast_clip
    assert "fast.click@example.ru" not in fast_clip
    assert "maria.ivanova@example.ru" not in fast_clip

    # Unchecked live-sanitize toggle + #copy-goto-step2-btn must also mask current rawText before copy
    ui.click_back_sanitize()
    live_toggle = page.locator("#live-sanitize-toggle")
    if live_toggle.is_checked():
        live_toggle.uncheck()
    page.evaluate(
        """() => {
            const inp = document.getElementById('raw-prompt-input');
            inp.value = 'Офлайн для manual.sync@example.ru';
            inp.dispatchEvent(new Event('input', { bubbles: true }));
            document.getElementById('copy-goto-step2-btn').click();
        }"""
    )
    page.wait_for_timeout(120)
    assert ui.get_rehydrate_input().is_visible()
    manual_clip = ui.read_clipboard_text() or ""
    assert "Офлайн для [EMAIL_" in manual_clip
    assert "manual.sync@example.ru" not in manual_clip
    ui.click_back_sanitize()
    if not live_toggle.is_checked():
        live_toggle.check()
    ui.click_copy_goto_step2()

    # Verify graceful fallback when Clipboard readText rejects
    page.evaluate(
        """() => {
            Object.defineProperty(navigator, 'clipboard', {
                configurable: true,
                value: {
                    readText: () => Promise.reject(new DOMException('Denied', 'NotAllowedError')),
                    writeText: () => Promise.resolve()
                }
            });
        }"""
    )
    ui.click_paste_rehydrate()
    banner_txt = ui.get_status_banner_text()
    assert "Ctrl+V" in banner_txt
    assert page.evaluate("() => document.activeElement?.id") == "llm-reply-input"

    ui.click_back_sanitize()
    ui.click_paste_raw()
    assert "Ctrl+V" in ui.get_status_banner_text()
    assert page.evaluate("() => document.activeElement?.id") == "raw-prompt-input"

    e2e_session.net.assert_zero_egress(
        [
            "maria.ivanova@example.ru",
            "+7 (916) 555-01-44",
            "fast.click@example.ru",
            "manual.sync@example.ru",
        ]
    )
    e2e_session.console.assert_no_errors()


def test_ACC_08_pricing_request_modals_footer_contacts_and_i18n(e2e_session: E2ESession) -> None:
    """R4 & R5: Honest Waitlist pricing, Pro/Team client-only forms, Trust Footer, Terms/Policy, and RU/EN i18n."""
    page = e2e_session.page
    ui = e2e_session.ui

    # 1. Honest Free + Waitlist Pricing section in RU (no fake prices or 30-day free trial)
    pricing_el = page.locator("[data-testid='pricing-section']")
    pricing_txt = pricing_el.inner_text()
    assert page.locator("[data-testid='pricing-card-free']").is_visible()
    assert "Активен сейчас" in page.locator("[data-testid='pricing-card-free']").inner_text()
    assert "0 ₽" in page.locator("[data-testid='pricing-card-free']").inner_text()
    assert page.locator("[data-testid='price-pro-value']").inner_text().strip() == "Лист ожидания"
    assert page.locator("[data-testid='price-team-value']").inner_text().strip() == "Лист ожидания"
    assert page.locator("[data-testid='billing-toggle']").count() == 0
    for forbidden in ("490 ₽", "390 ₽", "1 990 ₽", "1 590 ₽", "30 дней бесплатно"):
        assert forbidden not in pricing_txt, f"Unexpected pricing claim {forbidden!r}"

    # 2. Pro & Team client-only waitlist validation + formatted summary + copy + mailto
    ui.open_plan_request_modal("pro")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    assert page.locator("[data-testid='plan-request-alert']").is_visible()

    page.locator("[data-testid='plan-req-name']").fill("Иван Петров")
    page.locator("[data-testid='plan-req-contact']").fill("bad-contact")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    assert page.locator("[data-testid='plan-request-alert']").is_visible()

    page.locator("[data-testid='plan-req-contact']").fill("test<img src=x onerror=alert(1)>@evil.com")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    assert page.locator("[data-testid='plan-request-alert']").is_visible()
    assert not page.locator("[data-testid='plan-request-result']").is_visible()

    page.locator("[data-testid='plan-req-contact']").fill("ivan@company.ru")
    page.locator("[data-testid='plan-req-note']").fill("Нужна обработка docx")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    preview_txt = page.locator("[data-testid='plan-request-preview']").inner_text()
    assert "Pro" in preview_txt and "Иван Петров" in preview_txt and "Лист ожидания" in preview_txt
    mailto_href = page.locator("[data-testid='plan-req-mailto-link']").get_attribute("href") or ""
    assert mailto_href.startswith("mailto:kilkauciha@gmail.com?")
    page.locator("[data-testid='plan-req-copy-btn']").click()
    assert (ui.read_clipboard_text() or "").replace("\r\n", "\n") == preview_txt.replace("\r\n", "\n")
    toast_over_modal = page.evaluate(
        """() => {
            const toast = document.querySelector("[data-testid='status-banner']");
            const dialog = document.querySelector("[data-testid='modal-plan-request']");
            return Boolean(toast && !toast.hidden) && Number(getComputedStyle(toast).zIndex || 0) > Number(getComputedStyle(dialog).zIndex || 0);
        }"""
    )
    assert toast_over_modal is True
    ui.close_active_modal()

    ui.open_plan_request_modal("team")
    assert page.locator("[data-testid='plan-req-name']").input_value() == ""
    assert page.locator("[data-testid='plan-req-contact']").input_value() == ""
    assert page.locator("[data-testid='plan-req-note']").input_value() == ""
    assert page.locator("[data-testid='plan-req-seats']").input_value() == "10"
    assert not page.locator("[data-testid='plan-request-alert']").is_visible()
    assert not page.locator("[data-testid='plan-request-result']").is_visible()
    assert page.locator("[data-testid='plan-req-seats']").is_visible()

    page.locator("[data-testid='plan-req-name']").fill("Иван Петров")
    page.locator("[data-testid='plan-req-contact']").fill("ivan@company.ru")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    assert page.locator("[data-testid='plan-request-result']").is_visible()

    page.locator("[data-testid='plan-req-seats']").fill("")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    seats_alert = page.locator("[data-testid='plan-request-alert']")
    assert seats_alert.is_visible()
    assert "5000" in seats_alert.inner_text()
    assert not page.locator("[data-testid='plan-request-result']").is_visible()

    page.locator("[data-testid='plan-req-seats']").fill("15")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    team_preview = page.locator("[data-testid='plan-request-preview']").inner_text()
    assert "15" in team_preview
    ui.close_active_modal()

    # 3. Trust Footer, Clickable Real Contacts, Privacy Policy Disclaimer, and Terms Modal
    footer_text = page.locator("[data-testid='site-footer']").inner_text()
    for token in (
        "HTTPS / TLS",
        "0 логов ваших текстов",
        "Strict CSP",
        "Без cookies и трекеров",
        "@supv1rus",
        "kilkauciha@gmail.com",
        "github.com/Aquanti",
        "Автор проекта: SupV1rus",
    ):
        assert token in footer_text, f"Missing footer trust/contact token {token!r}"

    tg_link = page.locator("[data-testid='contact-telegram-text']")
    assert tg_link.get_attribute("href") == "https://t.me/supv1rus"
    assert tg_link.get_attribute("target") == "_blank"
    assert "noopener" in (tg_link.get_attribute("rel") or "")

    gh_link = page.locator("[data-testid='contact-github-text']")
    assert gh_link.get_attribute("href") == "https://github.com/Aquanti"
    assert gh_link.get_attribute("target") == "_blank"
    assert "noopener" in (gh_link.get_attribute("rel") or "")

    page.locator("[data-testid='copy-contact-telegram-btn']").click()
    assert ui.read_clipboard_text() == "@supv1rus"
    page.locator("[data-testid='copy-contact-github-btn']").click()
    assert ui.read_clipboard_text() == "github.com/Aquanti"

    policy_modal = ui.open_privacy_policy_modal()
    policy_txt = policy_modal.inner_text()
    assert "kilkauciha@gmail.com" in policy_txt
    assert "@supv1rus" in policy_txt
    assert "эвристик" in policy_txt
    assert "access-логи" in policy_txt
    ui.close_active_modal()

    terms_modal = ui.open_terms_modal()
    terms_txt = terms_modal.inner_text()
    assert "как есть" in terms_txt
    assert "SupV1rus" in terms_txt
    ui.close_active_modal()

    # 4. EN translation across waitlist pricing, Free tier localization, theme aria-label, footer, and Proof modal
    ru_theme_aria = page.locator("[data-testid='theme-toggle-btn']").get_attribute("aria-label") or ""
    ui.switch_language("en")
    en_free_txt = page.locator("[data-testid='pricing-card-free']").inner_text()
    assert "$0" in en_free_txt
    for ru_only in ("ИНН", "СНИЛС", "INN", "SNILS"):
        assert ru_only not in en_free_txt
    en_theme_aria = page.locator("[data-testid='theme-toggle-btn']").get_attribute("aria-label") or ""
    assert en_theme_aria and en_theme_aria != ru_theme_aria
    assert page.locator("[data-testid='price-pro-value']").inner_text().strip() == "Waitlist"
    assert page.locator("[data-testid='price-team-value']").inner_text().strip() == "Waitlist"
    assert "0 Text Logs" in page.locator("[data-testid='site-footer']").inner_text()
    assert "Created by SupV1rus" in page.locator("[data-testid='footer-copyright']").inner_text()
    assert "Zero-Retention • Verify" in ui.get_zero_egress_pill().inner_text()

    e2e_session.net.assert_zero_egress(["ivan@company.ru", "Иван Петров"])
    e2e_session.console.assert_no_errors()


def test_ACC_09_russian_id_detectors_valid_and_invalid_checksums(e2e_session: E2ESession) -> None:
    """P0: Validate all 7 free Russian ID categories with checksums + secondary US SSN."""
    ui = e2e_session.ui

    valid_payload = (
        "Организация ИНН 7707083893 ОГРН 1027700132195\n"
        "ИП ИНН 500100732259 ОГРНИП 304500116000157\n"
        "СНИЛС 112-233-445 95 Паспорт РФ: 45 10 № 123456\n"
        "БИК 044525225 р/с 40702810938000012345 к/с 30101810400000000225\n"
        "Полис ОМС: 7746 1234 5678 9019\n"
        "US Tax ID SSN: 123-45-6789"
    )
    masked = ui.sanitize_text(valid_payload)
    for token in (
        "[INN_1]",
        "[INN_2]",
        "[OGRN_1]",
        "[OGRN_2]",
        "[SNILS_1]",
        "[PASSPORT_1]",
        "[BIK_1]",
        "[BANK_ACC_1]",
        "[BANK_ACC_2]",
        "[OMS_1]",
        "[SSN_1]",
    ):
        assert token in masked, f"Missing expected token {token} in:\n{masked}"

    for secret in (
        "7707083893",
        "500100732259",
        "1027700132195",
        "304500116000157",
        "112-233-445 95",
        "45 10 № 123456",
        "044525225",
        "40702810938000012345",
        "30101810400000000225",
        "7746 1234 5678 9019",
        "123-45-6789",
    ):
        assert secret not in masked, f"Secret {secret!r} leaked into masked output"

    restored = ui.rehydrate_text(masked)
    assert restored.strip() == valid_payload.strip()

    # Invalid checksums must remain unmasked (except the valid anchor BIK used to verify accounts)
    invalid_payload = (
        "ИНН 7707083894 ИНН2 500100732250 ОГРН 1027700132196 ОГРНИП 304500116000158 "
        "СНИЛС 112-233-445 96 Паспорт 00 10 123456 "
        "БИК 044525225 р/с 40702810838000012345 к/с 30101810500000000225 "
        "Полис ОМС: 7746 1234 5678 9018"
    )
    bad_masked = ui.sanitize_text(invalid_payload)
    assert "[BIK_1]" in bad_masked
    for bad_val in (
        "7707083894",
        "500100732250",
        "1027700132196",
        "304500116000158",
        "112-233-445 96",
        "00 10 123456",
        "40702810838000012345",
        "30101810500000000225",
        "7746 1234 5678 9018",
    ):
        assert bad_val in bad_masked, f"Invalid checksum value {bad_val!r} should NOT be masked"

    e2e_session.net.assert_zero_egress(["7707083893", "112-233-445 95", "40702810938000012345"])
    e2e_session.console.assert_no_errors()


def test_ACC_10_p1_detectors_and_ru_requisites_preset(e2e_session: E2ESession) -> None:
    """P1 & Stage A: Validate RU_FIO (incl. 2-word), RU_ORG, RU_ADDRESS (incl. city), RU_AUTO_PLATE, URL_TOKEN, and ru_requisites preset."""
    ui = e2e_session.ui

    p1_payload = (
        "Подписант Соколов Алексей Петрович (Петрова И.С.)\n"
        "Адрес: 125009, г. Москва, ул. Тверская, д. 12, стр. 1, оф. 45\n"
        "Авто: А123ВС 777 и фейк А123ВС 345\n"
        "Ссылка: https://portal.example.ru/doc?token=UrlSecToken778899&tab=main\n"
        "Обычный URL без секрета: https://example.com:8443/v1/users/profile_overview_page\n"
        "Двухсловные без отчества: Алексей Смирнов и Иван Петров"
    )
    masked = ui.sanitize_text(p1_payload)
    assert "[FIO_1]" in masked and "[FIO_2]" in masked
    assert "[FIO_3]" in masked and "[FIO_4]" in masked
    assert "[ADDRESS_1]" in masked
    assert "[PLATE_1]" in masked
    assert "[URL_TOKEN_1]" in masked
    assert "А123ВС 345" in masked
    assert "https://example.com:8443/v1/users/profile_overview_page" in masked
    assert "Алексей Смирнов" not in masked and "Иван Петров" not in masked
    assert "г. Москва" not in masked
    assert ui.rehydrate_text(masked).strip() == p1_payload.strip()

    ui.switch_mode("sanitize")
    ui.select_preset("ru_requisites")
    preset_out = ui.get_sanitize_output_text()
    for token in (
        "[ORG_1]",
        "[ORG_2]",
        "[INN_1]",
        "[OGRN_1]",
        "[BIK_1]",
        "[BANK_ACC_1]",
        "[ADDRESS_1]",
        "[FIO_1]",
        "[SNILS_1]",
        "[PASSPORT_1]",
        "[OMS_1]",
        "[PLATE_1]",
        "[URL_TOKEN_1]",
    ):
        assert token in preset_out, f"Preset ru_requisites missing {token}"

    restored = ui.rehydrate_text(preset_out)
    for expected in (
        "АО «ТехноСфера»",
        "ПАО «ТестБанк»",
        "7707083893",
        "112-233-445 95",
        "Соколов Алексей Петрович",
        "DemoUrlToken998877",
    ):
        assert expected in restored

    e2e_session.net.assert_zero_egress(
        [
            "UrlSecToken778899",
            "DemoUrlToken998877",
            "Соколов Алексей Петрович",
            "Алексей Смирнов",
            "Иван Петров",
            "АО «ТехноСфера»",
        ]
    )
    e2e_session.console.assert_no_errors()


def test_ACC_11_pwa_offline_service_worker_and_seo_routes(raw_session: E2ESession) -> None:
    """P1 & SEO: Verify SEO endpoints, manifest MIME, /en/, active SW offline Proof card, and offline masking/reload."""
    page = raw_session.page
    ui = raw_session.ui
    base_url = raw_session.base_url

    for path in ("/robots.txt", "/sitemap.xml", "/404.html", "/manifest.webmanifest", "/og-image.png", "/sw.js", "/en/"):
        status, hdrs, _ = fetch_http_response(f"{base_url}{path}")
        assert status == 200, f"GET {path} returned {status}"
        if path == "/manifest.webmanifest":
            assert hdrs.get("content-type", "").lower().startswith("application/manifest+json"), (
                f"Unexpected /manifest.webmanifest Content-Type: {hdrs.get('content-type')!r}"
            )

    page.goto(f"{base_url}/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.console.assert_no_errors()

    # Wait for Service Worker registration & activation before going offline
    sw_ready = page.evaluate(
        """async () => {
            if (!('serviceWorker' in navigator)) return false;
            const reg = await navigator.serviceWorker.ready;
            return Boolean(reg && reg.active);
        }"""
    )
    assert sw_ready is True, "Service Worker failed to become active"

    # Reload once so SW controls the client, then verify Proof offline card
    page.reload(wait_until="networkidle")
    modal = ui.open_privacy_proof_modal("header")
    assert page.locator("[data-testid='proof-offline-card']").is_visible()
    offline_text = modal.inner_text()
    assert "Офлайн готов" in offline_text
    assert "Отключите интернет" in offline_text
    ui.close_active_modal()

    # Cut network connectivity completely and verify offline reload + sanitize/rehydrate
    try:
        page.context.set_offline(True)
        page.reload(wait_until="domcontentloaded")
        page.locator("[data-testid='raw-prompt-input']").wait_for(state="visible", timeout=5000)

        offline_in = "ИНН 7707083893, СНИЛС 112-233-445 95, offline@example.ru"
        offline_out = ui.sanitize_text(offline_in)
        assert "[INN_1]" in offline_out and "[SNILS_1]" in offline_out and "[EMAIL_1]" in offline_out
        assert ui.rehydrate_text(offline_out).strip() == offline_in
    finally:
        page.context.set_offline(False)

    raw_session.console.assert_no_errors()


def test_ACC_12_ai_launchers_dark_theme_and_screenshots(e2e_session: E2ESession) -> None:
    """P1: Verify 'Open in AI' links, Dark Theme persistence + Proof storage clean, & screenshots."""
    page = e2e_session.page
    ui = e2e_session.ui

    expected_launchers = {
        "ai-launcher-chatgpt": "https://chatgpt.com/",
        "ai-launcher-deepseek": "https://chat.deepseek.com/",
        "ai-launcher-gigachat": "https://giga.chat/",
        "ai-launcher-alice": "https://alice.yandex.ru/",
        "ai-launcher-claude": "https://claude.ai/",
    }
    launchers_bar = page.locator("[data-testid='ai-launchers-bar']")
    assert launchers_bar.is_visible()
    for tid, expected_href in expected_launchers.items():
        link = page.locator(f"[data-testid='{tid}']")
        assert link.is_visible()
        assert link.get_attribute("href") == expected_href
        assert link.get_attribute("target") == "_blank"
        assert "noopener" in (link.get_attribute("rel") or "")

    ui.sanitize_text("Почта dev@example.ru")
    assert "is-ready" in (launchers_bar.get_attribute("class") or "")

    # Toggle dark theme and verify persistence + Proof unknownKeys=0
    theme_btn = page.locator("[data-testid='theme-toggle-btn']")
    assert theme_btn.is_visible()
    theme_btn.click()
    assert page.evaluate("() => document.documentElement.dataset.theme") == "dark"
    assert page.evaluate("() => localStorage.getItem('promptveil_theme_v1')") == "dark"

    modal = ui.open_privacy_proof_modal("header")
    assert "неизвестные ключи: 0" in modal.inner_text()
    ui.close_active_modal()

    ui.select_preset("ru_requisites")
    for label_prefix, width, height in (("desktop", 1440, 900), ("mobile", 390, 844)):
        verify_responsive_layout(page, width, height)
        if width <= 639:
            top_rail_h = page.locator("header.top-rail").evaluate("el => el.getBoundingClientRect().height")
            assert top_rail_h <= 64.5, f"Mobile top-rail height exceeded 64px with theme btn: {top_rail_h}"
        capture_viewport_screenshot(
            page,
            f"acc_{label_prefix}_dark",
            width,
            height,
            output_dir=ACCEPTANCE_SCREENSHOTS_DIR,
            full_page=False,
        )

    e2e_session.net.assert_zero_egress(["dev@example.ru"])
    e2e_session.console.assert_no_errors()


def test_ACC_13_stage_e_copy_open_ai_telegram_limits_sensitivity_and_packs(
    e2e_session: E2ESession,
) -> None:
    """Stage E Acceptance: Copy & Open AI, Telegram plan CTA + email fallback, How It Works/Honest Limits, Sensitivity & tooltips, Industry Word Packs."""
    page = e2e_session.page
    ui = e2e_session.ui

    # 1. How It Works & Honest Limits sections in RU and EN + responsive check
    how_sec = ui.get_how_it_works_section()
    limits_sec = ui.get_honest_limits_section()
    assert how_sec.is_visible() and limits_sec.is_visible()
    verify_russian_purity(page)
    verify_responsive_layout(page, 1440, 900)
    verify_responsive_layout(page, 390, 844)
    page.set_viewport_size({"width": 1440, "height": 900})

    ui.switch_language("en")
    assert ui.get_how_it_works_section().is_visible()
    assert ui.get_honest_limits_section().is_visible()
    ui.switch_language("ru")

    drawer = ui.click_limits_rulebook_link()
    assert drawer.is_visible()

    # 2. Industry Word Packs (Legal, HR, Medical, Accounting) + deduplication
    pack_patterns = {
        "legal": re.compile(r"юрид|правов|legal", re.I),
        "hr": re.compile(r"\bhr\b|кадр", re.I),
        "medical": re.compile(r"медиц|здрав|medical|clinic", re.I),
        "accounting": re.compile(r"бухгалт|финанс|accounting|finance", re.I),
    }
    for pack_key, pat in pack_patterns.items():
        pack_btn = drawer.locator(f"[data-testid='word-pack-{pack_key}'], [data-pack='{pack_key}']")
        if pack_btn.count() == 0:
            pack_btn = drawer.locator("button").filter(has_text=pat)
        assert pack_btn.count() >= 1 and pack_btn.first.is_visible()
    before_rules = ui.get_rulebook_badge_count()
    ui.apply_industry_word_pack("legal")
    after_rules = ui.get_rulebook_badge_count()
    assert after_rules > before_rules
    sample_term = (
        drawer.locator(
            "[data-testid='rules-list'] .rule-term-text, "
            "[data-testid='rules-list'] [data-term], "
            "[data-testid='rules-list'] .rule-term"
        )
        .first.inner_text()
        .strip()
    )
    ui.apply_industry_word_pack("legal")
    assert ui.get_rulebook_badge_count() == after_rules
    ui.close_open_drawer()

    # 3. Sensitivity mode (normal -> strict) + reason tooltips
    sample_uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert ui.get_sensitivity_mode() == "normal"
    out_normal = ui.sanitize_text(f"Условие {sample_term}, UUID {sample_uuid}, почта acc13@example.ru")
    assert "[CUSTOM_1]" in out_normal and "[EMAIL_1]" in out_normal
    assert sample_uuid in out_normal

    ui.set_sensitivity_mode("strict")
    out_strict = ui.get_sanitize_output_text()
    assert "[UUID_1]" in out_strict
    assert sample_uuid not in out_strict
    verify_russian_purity(page)

    rows = ui.get_vault_rows()
    assert len(rows) >= 3
    assert any(
        r.row_locator.evaluate(
            """el => {
                const n = el.matches('[title], [data-reason], .vault-reason')
                    ? el
                    : el.querySelector('[title], [data-reason], .vault-reason');
                if (!n) return false;
                if (n.classList && n.classList.contains('vault-reason')) {
                    return Boolean((n.getAttribute('title') || n.getAttribute('data-reason') || n.textContent || '').trim());
                }
                return Boolean((n.getAttribute('title') || n.getAttribute('data-reason') || '').trim());
            }"""
        )
        for r in rows
    )

    # 4. One-click Copy & Open AI + Telegram plan CTA & email fallback
    def _abort_ext(route: Any) -> None:
        route.abort()

    page.context.route("https://chatgpt.com/**", _abort_ext)
    page.context.route("https://t.me/**", _abort_ext)
    try:
        with page.expect_popup(timeout=3000) as ai_pop:
            ui.click_ai_launcher("chatgpt")
        ai_pop.value.close()
        assert ui.read_clipboard_text() == out_strict
        assert ui.get_status_banner_text()

        ui.open_plan_request_modal("pro")
        page.locator("[data-testid='plan-req-name']").fill("Сергей")
        page.locator("[data-testid='plan-req-contact']").fill("@sergey_test")
        page.locator("[data-testid='plan-req-submit-btn']").click()
        assert "kilkauciha@gmail.com" in page.locator("[data-testid='modal-plan-request']").inner_text()

        tg_cta = ui.get_plan_telegram_link()
        assert tg_cta.get_attribute("target") == "_blank"
        assert "noopener" in (tg_cta.get_attribute("rel") or "")
        assert "https://t.me/supv1rus" in (tg_cta.get_attribute("href") or "")
        with page.expect_popup(timeout=3000) as tg_pop:
            ui.copy_plan_for_telegram()
        tg_pop.value.close()
        assert "Pro" in (ui.read_clipboard_text() or "")
        assert ui.get_status_banner_text()
        ui.close_active_modal()
    finally:
        page.context.unroute("https://chatgpt.com/**")
        page.context.unroute("https://t.me/**")

    e2e_session.net.assert_zero_egress(["acc13@example.ru", sample_term])
    e2e_session.console.assert_no_errors()
