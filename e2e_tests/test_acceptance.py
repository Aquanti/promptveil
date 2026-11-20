"""Product Acceptance Gate Tests (R1/R2/R3: ACC-01..ACC-05)."""

from __future__ import annotations

import re

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

    e2e_session.console.assert_no_errors()


def test_ACC_02_language_switcher_ru_en_and_persistence(e2e_session: E2ESession) -> None:
    """R1: Compact RU | EN toggle updates UI live without reload and persists in localStorage."""
    page = e2e_session.page
    ui = e2e_session.ui

    assert page.locator("[data-testid='lang-switch']").first.is_visible()
    assert page.locator("[data-testid='lang-ru']").first.is_visible()
    assert page.locator("[data-testid='lang-en']").first.is_visible()
    assert ui.get_document_lang().lower() == "ru"

    ru_tab_label = page.locator("[data-testid='mode-sanitize']").first.inner_text()
    page.evaluate("() => { window.__pvNoReloadMarker = 1; }")

    ui.switch_language("en")
    assert page.evaluate("() => window.__pvNoReloadMarker") == 1, "Language switch must not reload page"
    assert ui.get_document_lang().lower() == "en"
    assert ui.get_stored_language() == "en"
    en_tab_label = page.locator("[data-testid='mode-sanitize']").first.inner_text()
    assert en_tab_label != ru_tab_label
    assert re.search(r"[A-Za-z]", en_tab_label)

    page.reload(wait_until="networkidle")
    assert ui.get_document_lang().lower() == "en"
    assert ui.get_stored_language() == "en"
    assert page.locator("[data-testid='mode-sanitize']").first.inner_text() == en_tab_label

    ui.switch_language("ru")
    assert ui.get_document_lang().lower() == "ru"
    assert ui.get_stored_language() == "ru"
    verify_russian_purity(page)

    page.reload(wait_until="networkidle")
    assert ui.get_document_lang().lower() == "ru"
    assert ui.get_stored_language() == "ru"
    verify_russian_purity(page)
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
