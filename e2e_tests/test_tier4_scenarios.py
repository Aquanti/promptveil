"""Tier 4: Real-World Application Scenarios (6 Tests: T4-01..T4-06)."""

from __future__ import annotations

import re
from typing import Any

import pytest

from conftest import E2ESession
from monitors import verify_responsive_layout


pytestmark = [pytest.mark.tier4]


def test_T4_01_consulting_nda_review_english_contract(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = dict(test_cases_data["tier4"]["T4-01"])
    e2e_session.ui.add_custom_rule(case["custom_rule"])
    e2e_session.ui.close_open_drawer()

    masked = e2e_session.ui.sanitize_text(case["prompt"])
    for tok in ("[CUSTOM_1]", "[EMAIL_1]", "[PHONE_1]", "[SSN_1]", "[IBAN_1]", "[CARD_1]"):
        assert tok in masked
    for raw in case["expected_restored"]:
        assert raw not in masked

    restored = e2e_session.ui.rehydrate_text(case["reply_template"])
    for raw in case["expected_restored"]:
        assert raw in restored
    assert e2e_session.ui.get_unresolved_tokens() == []
    e2e_session.console.assert_no_errors()


def test_T4_02_production_incident_env_and_stacktrace(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = dict(test_cases_data["tier4"]["T4-02"])
    masked = e2e_session.ui.sanitize_text(case["prompt"])
    for tok in (
        "[API_KEY_1]",
        "[API_KEY_2]",
        "[API_KEY_3]",
        "[API_KEY_4]",
        "[ENV_SECRET_1]",
        "[JWT_1]",
        "[IP_1]",
        "[SECRET_1]",
    ):
        assert tok in masked
    assert "v2.4.1.0" in masked
    assert "AWS_ACCESS_KEY_ID=" in masked
    assert "AKIAIOSFODNN7EXAMPLE" not in masked

    restored = e2e_session.ui.rehydrate_text(case["reply_template"])
    assert "AKIAIOSFODNN7EXAMPLE" in restored
    assert "v2.4.1.0" in restored
    assert "203.0.113.77" in restored
    hashes = e2e_session.ui.get_audit_hashes()
    assert len(hashes) >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in e2e_session.ui.get_audit_drawer_text()
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None


def test_T4_03_bilingual_ru_cis_hr_candidate_screening(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = dict(test_cases_data["tier4"]["T4-03"])
    for rule in case["custom_rules"]:
        e2e_session.ui.add_custom_rule(rule)
    e2e_session.ui.close_open_drawer()

    masked = e2e_session.ui.sanitize_text(case["prompt"])
    for tok in ("[CUSTOM_1]", "[CUSTOM_2]", "[PHONE_1]", "[PHONE_2]", "[EMAIL_1]", "[CARD_1]"):
        assert tok in masked
    assert "19.11.2026" in masked
    assert "Алексей Смирнов" not in masked
    assert "ООО «Вектор»" not in masked

    restored = e2e_session.ui.rehydrate_text(case["reply_template"])
    for expected in (
        "Алексей Смирнов",
        "ООО «Вектор»",
        "+7 (916) 555-01-23",
        "8 (495) 555-35-35",
        "a.smirnov@vector-synth.example",
        "5500-0000-0000-0004",
        "19.11.2026",
    ):
        assert expected in restored


def test_T4_04_zero_http_egress_network_audit(e2e_session: E2ESession) -> None:
    canary = "UltraCanaryToken99887766"
    canary_email = "canary.audit@example.com"

    # (a) Sanitize canary secret + email + card
    out = e2e_session.ui.sanitize_text(
        f"CANARY_SECRET={canary} mail {canary_email} card 4111 1111 1111 1111"
    )
    assert canary not in out and canary_email not in out

    # (b) Toggle entity off & on
    e2e_session.ui.toggle_vault_entity(canary_email)
    e2e_session.ui.toggle_vault_entity(canary_email)

    # (c) Upload .txt via FileReader
    up = e2e_session.io.uploads / "canary.txt"
    up.write_text(f"FILE_SECRET={canary} user {canary_email}", encoding="utf-8")
    e2e_session.ui.upload_file(up)

    # (d) Add & export Custom Rule (blob: download allowed; HTTP forbidden)
    e2e_session.ui.add_custom_rule("CanaryProject")
    e2e_session.ui.export_rules_json(e2e_session.io.downloads)
    e2e_session.ui.close_open_drawer()

    # (e) Re-Hydrate reply
    restored = e2e_session.ui.rehydrate_text("Keep [ENV_SECRET_1] and [EMAIL_1]")
    assert canary in restored and canary_email in restored

    # (f) Open Audit Receipts drawer
    assert len(e2e_session.ui.get_audit_hashes()) >= 1

    e2e_session.net.assert_zero_egress([canary, canary_email, "4111 1111 1111 1111"])


def test_T4_05_desktop_and_mobile_responsive_and_console_hygiene(e2e_session: E2ESession) -> None:
    for width, height in ((1440, 900), (1280, 800), (390, 844)):
        verify_responsive_layout(e2e_session.page, width, height)
        e2e_session.ui.select_preset("bilingual_cis_hr")
        assert len(e2e_session.ui.get_vault_rows()) >= 3

        e2e_session.ui.toggle_category_chip("EMAIL")
        e2e_session.ui.toggle_category_chip("EMAIL")

        first_row = e2e_session.ui.get_vault_rows()[0]
        e2e_session.ui.toggle_vault_entity(first_row.token)
        e2e_session.ui.toggle_vault_entity(first_row.token)

        masked = e2e_session.ui.get_sanitize_output_text()
        restored = e2e_session.ui.rehydrate_text(masked)
        assert len(restored.strip()) > 0
        e2e_session.ui.switch_mode("sanitize")

        e2e_session.ui.open_rulebook_drawer()
        verify_responsive_layout(e2e_session.page, width, height)
        e2e_session.ui.close_open_drawer()
        e2e_session.ui.open_audit_drawer()
        verify_responsive_layout(e2e_session.page, width, height)
        e2e_session.ui.close_open_drawer()

        verify_responsive_layout(e2e_session.page, width, height)

    e2e_session.net.assert_clean_load()
    e2e_session.net.assert_zero_egress()
    e2e_session.console.assert_no_errors()


def test_T4_06_mobile_390x844_compact_header_collapsible_vault_sticky_cta_and_tap_targets(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    verify_responsive_layout(page, 390, 844)

    top_rail_h = page.locator("header.top-rail").evaluate("el => el.getBoundingClientRect().height")
    assert top_rail_h <= 64.5, f"Compact mobile header exceeded 64.5px: {top_rail_h}"

    proof_box = page.locator("[data-testid='brand-badge']").bounding_box()
    assert proof_box is not None and proof_box["width"] >= 43.5 and proof_box["height"] >= 43.5

    mobile_lang = page.locator("[data-testid='lang-mobile-toggle']")
    assert mobile_lang.is_visible()
    lang_box = mobile_lang.bounding_box()
    assert lang_box is not None and lang_box["width"] >= 43.5 and lang_box["height"] >= 43.5
    assert not page.locator("[data-testid='lang-ru']").is_visible()
    assert not page.locator("[data-testid='lang-en']").is_visible()

    more_btn = page.locator("[data-testid='mobile-more-btn']")
    assert more_btn.is_visible()
    more_box = more_btn.bounding_box()
    assert more_box is not None and more_box["width"] >= 43.5 and more_box["height"] >= 43.5

    assert page.locator("[data-testid='mode-rehydrate'] [data-i18n='nav.step2']").inner_text().strip() == "2. Вернуть"
    ui.switch_language("en")
    assert page.locator("[data-testid='mode-rehydrate'] [data-i18n='nav.step2']").inner_text().strip() == "2. Restore"
    ui.switch_language("ru")

    ui.select_preset("bilingual_cis_hr")
    ui.ensure_vault_expanded()
    expanded_scroll_h = page.evaluate("() => document.documentElement.scrollHeight")
    if not ui.is_vault_collapsed():
        ui.toggle_vault_collapse()
    assert ui.is_vault_collapsed() is True
    collapsed_scroll_h = page.evaluate("() => document.documentElement.scrollHeight")
    assert collapsed_scroll_h < expanded_scroll_h
    ui.ensure_vault_expanded()

    sticky = ui.get_mobile_sticky_cta()
    assert sticky.is_visible()

    for pill_idx in range(page.locator(".ai-launcher-pill").count()):
        pill_box = page.locator(".ai-launcher-pill").nth(pill_idx).bounding_box()
        assert pill_box is not None and pill_box["height"] >= 43.5
    footer_targets = page.locator("footer a, footer button")
    for idx in range(footer_targets.count()):
        item = footer_targets.nth(idx)
        if item.is_visible():
            f_box = item.bounding_box()
            assert f_box is not None and f_box["height"] >= 43.5

    for opener in (ui.open_rulebook_drawer, ui.open_audit_drawer):
        drawer = opener()
        box = drawer.bounding_box()
        assert box is not None
        assert box["x"] >= -0.5 and (box["x"] + box["width"]) <= 390.5
        verify_responsive_layout(page, 390, 844)
        ui.close_open_drawer()

    e2e_session.console.assert_no_errors()
