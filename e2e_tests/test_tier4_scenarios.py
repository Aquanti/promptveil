"""Tier 4: Real-World Application Scenarios (5 Tests: T4-01..T4-05)."""

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
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || ''")
    assert re.search(r"[0-9a-f]{64}", stored, re.I) is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in stored


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
        e2e_session.ui.close_open_drawer()
        e2e_session.ui.open_audit_drawer()
        e2e_session.ui.close_open_drawer()

        verify_responsive_layout(e2e_session.page, width, height)

    e2e_session.net.assert_clean_load()
    e2e_session.net.assert_zero_egress()
    e2e_session.console.assert_no_errors()
