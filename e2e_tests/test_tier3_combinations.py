"""Tier 3: Cross-Feature Pairwise & Multi-Feature Combinations (9 Tests: T3-01..T3-09)."""

from __future__ import annotations

import json
import re

import pytest

from conftest import E2ESession


pytestmark = [pytest.mark.tier3]


def test_T3_01_sanitize_toggle_entity_off_then_rehydrate(e2e_session: E2ESession) -> None:
    out1 = e2e_session.ui.sanitize_text("Send contract to alice@example.com and bob@example.com.")
    assert "[EMAIL_1]" in out1 and "[EMAIL_2]" in out1
    e2e_session.ui.toggle_vault_entity("bob@example.com")
    out2 = e2e_session.ui.get_sanitize_output_text()
    assert "[EMAIL_1]" in out2 and "bob@example.com" in out2
    restored = e2e_session.ui.rehydrate_text("Sent to [EMAIL_1] and bob@example.com.")
    assert restored.strip() == "Sent to alice@example.com and bob@example.com."


def test_T3_02_cyrillic_rule_bilingual_preset_audit_zero_pii(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Секретный Проект Альфа")
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.select_preset("bilingual_cis_hr")
    preset_prompt = e2e_session.ui.get_prompt_input().input_value()
    out = e2e_session.ui.sanitize_text(preset_prompt + "\nПроект: Секретный Проект Альфа.")
    assert "[CUSTOM_" in out
    assert "Секретный Проект Альфа" not in out
    hashes = e2e_session.ui.get_audit_hashes()
    assert len(hashes) >= 1
    assert "Секретный Проект Альфа" not in e2e_session.ui.get_audit_drawer_text()
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None


def test_T3_03_export_rules_clear_rules_import_rules_rescan(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Project Falcon")
    e2e_session.ui.add_custom_rule("Проект Альфа")
    exported = e2e_session.ui.export_rules_json(e2e_session.io.downloads)

    e2e_session.ui.delete_custom_rule("Project Falcon")
    e2e_session.ui.delete_custom_rule("Проект Альфа")
    e2e_session.ui.close_open_drawer()
    unmasked = e2e_session.ui.sanitize_text("Project Falcon / Проект Альфа")
    assert "Project Falcon" in unmasked and "Проект Альфа" in unmasked

    e2e_session.ui.import_rules_json(exported)
    e2e_session.ui.close_open_drawer()
    remasked = e2e_session.ui.sanitize_text("Project Falcon / Проект Альфа")
    assert "[CUSTOM_1]" in remasked and "[CUSTOM_2]" in remasked
    assert "Project Falcon" not in remasked and "Проект Альфа" not in remasked


def test_T3_04_filereader_upload_chip_disable_rehydrate_unresolved(e2e_session: E2ESession) -> None:
    inc = e2e_session.io.uploads / "inc.txt"
    inc.write_text("User ops@example.com IP 198.51.100.4", encoding="utf-8")
    e2e_session.ui.upload_file(inc)
    e2e_session.net.assert_zero_egress(["ops@example.com", "198.51.100.4"])

    e2e_session.ui.toggle_category_chip("IPV4")
    assert "198.51.100.4" in e2e_session.ui.get_sanitize_output_text()

    restored = e2e_session.ui.rehydrate_text("Alert [EMAIL_1] from 198.51.100.4 and [JWT_99].")
    assert "ops@example.com" in restored
    assert "198.51.100.4" in restored
    assert "[JWT_99]" in e2e_session.ui.get_unresolved_tokens()


def test_T3_05_multi_category_overlap_entity_toggle_and_reload(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("AcmeKey")
    e2e_session.ui.close_open_drawer()
    prompt = "OPENAI_API_KEY=sk-proj-TestSynthKey000111222333444 AcmeKey ops@example.com"
    e2e_session.ui.sanitize_text(prompt)
    e2e_session.ui.toggle_vault_entity("ops@example.com")
    out1 = e2e_session.ui.get_sanitize_output_text()
    assert "[API_KEY_1]" in out1 and "[CUSTOM_1]" in out1 and "ops@example.com" in out1

    e2e_session.page.reload(wait_until="networkidle")
    assert e2e_session.ui.get_audit_hashes() == []
    e2e_session.ui.close_open_drawer()
    out2 = e2e_session.ui.sanitize_text(prompt)
    assert "[CUSTOM_1]" in out2
    assert len(e2e_session.ui.get_audit_hashes()) >= 1


def test_T3_06_preset_export_audit_zero_secrets_and_clear(e2e_session: E2ESession) -> None:
    e2e_session.ui.select_preset("prod_env_trace")
    exported = e2e_session.ui.export_audit_json(e2e_session.io.downloads)
    raw = exported.read_text(encoding="utf-8")
    assert re.search(r"[0-9a-f]{64}", raw, re.I) is not None
    for marker in ("sk-proj-", "AKIA", "eyJhbGci"):
        assert marker not in raw
    e2e_session.ui.clear_audit_log()
    assert e2e_session.ui.get_audit_hashes() == []
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None


def test_T3_07_xss_custom_rule_filereader_and_rehydrate(e2e_session: E2ESession) -> None:
    xss_rule = "<img src=x onerror=alert(2)>"
    e2e_session.ui.add_custom_rule(xss_rule)
    e2e_session.ui.close_open_drawer()

    xss_file = e2e_session.io.uploads / "xss.txt"
    xss_file.write_text("Contact <script>alert(1)</script> at qa@example.com", encoding="utf-8")
    e2e_session.ui.upload_file(xss_file)
    combined = e2e_session.ui.get_prompt_input().input_value() + f" {xss_rule}"
    out = e2e_session.ui.sanitize_text(combined)
    assert "[EMAIL_1]" in out and "[CUSTOM_1]" in out

    restored = e2e_session.ui.rehydrate_text("Reply: [CUSTOM_1] <script>alert(1)</script> [EMAIL_1]")
    assert xss_rule in restored and "qa@example.com" in restored
    assert e2e_session.page.evaluate("() => document.querySelectorAll('img[src=\"x\"]').length") == 0
    e2e_session.net.assert_zero_egress()
    e2e_session.console.assert_no_errors()


def test_T3_08_twelve_emails_plus_chip_toggle_and_rehydrate(e2e_session: E2ESession) -> None:
    emails = [f"user{i}@example.com" for i in range(1, 13)]
    e2e_session.ui.sanitize_text(" ".join(emails) + " 192.0.2.50")
    e2e_session.ui.toggle_category_chip("IPV4")
    assert "192.0.2.50" in e2e_session.ui.get_sanitize_output_text()

    restored = e2e_session.ui.rehydrate_text("To [EMAIL_1], [EMAIL_10], [EMAIL_12] from 192.0.2.50")
    assert restored.strip() == "To user1@example.com, user10@example.com, user12@example.com from 192.0.2.50"


def test_T3_09_strict_mode_industry_pack_stage_a_detectors_counter_sync_and_ram_audit(
    e2e_session: E2ESession,
) -> None:
    drawer = e2e_session.ui.open_rulebook_drawer()
    e2e_session.ui.apply_industry_word_pack("legal")
    first_term = (
        drawer.locator(
            "[data-testid='rules-list'] .rule-term-text, "
            "[data-testid='rules-list'] [data-term], "
            "[data-testid='rules-list'] .rule-term"
        )
        .first.inner_text()
        .strip()
    )
    e2e_session.ui.close_open_drawer()

    e2e_session.ui.set_sensitivity_mode("strict")
    prompt = (
        f"Договор с ООО «Вектор» (подписант Алексей Смирнов), {first_term}, "
        "карта 4276 3800 1234 5678, адрес Москва, ул. Ленина, д. 5, "
        "ID 550e8400-e29b-41d4-a716-446655440000."
    )
    masked = e2e_session.ui.sanitize_text(prompt)
    for tok in ("[ORG_1]", "[FIO_1]", "[CUSTOM_1]", "[POSSIBLE_CARD_1]", "[ADDRESS_1]", "[UUID_1]"):
        assert tok in masked, f"Missing {tok} in {masked!r}"

    count_before = e2e_session.ui.get_telemetry_masked_count()
    assert count_before >= 6
    e2e_session.ui.toggle_vault_entity("[UUID_1]")
    assert e2e_session.ui.get_telemetry_masked_count() == count_before - 1
    e2e_session.ui.toggle_vault_entity("[UUID_1]")
    assert e2e_session.ui.get_telemetry_masked_count() == count_before

    restored = e2e_session.ui.rehydrate_text(e2e_session.ui.get_sanitize_output_text())
    assert restored.strip() == prompt.strip()
    assert len(e2e_session.ui.get_audit_hashes()) >= 1
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None
