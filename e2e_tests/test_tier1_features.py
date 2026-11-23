"""Tier 1: Isolated Happy-Path E2E Feature Coverage (103 Tests: T1-F1-01..T1-F14-10)."""

from __future__ import annotations

import io
import json
import re
import urllib.request
from typing import Any
import zipfile

import pytest

from conftest import E2ESession, EphemeralProKeys
from doc_fixtures import make_synthetic_docx, make_synthetic_pdf, make_synthetic_xlsx
from monitors import (
    fetch_http_response,
    verify_ai_launcher_links,
    verify_allowed_local_storage_keys,
    verify_csp_and_security_headers,
    verify_health_endpoint,
    verify_russian_purity,
)


pytestmark = [pytest.mark.tier1]


def _t1_data(test_cases_data: dict[str, Any], case_id: str) -> dict[str, Any]:
    return dict(test_cases_data["tier1"][case_id])


# ---------------------------------------------------------------------------
# F1: 11 PII/Secret Categories & Deterministic Detection (15 Tests)
# ---------------------------------------------------------------------------


def test_T1_F1_01_api_key_aws(e2e_session: E2ESession, test_cases_data: dict[str, Any]) -> None:
    case = _t1_data(test_cases_data, "T1-F1-01")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    api_rows = [r for r in e2e_session.ui.get_vault_rows() if r.category == "API_KEY"]
    assert len(api_rows) == 2


def test_T1_F1_02_api_key_openai_and_anthropic(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-02")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("API_KEY") >= 2


def test_T1_F1_03_api_key_stripe_and_github(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-03")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out


def test_T1_F1_04_api_key_slack_and_google(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-04")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out


def test_T1_F1_05_jwt_detection(e2e_session: E2ESession, test_cases_data: dict[str, Any]) -> None:
    case = _t1_data(test_cases_data, "T1-F1-05")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert out.strip() == case["expected_output"]
    for raw in case["raw_secrets"]:
        assert raw not in out
    jwt_rows = [r for r in e2e_session.ui.get_vault_rows() if r.category == "JWT"]
    assert len(jwt_rows) == 1


def test_T1_F1_06_credit_card_luhn_valid_formats(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-06")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 3


def test_T1_F1_07_iban_iso7064_mod97_valid(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-07")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("IBAN") == 3


def test_T1_F1_08_ssn_detection(e2e_session: E2ESession, test_cases_data: dict[str, Any]) -> None:
    case = _t1_data(test_cases_data, "T1-F1-08")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert out.strip() == case["expected_output"]
    assert e2e_session.ui.get_category_chip_count("SSN") == 1


def test_T1_F1_09_env_secret_rhs_only_masking(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-09")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert "DB_PASSWORD=[ENV_SECRET_1]" in out
    assert "SERVICE_SECRET=" in out
    assert "[ENV_SECRET_2]" in out
    for raw in case["raw_secrets"]:
        assert raw not in out


def test_T1_F1_10_custom_en_and_cyrillic_rules(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-10")
    for rule in case["rules"]:
        e2e_session.ui.add_custom_rule(rule)
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for rule in case["rules"]:
        assert rule not in out


def test_T1_F1_11_email_detection(e2e_session: E2ESession, test_cases_data: dict[str, Any]) -> None:
    case = _t1_data(test_cases_data, "T1-F1-11")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert out.strip() == case["expected_output"]
    assert e2e_session.ui.get_category_chip_count("EMAIL") == 2


def test_T1_F1_12_phone_intl_and_ru_cis(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-12")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("PHONE") == 3


def test_T1_F1_13_ipv4_detection(e2e_session: E2ESession, test_cases_data: dict[str, Any]) -> None:
    case = _t1_data(test_cases_data, "T1-F1-13")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert out.strip() == case["expected_output"]
    assert e2e_session.ui.get_category_chip_count("IPV4") == 2


def test_T1_F1_14_high_entropy_shannon_detection(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-14")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("HIGH_ENTROPY") == 2


def test_T1_F1_15_deterministic_deduplication_identical_values(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-15")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert out.strip() == case["expected_output"]
    email_rows = [r for r in e2e_session.ui.get_vault_rows() if r.category == "EMAIL"]
    assert len(email_rows) == 2


def test_T1_F1_16_ru_org_detection_and_roundtrip(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-16")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("RU_ORG") == 3
    restored = e2e_session.ui.rehydrate_text(out)
    assert restored.strip() == case["input"].strip()


def test_T1_F1_17_ru_fio_two_word_detection_and_roundtrip(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-17")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("RU_FIO") == 2
    restored = e2e_session.ui.rehydrate_text(out)
    assert restored.strip() == case["input"].strip()


def test_T1_F1_18_possible_card_context_detection_and_roundtrip(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-18")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("POSSIBLE_CARD") == 2
    restored = e2e_session.ui.rehydrate_text(out)
    assert restored.strip() == case["input"].strip()


def test_T1_F1_19_optional_uuid_toggle_off_on_off(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-19")
    assert e2e_session.ui.is_detect_uuid_enabled() is False
    out_off = e2e_session.ui.sanitize_text(case["input"])
    assert case["uuid"] in out_off
    assert case["expected_token"] not in out_off

    e2e_session.ui.set_detect_uuid(True)
    out_on = e2e_session.ui.get_sanitize_output_text()
    assert case["expected_token"] in out_on
    assert case["uuid"] not in out_on
    assert e2e_session.ui.get_category_chip_count("UUID") == 1

    restored = e2e_session.ui.rehydrate_text(out_on)
    assert restored.strip() == case["input"].strip()

    e2e_session.ui.switch_mode("sanitize")
    e2e_session.ui.set_detect_uuid(False)
    out_off_again = e2e_session.ui.get_sanitize_output_text()
    assert case["uuid"] in out_off_again
    assert case["expected_token"] not in out_off_again


def test_T1_F1_20_ru_address_city_capture_and_roundtrip(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t1_data(test_cases_data, "T1-F1-20")
    out = e2e_session.ui.sanitize_text(case["input"])
    for tok in case["expected_tokens"]:
        assert tok in out
    for raw in case["raw_secrets"]:
        assert raw not in out
    assert e2e_session.ui.get_category_chip_count("RU_ADDRESS") == 2
    restored = e2e_session.ui.rehydrate_text(out)
    assert restored.strip() == case["input"].strip()


def test_T1_F1_21_sensitivity_mode_strict_and_reason_tooltips(e2e_session: E2ESession) -> None:
    sample_uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert e2e_session.ui.get_sensitivity_mode() == "normal"
    out_norm = e2e_session.ui.sanitize_text(f"ID {sample_uuid} mail dev@example.com")
    assert sample_uuid in out_norm
    assert "[EMAIL_1]" in out_norm

    e2e_session.ui.set_sensitivity_mode("strict")
    assert e2e_session.ui.get_sensitivity_mode() == "strict"
    out_strict = e2e_session.ui.get_sanitize_output_text()
    assert "[UUID_1]" in out_strict
    assert sample_uuid not in out_strict

    rows = e2e_session.ui.get_vault_rows()
    assert len(rows) >= 2
    reason_texts = [
        r.row_locator.evaluate(
            """el => {
                const target = el.matches('[title], [data-reason], .vault-reason')
                    ? el
                    : el.querySelector('[title], [data-reason], .vault-reason');
                if (!target) return '';
                if (target.classList && target.classList.contains('vault-reason')) {
                    return (target.getAttribute('title') || target.getAttribute('data-reason') || target.textContent || '').trim();
                }
                return (target.getAttribute('title') || target.getAttribute('data-reason') || '').trim();
            }"""
        )
        for r in rows
    ]
    assert any(len(t) > 5 for t in reason_texts)
    verify_russian_purity(e2e_session.page)


# ---------------------------------------------------------------------------
# F2: Reversible Vault & Re-Hydration (5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F2_01_single_entity_rehydrate(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Email alice@example.com about invoice.")
    restored = e2e_session.ui.rehydrate_text("Drafted reply for [EMAIL_1].")
    assert restored.strip() == "Drafted reply for alice@example.com."
    assert e2e_session.ui.get_unresolved_tokens() == []


def test_T1_F2_02_multi_category_rehydrate(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("User bob@example.com IP 198.51.100.7 card 4111 1111 1111 1111")
    restored = e2e_session.ui.rehydrate_text("Notify [EMAIL_1] from [IP_1] on [CARD_1].")
    assert restored.strip() == "Notify bob@example.com from 198.51.100.7 on 4111 1111 1111 1111."


def test_T1_F2_03_repeated_token_in_llm_reply(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Contact dev@example.com")
    restored = e2e_session.ui.rehydrate_text("To: [EMAIL_1]\nCC: [EMAIL_1]")
    assert restored.strip() == "To: dev@example.com\nCC: dev@example.com"


def test_T1_F2_04_cyrillic_and_special_char_restoration(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("ООО «Вектор»")
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("Vendor ООО «Вектор»")
    restored = e2e_session.ui.rehydrate_text("Approved vendor: [CUSTOM_1].")
    assert restored.strip() == "Approved vendor: ООО «Вектор»."


def test_T1_F2_05_unresolved_token_reporting(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Primary a@example.com")
    restored = e2e_session.ui.rehydrate_text("Sent to [EMAIL_1] and [EMAIL_99].")
    assert "a@example.com" in restored
    assert "[EMAIL_99]" in restored
    unresolved = e2e_session.ui.get_unresolved_tokens()
    assert "[EMAIL_99]" in unresolved


# ---------------------------------------------------------------------------
# F3: Category Filter Chips & Per-Entity Toggles (5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F3_01_category_chip_counts_tabular_nums(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Mail u1@example.com, u2@example.com, IP 203.0.113.5")
    assert e2e_session.ui.get_category_chip_count("EMAIL") == 2
    assert e2e_session.ui.get_category_chip_count("IPV4") == 1
    email_chip = e2e_session.ui.get_category_chip("EMAIL")
    has_tabular = email_chip.evaluate(
        """el => {
            const nodes = [el, ...el.querySelectorAll('*')];
            return nodes.some(n => (window.getComputedStyle(n).fontVariantNumeric || '').includes('tabular-nums'));
        }"""
    )
    assert has_tabular, "Expected category chip or count badge to use font-variant-numeric: tabular-nums"


def test_T1_F3_02_disable_category_chip(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Mail u1@example.com, u2@example.com, IP 203.0.113.5")
    e2e_session.ui.toggle_category_chip("IPV4")
    out = e2e_session.ui.get_sanitize_output_text()
    assert "203.0.113.5" in out
    assert "[EMAIL_1]" in out
    ip_rows = [r for r in e2e_session.ui.get_vault_rows() if r.category in ("IP", "IPV4")]
    assert len(ip_rows) == 1
    assert ip_rows[0].enabled is False


def test_T1_F3_03_reenable_category_chip(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Mail u1@example.com, u2@example.com, IP 203.0.113.5")
    e2e_session.ui.toggle_category_chip("IPV4")
    assert "203.0.113.5" in e2e_session.ui.get_sanitize_output_text()
    e2e_session.ui.toggle_category_chip("IPV4")
    out = e2e_session.ui.get_sanitize_output_text()
    assert "[IP_1]" in out
    assert "203.0.113.5" not in out


def test_T1_F3_04_per_entity_toggle_off(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Primary p1@example.com and public support@example.com")
    e2e_session.ui.toggle_vault_entity("support@example.com")
    out = e2e_session.ui.get_sanitize_output_text()
    assert "[EMAIL_1]" in out
    assert "support@example.com" in out
    rows = [r for r in e2e_session.ui.get_vault_rows() if r.category == "EMAIL"]
    assert len(rows) == 2
    assert sum(1 for r in rows if r.enabled) == 1
    assert sum(1 for r in rows if not r.enabled) == 1


def test_T1_F3_05_per_entity_toggle_on(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Primary p1@example.com and public support@example.com")
    e2e_session.ui.toggle_vault_entity("support@example.com")
    assert "support@example.com" in e2e_session.ui.get_sanitize_output_text()
    e2e_session.ui.toggle_vault_entity("support@example.com")
    out = e2e_session.ui.get_sanitize_output_text()
    assert out.strip() == "Primary [EMAIL_1] and public [EMAIL_2]"


def test_T1_F3_06_hide_values_aria_pressed_and_clear_cancels_copied_timer(
    e2e_session: E2ESession,
) -> None:
    e2e_session.ui.sanitize_text("Contact copycheck@example.com")
    assert e2e_session.ui.get_hide_values_pressed() == "false"
    e2e_session.ui.toggle_hide_values()
    assert e2e_session.ui.get_hide_values_pressed() == "true"
    assert "copycheck@example.com" not in e2e_session.ui.get_vault_rows()[0].raw_text
    e2e_session.ui.toggle_hide_values()
    assert e2e_session.ui.get_hide_values_pressed() == "false"

    copy_btn = e2e_session.page.locator("[data-testid='copy-sanitized-btn']").first
    e2e_session.ui.click_copy_output()
    assert copy_btn.get_attribute("data-copied") == "true"
    e2e_session.ui.click_clear_input()
    assert copy_btn.get_attribute("data-copied") is None
    assert copy_btn.is_disabled()
    assert "✓" not in copy_btn.inner_text()


# ---------------------------------------------------------------------------
# F4: Custom Rulebook (localStorage, EN + Cyrillic, Export/Import) (5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F4_01_add_english_custom_rule_and_mask(e2e_session: E2ESession) -> None:
    before_count = e2e_session.ui.get_rulebook_badge_count()
    e2e_session.ui.add_custom_rule("Project Falcon")
    e2e_session.ui.close_open_drawer()
    after_count = e2e_session.ui.get_rulebook_badge_count()
    assert after_count == before_count + 1
    out = e2e_session.ui.sanitize_text("Budget for Project Falcon approved.")
    assert "[CUSTOM_1]" in out
    assert "Project Falcon" not in out


def test_T1_F4_02_add_cyrillic_custom_rule_and_mask(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Иван Петров")
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text("Кандидат Иван Петров прошёл интервью.")
    assert "[CUSTOM_1]" in out
    assert "Иван Петров" not in out


def test_T1_F4_03_rulebook_persistence_across_reload(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Иван Петров")
    e2e_session.ui.close_open_drawer()
    e2e_session.page.reload(wait_until="networkidle")
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_rules_v1') || ''")
    assert "Иван Петров" in stored
    out = e2e_session.ui.sanitize_text("Договор подписал Иван Петров.")
    assert "[CUSTOM_1]" in out
    assert "Иван Петров" not in out


def test_T1_F4_04_delete_custom_rule(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Project Falcon")
    e2e_session.ui.delete_custom_rule("Project Falcon")
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text("Budget for Project Falcon approved.")
    assert out.strip() == "Budget for Project Falcon approved."
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_rules_v1') || ''")
    assert "Project Falcon" not in stored


def test_T1_F4_05_export_and_import_rulebook_json(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Project Falcon")
    e2e_session.ui.add_custom_rule("Иван Петров")
    exported_path = e2e_session.ui.export_rules_json(e2e_session.io.downloads)
    raw_json = exported_path.read_text(encoding="utf-8")
    parsed = json.loads(raw_json)
    assert "Project Falcon" in raw_json and "Иван Петров" in raw_json
    assert isinstance(parsed, (list, dict))

    e2e_session.ui.delete_custom_rule("Project Falcon")
    e2e_session.ui.delete_custom_rule("Иван Петров")
    e2e_session.ui.import_rules_json(exported_path)
    e2e_session.ui.close_open_drawer()

    out = e2e_session.ui.sanitize_text("Project Falcon and Иван Петров.")
    assert "[CUSTOM_1]" in out and "[CUSTOM_2]" in out
    assert "Project Falcon" not in out and "Иван Петров" not in out


def test_T1_F4_06_industry_word_packs_apply_and_mask(e2e_session: E2ESession) -> None:
    drawer = e2e_session.ui.open_rulebook_drawer()
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

    before_count = e2e_session.ui.get_rulebook_badge_count()
    e2e_session.ui.apply_industry_word_pack("legal")
    after_count = e2e_session.ui.get_rulebook_badge_count()
    assert after_count > before_count

    first_rule_term = (
        drawer.locator(
            "[data-testid='rules-list'] .rule-term-text, "
            "[data-testid='rules-list'] [data-term], "
            "[data-testid='rules-list'] .rule-term"
        )
        .first.inner_text()
        .strip()
    )
    assert first_rule_term
    e2e_session.ui.apply_industry_word_pack("legal")
    assert e2e_session.ui.get_rulebook_badge_count() == after_count
    e2e_session.ui.close_open_drawer()

    out = e2e_session.ui.sanitize_text(f"Document clause mentions {first_rule_term}.")
    assert "[CUSTOM_1]" in out
    assert first_rule_term not in out


# ---------------------------------------------------------------------------
# F5: Presets (5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F5_01_load_client_contract_preset(e2e_session: E2ESession) -> None:
    e2e_session.ui.select_preset("client_contract")
    prompt_val = e2e_session.ui.get_prompt_input().input_value()
    out = e2e_session.ui.get_sanitize_output_text()
    assert len(prompt_val.strip()) > 20
    assert len(e2e_session.ui.get_vault_rows()) >= 3
    assert any(tok in out for tok in ("[IBAN_", "[CARD_", "[EMAIL_", "[PHONE_"))


def test_T1_F5_02_load_prod_env_trace_preset(e2e_session: E2ESession) -> None:
    e2e_session.ui.select_preset("prod_env_trace")
    prompt_val = e2e_session.ui.get_prompt_input().input_value()
    out = e2e_session.ui.get_sanitize_output_text()
    cats = {r.category for r in e2e_session.ui.get_vault_rows()}
    assert len(cats) >= 2
    assert any(tok in out for tok in ("[API_KEY_", "[JWT_", "[IP_", "[ENV_SECRET_", "[SECRET_"))
    assert out != prompt_val
    for match in re.finditer(
        r"(?:(?:AKIA|ASIA)[0-9A-Z]{16}|sk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}|"
        r"(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|"
        r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,})",
        prompt_val,
    ):
        assert match.group(0) not in out


def test_T1_F5_03_load_bilingual_cis_hr_preset(e2e_session: E2ESession) -> None:
    e2e_session.ui.select_preset("bilingual_cis_hr")
    prompt_val = e2e_session.ui.get_prompt_input().input_value()
    assert re.search(r"[А-Яа-яЁё]", prompt_val) is not None
    rows = e2e_session.ui.get_vault_rows()
    assert len(rows) >= 3
    cats = {r.category for r in rows}
    assert "PHONE" in cats and "EMAIL" in cats


def test_T1_F5_04_switch_between_presets(e2e_session: E2ESession) -> None:
    e2e_session.ui.select_preset("client_contract")
    first_out = e2e_session.ui.get_sanitize_output_text()
    e2e_session.ui.select_preset("prod_env_trace")
    second_out = e2e_session.ui.get_sanitize_output_text()
    assert second_out != first_out
    assert "[IBAN_" not in second_out


def test_T1_F5_05_preset_and_immediate_rehydrate_roundtrip(e2e_session: E2ESession) -> None:
    e2e_session.ui.select_preset("client_contract")
    original_prompt = e2e_session.ui.get_prompt_input().input_value()
    masked_output = e2e_session.ui.get_sanitize_output_text()
    restored = e2e_session.ui.rehydrate_text(masked_output)
    assert restored == original_prompt


# ---------------------------------------------------------------------------
# F6: Local FileReader Upload (5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F6_01_upload_txt_file(e2e_session: E2ESession) -> None:
    sample = e2e_session.io.uploads / "sample.txt"
    sample.write_text("Contact qa@example.com SSN 123-45-6789", encoding="utf-8")
    e2e_session.ui.upload_file(sample)
    out = e2e_session.ui.get_sanitize_output_text()
    assert "[EMAIL_1]" in out and "[SSN_1]" in out
    e2e_session.net.assert_zero_egress(["qa@example.com", "123-45-6789"])


def test_T1_F6_02_upload_env_file(e2e_session: E2ESession) -> None:
    env_file = e2e_session.io.uploads / "app.env"
    env_file.write_text(
        "STRIPE_API_KEY=sk_test_51SynthTestKey000111222\nDB_PASSWORD=ProdSynthPass99!",
        encoding="utf-8",
    )
    e2e_session.ui.upload_file(env_file)
    out = e2e_session.ui.get_sanitize_output_text()
    assert "DB_PASSWORD=" in out
    assert "[API_KEY_1]" in out and "[ENV_SECRET_1]" in out
    assert "sk_test_51SynthTestKey000111222" not in out
    assert "ProdSynthPass99!" not in out
    e2e_session.net.assert_zero_egress(["ProdSynthPass99!"])


def test_T1_F6_03_upload_json_file(e2e_session: E2ESession) -> None:
    json_file = e2e_session.io.uploads / "payload.json"
    json_file.write_text('{"user":"ops@example.com","ip":"192.0.2.10"}', encoding="utf-8")
    e2e_session.ui.upload_file(json_file)
    out = e2e_session.ui.get_sanitize_output_text()
    assert out.strip() == '{"user":"[EMAIL_1]","ip":"[IP_1]"}'
    e2e_session.net.assert_zero_egress(["ops@example.com"])


def test_T1_F6_04_upload_csv_file(e2e_session: E2ESession) -> None:
    csv_file = e2e_session.io.uploads / "users.csv"
    csv_file.write_text("name,email,phone\nAlice,alice@example.com,+1 415 555 0199", encoding="utf-8")
    e2e_session.ui.upload_file(csv_file)
    out = e2e_session.ui.get_sanitize_output_text()
    assert "Alice,[EMAIL_1],[PHONE_1]" in out
    e2e_session.net.assert_zero_egress(["alice@example.com"])


def test_T1_F6_05_upload_log_and_md_files(e2e_session: E2ESession) -> None:
    log_file = e2e_session.io.uploads / "trace.log"
    log_file.write_text(
        "[ERROR] 203.0.113.9 auth failed for eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.synthSig_12345678",
        encoding="utf-8",
    )
    e2e_session.ui.upload_file(log_file)
    log_out = e2e_session.ui.get_sanitize_output_text()
    assert "[IP_1]" in log_out and "[JWT_1]" in log_out
    assert "203.0.113.9" not in log_out

    md_file = e2e_session.io.uploads / "notes.md"
    md_file.write_text("# Notes\nReach out to lead@example.com", encoding="utf-8")
    e2e_session.ui.upload_file(md_file)
    md_out = e2e_session.ui.get_sanitize_output_text()
    assert "[EMAIL_1]" in md_out
    assert "lead@example.com" not in md_out
    e2e_session.net.assert_zero_egress()


# ---------------------------------------------------------------------------
# F7: Audit Receipts (localStorage + Web Crypto SHA-256) (5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F7_01_audit_receipt_created_on_sanitize(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Secret user alice@example.com card 4111 1111 1111 1111")
    hashes = e2e_session.ui.get_audit_hashes()
    assert len(hashes) >= 1
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')")
    assert stored is None


def test_T1_F7_02_zero_raw_pii_in_audit_store(e2e_session: E2ESession) -> None:
    secrets = ["alice.secret@example.com", "123-45-6789", "AKIAIOSFODNN7EXAMPLE"]
    e2e_session.ui.set_audit_persistence(True)
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("PII " + " ".join(secrets))
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || ''")
    assert re.search(r"[0-9a-f]{64}", stored, re.I) is not None
    drawer_text = e2e_session.ui.get_audit_drawer_text()
    for s in secrets:
        assert s not in stored
        assert s not in drawer_text


def test_T1_F7_03_audit_persistence_across_reload(e2e_session: E2ESession) -> None:
    # RAM-only default clears across reload
    e2e_session.ui.sanitize_text("Secret user ram@example.com")
    assert len(e2e_session.ui.get_audit_hashes()) >= 1
    e2e_session.page.reload(wait_until="networkidle")
    assert e2e_session.ui.get_audit_hashes() == []
    e2e_session.ui.close_open_drawer()

    # Opt-in persistence preserves receipts across reload
    e2e_session.ui.set_audit_persistence(True)
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("Secret user alice@example.com card 4111 1111 1111 1111")
    hashes_before = e2e_session.ui.get_audit_hashes()
    assert len(hashes_before) >= 1
    e2e_session.page.reload(wait_until="networkidle")
    hashes_after = e2e_session.ui.get_audit_hashes()
    assert any(h in hashes_after for h in hashes_before)


def test_T1_F7_04_export_audit_json(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Confidential pii.user@example.com SSN 123-45-6789")
    exported = e2e_session.ui.export_audit_json(e2e_session.io.downloads)
    raw = exported.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert isinstance(parsed, (list, dict))
    assert re.search(r"[0-9a-f]{64}", raw, re.I) is not None
    assert "pii.user@example.com" not in raw
    assert "123-45-6789" not in raw


def test_T1_F7_05_clear_audit_log(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Email clearme@example.com")
    assert len(e2e_session.ui.get_audit_hashes()) >= 1
    e2e_session.ui.clear_audit_log()
    assert e2e_session.ui.get_audit_hashes() == []
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None

    e2e_session.ui.set_audit_persistence(True)
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("Email clearme2@example.com")
    assert e2e_session.page.evaluate("() => Boolean(localStorage.getItem('promptveil_audit_v1'))")
    e2e_session.ui.clear_audit_log()
    assert e2e_session.ui.get_audit_hashes() == []
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || '[]'")
    assert json.loads(stored) == []


# ---------------------------------------------------------------------------
# F8: FastAPI Host, CSP, /health, Security & UI States (6 Tests)
# ---------------------------------------------------------------------------


def test_T1_F8_01_health_endpoint_contract(
    raw_session: E2ESession,
    request: pytest.FixtureRequest,
) -> None:
    if request.config.getoption("--static-only"):
        status, _, _ = fetch_http_response(f"{raw_session.base_url}/health")
        assert status == 404, f"Static-only mode must return 404 on /health, got {status}"
        return
    data = verify_health_endpoint(raw_session.base_url)
    assert data["status"] == "ok"
    assert data["mode"] == "client-side-zero-egress"


def test_T1_F8_02_csp_and_security_headers_on_root(raw_session: E2ESession) -> None:
    headers = verify_csp_and_security_headers(raw_session.base_url)
    assert "connect-src 'self'" in headers["content-security-policy"]


def test_T1_F8_03_static_asset_integrity(e2e_session: E2ESession) -> None:
    e2e_session.net.assert_clean_load()
    e2e_session.console.assert_no_errors()


def test_T1_F8_04_status_pill_and_mode_switch(e2e_session: E2ESession) -> None:
    pill = e2e_session.ui.get_zero_egress_pill()
    assert pill.is_visible()
    e2e_session.ui.switch_mode("rehydrate")
    assert e2e_session.ui.get_rehydrate_input().is_visible()
    e2e_session.ui.switch_mode("sanitize")
    assert e2e_session.ui.get_prompt_input().is_visible()


def test_T1_F8_05_empty_initial_workbench_state(e2e_session: E2ESession) -> None:
    assert e2e_session.ui.get_vault_rows() == []
    assert e2e_session.ui.get_prompt_input().input_value() == ""
    assert e2e_session.ui.get_vault_empty_state_text(), "Expected visible empty-state hint in Vault area"
    e2e_session.console.assert_no_errors()


def test_T1_F8_06_copy_masked_output(e2e_session: E2ESession) -> None:
    out = e2e_session.ui.sanitize_text("Email copy@example.com")
    assert "[EMAIL_1]" in out
    e2e_session.ui.click_copy_output()
    clipboard_text = e2e_session.ui.read_clipboard_text()
    feedback_text = e2e_session.ui.get_copy_feedback_text()
    assert (clipboard_text is not None and "[EMAIL_1]" in clipboard_text) or bool(feedback_text), (
        f"Copy action produced neither clipboard '[EMAIL_1]' ({clipboard_text!r}) "
        f"nor visible copy feedback ({feedback_text!r})"
    )
    e2e_session.console.assert_no_errors()


def test_T1_F8_07_manifest_mime_coop_corp_proof_csp_and_github_links(
    raw_session: E2ESession,
) -> None:
    status, manifest_headers, _ = fetch_http_response(f"{raw_session.base_url}/manifest.webmanifest")
    assert status == 200
    assert manifest_headers.get("content-type", "").lower().startswith("application/manifest+json")

    headers = verify_csp_and_security_headers(raw_session.base_url)
    assert headers.get("cross-origin-opener-policy", "").lower() == "same-origin"
    assert headers.get("cross-origin-resource-policy", "").lower() == "same-origin"

    page = raw_session.page
    page.goto(f"{raw_session.base_url}/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    footer_repo = page.locator("[data-testid='site-footer'] a[href='https://github.com/Aquanti/promptveil']")
    assert footer_repo.count() >= 1 and footer_repo.first.is_visible()

    modal = raw_session.ui.open_privacy_proof_modal("header")
    assert "нарушений CSP в документе приложения: 0" in modal.inner_text()
    modal_repo = modal.locator("a[href='https://github.com/Aquanti/promptveil']")
    assert modal_repo.count() >= 1 and modal_repo.first.is_visible()
    raw_session.ui.close_active_modal()


def test_T1_F8_08_plan_modal_reset_toast_layering_and_proof_pluralization(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    ui.open_plan_request_modal("pro")
    page.locator("[data-testid='plan-req-name']").fill("Анна Тестова")
    page.locator("[data-testid='plan-req-contact']").fill("anna@example.ru")
    page.locator("[data-testid='plan-req-note']").fill("Нужен Pro")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    assert page.locator("[data-testid='plan-request-result']").is_visible()
    ui.close_active_modal()

    ui.open_plan_request_modal("team")
    assert page.locator("[data-testid='plan-req-name']").input_value() == ""
    assert page.locator("[data-testid='plan-req-contact']").input_value() == ""
    assert page.locator("[data-testid='plan-req-note']").input_value() == ""
    assert page.locator("[data-testid='plan-req-seats']").input_value() == "10"
    assert not page.locator("[data-testid='plan-request-alert']").is_visible()
    assert not page.locator("[data-testid='plan-request-result']").is_visible()

    page.locator("[data-testid='plan-req-name']").fill("Анна Тестова")
    page.locator("[data-testid='plan-req-contact']").fill("anna@example.ru")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    assert page.locator("[data-testid='plan-request-result']").is_visible()

    # Invalid submit must hide stale result preview
    page.locator("[data-testid='plan-req-seats']").fill("")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    assert page.locator("[data-testid='plan-request-alert']").is_visible()
    assert not page.locator("[data-testid='plan-request-result']").is_visible()

    page.locator("[data-testid='plan-req-seats']").fill("12")
    page.locator("[data-testid='plan-req-submit-btn']").click()
    page.locator("[data-testid='plan-req-copy-btn']").click()
    z_info = page.evaluate(
        """() => {
            const toast = document.querySelector("[data-testid='status-banner']");
            const dialog = document.querySelector("[data-testid='modal-plan-request']");
            return {
                toastZ: toast ? Number(getComputedStyle(toast).zIndex || 0) : 0,
                dialogZ: dialog ? Number(getComputedStyle(dialog).zIndex || 0) : 0,
                toastVisible: Boolean(toast && !toast.hidden),
            };
        }"""
    )
    assert z_info["toastVisible"] is True
    assert z_info["toastZ"] > z_info["dialogZ"]
    ui.close_active_modal()

    page.evaluate("() => { window.gtag = () => {}; }")
    try:
        modal = ui.open_privacy_proof_modal("header")
        modal_txt = modal.inner_text()
        assert "1 трекер" in modal_txt
        assert "1 трекеров" not in modal_txt
        assert "0 запросов" in modal_txt
        assert "0 байт" in modal_txt
        ui.close_active_modal()
    finally:
        page.evaluate("() => { delete window.gtag; }")


def test_T1_F8_09_en_parity_hreflang_meta_free_tier_and_theme_aria_label(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    page.goto(f"{raw_session.base_url}/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    for hreflang in ("ru", "en", "x-default"):
        assert page.locator(f"link[rel='alternate'][hreflang='{hreflang}']").count() >= 1

    ru_meta = page.evaluate(
        """() => ({
            desc: document.querySelector("meta[name='description']")?.getAttribute('content') || '',
            ogTitle: document.querySelector("meta[property='og:title']")?.getAttribute('content') || '',
            ogLocale: document.querySelector("meta[property='og:locale']")?.getAttribute('content') || '',
            themeLabel: document.querySelector("[data-testid='theme-toggle-btn']")?.getAttribute('aria-label') || '',
        })"""
    )
    ui.switch_language("en")
    en_meta = page.evaluate(
        """() => ({
            desc: document.querySelector("meta[name='description']")?.getAttribute('content') || '',
            ogTitle: document.querySelector("meta[property='og:title']")?.getAttribute('content') || '',
            ogLocale: document.querySelector("meta[property='og:locale']")?.getAttribute('content') || '',
            themeLabel: document.querySelector("[data-testid='theme-toggle-btn']")?.getAttribute('aria-label') || '',
        })"""
    )
    assert en_meta["desc"] != ru_meta["desc"]
    assert en_meta["ogLocale"].lower().startswith("en")
    assert en_meta["themeLabel"] != ru_meta["themeLabel"]

    free_card_txt = page.locator("[data-testid='pricing-card-free']").inner_text()
    assert "$0" in free_card_txt
    for ru_only in ("ИНН", "СНИЛС", "INN", "SNILS"):
        assert ru_only not in free_card_txt

    raw_session.net.phase = "load"
    page.goto(f"{raw_session.base_url}/en/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    assert ui.get_document_lang().lower() == "en"


def test_T1_F8_10_stage_e_copy_open_ai_telegram_cta_and_how_limits_sections(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    how_sec = ui.get_how_it_works_section()
    limits_sec = ui.get_honest_limits_section()
    assert how_sec.is_visible() and limits_sec.is_visible()
    verify_russian_purity(page)

    drawer = ui.click_limits_rulebook_link()
    assert drawer.is_visible()
    ui.close_open_drawer()

    masked = ui.sanitize_text("Contact stagee@example.com")
    assert "[EMAIL_1]" in masked

    def _block_ext(route: Any) -> None:
        route.abort()

    page.context.route("https://chatgpt.com/**", _block_ext)
    page.context.route("https://t.me/**", _block_ext)
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("chatgpt")
        pop_info.value.close()
        assert ui.read_clipboard_text() == masked
        assert ui.get_status_banner_text()

        ui.open_plan_request_modal("pro")
        page.locator("[data-testid='plan-req-name']").fill("Анна")
        page.locator("[data-testid='plan-req-contact']").fill("@anna_test")
        page.locator("[data-testid='plan-req-submit-btn']").click()
        assert "kilkauciha@gmail.com" in page.locator("[data-testid='modal-plan-request']").inner_text()

        tg_link = ui.get_plan_telegram_link()
        assert "https://t.me/supv1rus" in (tg_link.get_attribute("href") or "")
        with page.expect_popup(timeout=3000) as tg_pop:
            ui.copy_plan_for_telegram()
        tg_pop.value.close()
        assert "Pro" in (ui.read_clipboard_text() or "")
        assert ui.get_status_banner_text()
        ui.close_active_modal()
    finally:
        page.context.unroute("https://chatgpt.com/**")
        page.context.unroute("https://t.me/**")

    e2e_session.net.assert_zero_egress(["stagee@example.com"])


# ---------------------------------------------------------------------------
# F9: Persistent AI Launchers (Step 1 & 2) + Gemini (R1 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F9_01_all_six_ai_launchers_including_gemini_contract(e2e_session: E2ESession) -> None:
    page = e2e_session.page
    ui = e2e_session.ui
    bar = ui.get_ai_launchers_bar()
    assert bar.is_visible()

    links = verify_ai_launcher_links(page)
    assert set(links.keys()) == {
        "ai-launcher-chatgpt",
        "ai-launcher-claude",
        "ai-launcher-gemini",
        "ai-launcher-deepseek",
        "ai-launcher-gigachat",
        "ai-launcher-alice",
    }
    gemini = ui.get_ai_launcher("gemini")
    assert gemini.is_visible()
    assert gemini.get_attribute("href") == "https://gemini.google.com/app"
    assert gemini.get_attribute("target") == "_blank"
    assert "noopener" in (gemini.get_attribute("rel") or "").lower()
    assert gemini.inner_text().strip() == "Gemini"


def test_T1_F9_02_launcher_bar_persistent_across_step1_and_step2(e2e_session: E2ESession) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    is_outside_panels = page.evaluate(
        """() => {
            const bar = document.querySelector('#ai-launchers-bar, [data-testid="ai-launchers-bar"]');
            const s1 = document.querySelector('#panel-sanitize, [data-testid="panel-sanitize"]');
            const s2 = document.querySelector('#panel-rehydrate, [data-testid="panel-rehydrate"]');
            return Boolean(bar && s1 && s2 && !s1.contains(bar) && !s2.contains(bar));
        }"""
    )
    assert is_outside_panels is True

    masked = ui.sanitize_text("Send to gemini.step@example.com")
    assert "[EMAIL_1]" in masked
    assert ui.get_ai_launchers_bar().is_visible()
    assert ui.is_ai_launchers_ready() is True

    ui.click_go_rehydrate()
    assert page.locator("[data-testid='panel-rehydrate']").is_visible()
    assert ui.get_ai_launchers_bar().is_visible()
    assert ui.is_ai_launchers_ready() is True
    assert ui.get_ai_launcher("gemini").is_visible()

    ui.switch_mode("sanitize")
    assert page.locator("[data-testid='panel-sanitize']").is_visible()
    ui.switch_mode("rehydrate")
    assert page.locator("[data-testid='panel-rehydrate']").is_visible()
    assert ui.get_ai_launchers_bar().is_visible()
    assert ui.is_ai_launchers_ready() is True


def test_T1_F9_03_click_gemini_on_step1_copies_sanitized_and_opens_popup(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui
    masked = ui.sanitize_text("alice@example.com")
    assert masked == "[EMAIL_1]"

    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        assert ui.read_clipboard_text() == "[EMAIL_1]"
        banner = ui.get_status_banner_text()
        assert banner and re.search(r"скопирован|copied", banner, re.I)
    finally:
        page.context.unroute("https://gemini.google.com/**")

    e2e_session.net.assert_zero_egress(["alice@example.com"])


def test_T1_F9_04_click_launcher_on_step2_flushes_and_copies_sanitized_text(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui
    ui.get_prompt_input().fill("Draft for step2.flush@example.com")
    ui.switch_mode("rehydrate")
    assert page.locator("[data-testid='panel-rehydrate']").is_visible()

    page.context.route("https://claude.ai/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("claude")
        pop_info.value.close()
        copied = ui.read_clipboard_text() or ""
        assert "[EMAIL_1]" in copied
        assert "step2.flush@example.com" not in copied
        assert ui.get_status_banner_text()
    finally:
        page.context.unroute("https://claude.ai/**")

    e2e_session.net.assert_zero_egress(["step2.flush@example.com"])


def test_T1_F9_05_copy_goto_step2_preserves_sanitized_text_for_step2_launchers(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui
    masked = ui.sanitize_text("Contact deepseek.flow@example.com and +79991234567")
    assert "[EMAIL_1]" in masked

    ui.click_copy_goto_step2()
    assert page.locator("[data-testid='panel-rehydrate']").is_visible()
    assert ui.is_ai_launchers_ready() is True

    page.evaluate("async () => navigator.clipboard.writeText('SENTINEL_STEP2')")
    page.context.route("https://chat.deepseek.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("deepseek")
        pop_info.value.close()
        assert ui.read_clipboard_text() == masked
        assert re.search(r"скопирован|copied", ui.get_status_banner_text(), re.I)
    finally:
        page.context.unroute("https://chat.deepseek.com/**")

    e2e_session.net.assert_zero_egress(["deepseek.flow@example.com", "+79991234567"])


# ---------------------------------------------------------------------------
# F10: Ed25519 Pro License System & Pricing (R2 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F10_01_initial_free_badge_pricing_cards_and_ru_en_labels(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    assert ui.get_pro_badge_text() == "Free"
    ui.open_pricing()

    free_card = page.locator("[data-testid='pricing-card-free']")
    free_txt = free_card.inner_text()
    assert "Старт (Free)" in free_txt
    assert re.search(r"0\s*₽\s*/\s*навсегда", free_txt)

    assert page.locator("#pricing-pro-badge, [data-testid='pricing-pro-badge']").inner_text().strip() == "Доступ по ключу"
    assert page.locator("[data-testid='open-pro-modal-btn']").inner_text().strip() == "Получить ключ (Telegram / Почта)"
    assert ui.get_pricing_activate_pro_btn().inner_text().strip() == "Уже есть ключ • Активировать"
    assert page.locator("[data-testid='price-team-value'], #price-team-value").inner_text().strip() == "Лист ожидания"
    assert page.locator("[data-testid='open-team-modal-btn']").inner_text().strip() == "Оставить заявку на пилот"

    ui.switch_language("en")
    assert ui.get_pro_badge_text() == "Free"
    assert page.locator("#pricing-pro-badge, [data-testid='pricing-pro-badge']").inner_text().strip() == "Key-Activated"
    assert page.locator("[data-testid='open-pro-modal-btn']").inner_text().strip() == "Get Key (Telegram / Email)"
    assert ui.get_pricing_activate_pro_btn().inner_text().strip() == "Have a key? • Activate"
    assert page.locator("[data-testid='price-team-value'], #price-team-value").inner_text().strip() == "Waitlist"
    assert page.locator("[data-testid='open-team-modal-btn']").inner_text().strip() == "Request Pilot"


def test_T1_F10_02_activate_pro_key_updates_badge_pricing_and_persists_reload(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    token = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PRO-02", label="Acme Legal")

    ui.open_pro_license_modal("header")
    ui.activate_pro_key(token)
    status_txt = ui.get_pro_status_card_text()
    assert "PV-E2E-PRO-02" in status_txt
    assert "Pro" in status_txt
    assert ui.get_pro_badge_text() == "Pro Активен"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") == token
    ui.close_active_modal()

    ui.open_pricing()
    assert page.locator("#pricing-pro-badge, [data-testid='pricing-pro-badge']").inner_text().strip() == "Pro Активен"
    assert page.locator("[data-testid='pricing-pro-unlocked-note']").is_visible()

    ui.switch_language("en")
    assert ui.get_pro_badge_text() == "Pro Active"
    assert page.locator("#pricing-pro-badge, [data-testid='pricing-pro-badge']").inner_text().strip() == "Pro Active"

    ui.switch_language("ru")
    page.reload(wait_until="networkidle")
    assert ui.get_pro_badge_text() == "Pro Активен"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") == token
    pro_e2e_session.console.assert_no_errors()


def test_T1_F10_03_activate_owner_master_key_displays_owner_pro_badge(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    owner_token = ephemeral_pro_keys.issue_token(
        tier="owner", key_id="PV-OWNER-E2E", label="PromptVeil Owner"
    )

    ui.activate_pro_key(owner_token)
    assert ui.get_pro_badge_text() == "Owner Pro"
    assert "PV-OWNER-E2E" in ui.get_pro_status_card_text()
    ui.close_active_modal()

    ui.open_pricing()
    assert page.locator("#pricing-pro-badge, [data-testid='pricing-pro-badge']").inner_text().strip() == "Owner Pro"

    ui.switch_language("en")
    assert ui.get_pro_badge_text() == "Owner Pro"
    assert page.locator("#pricing-pro-badge, [data-testid='pricing-pro-badge']").inner_text().strip() == "Owner Pro"
    pro_e2e_session.console.assert_no_errors()


def test_T1_F10_04_deactivate_remove_pro_key_reverts_to_free(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    token = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-DEL")

    ui.activate_pro_key(token)
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.remove_pro_key()
    assert ui.get_pro_badge_text() == "Free"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None
    ui.close_active_modal()

    page.reload(wait_until="networkidle")
    assert ui.get_pro_badge_text() == "Free"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None
    pro_e2e_session.console.assert_no_errors()


def test_T1_F10_05_privacy_proof_reports_zero_unknown_keys_with_pro_active(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PROOF"))
    ui.close_active_modal()

    modal = ui.open_privacy_proof_modal("header")
    ui.run_privacy_proof_check()
    ru_txt = modal.inner_text()
    assert "неизвестные ключи: 0" in ru_txt
    assert "0 байт" in ru_txt
    assert "0 запросов" in ru_txt
    ui.close_active_modal()

    ui.switch_language("en")
    modal_en = ui.open_privacy_proof_modal("header")
    ui.run_privacy_proof_check()
    en_txt = modal_en.inner_text()
    assert "unknown keys: 0" in en_txt
    assert "0 bytes" in en_txt
    assert "0 requests" in en_txt
    ui.close_active_modal()
    pro_e2e_session.console.assert_no_errors()


# ---------------------------------------------------------------------------
# F11: Local Batch & .docx/.xlsx/.pdf Document Scrubber (R3 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F11_01_pro_upload_docx_extracts_paragraphs_tables_headers_and_masks(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-DOCX"))
    ui.close_active_modal()

    docx_path = make_synthetic_docx(
        pro_e2e_session.io.uploads / "nda_contract.docx",
        paragraphs=["Contact legal.lead@acme.test regarding settlement."],
        table_rows=[["Counterparty", "INN 7707083893"], ["Card", "4276 3800 1234 5678"]],
        header_text="Confidential owner header@acme.test",
    )
    ui.upload_files([docx_path])

    panel = ui.get_batch_queue_panel()
    assert panel.is_visible()
    items = ui.get_batch_queue_items()
    assert len(items) == 1
    item_txt = items[0].inner_text()
    assert "nda_contract.docx" in item_txt
    for raw_secret in ("legal.lead@acme.test", "7707083893", "4276 3800 1234 5678", "header@acme.test"):
        assert raw_secret not in panel.inner_text()
        assert raw_secret not in ui.get_sanitize_output_text()

    pro_e2e_session.net.assert_zero_egress(
        ["legal.lead@acme.test", "7707083893", "4276 3800 1234 5678", "header@acme.test"]
    )
    pro_e2e_session.console.assert_no_errors()


def test_T1_F11_02_pro_upload_xlsx_extracts_shared_strings_and_sheet_cells(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-XLSX"))
    ui.close_active_modal()

    xlsx_path = make_synthetic_xlsx(
        pro_e2e_session.io.uploads / "registry.xlsx",
        shared_strings=["Client Email", "Phone", "IBAN"],
        rows=[
            ["Client Email", "Phone", "IBAN"],
            ["xlsx.user@example.org", "+7 916 555-01-22", "DE89370400440532013000"],
        ],
    )
    ui.upload_files([xlsx_path])

    panel = ui.get_batch_queue_panel()
    assert panel.is_visible()
    items = ui.get_batch_queue_items()
    assert len(items) == 1
    panel_txt = panel.inner_text()
    assert "registry.xlsx" in panel_txt
    for raw_secret in ("xlsx.user@example.org", "+7 916 555-01-22", "DE89370400440532013000"):
        assert raw_secret not in panel_txt
    assert re.search(r"\[(?:EMAIL|PHONE|IBAN)_1\]", panel_txt + "\n" + ui.get_sanitize_output_text())
    pro_e2e_session.net.assert_zero_egress(["xlsx.user@example.org", "DE89370400440532013000"])


def test_T1_F11_03_pro_upload_pdf_flate_tounicode_extracts_and_masks(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PDF"))
    ui.close_active_modal()

    pdf_path = make_synthetic_pdf(
        pro_e2e_session.io.uploads / "brief_tounicode.pdf",
        text_lines=[
            "Applicant email pdf.client@example.com",
            "Taxpayer SSN 123-45-6789",
        ],
        compressed=True,
        use_tounicode=True,
    )
    ui.upload_files([pdf_path])

    panel = ui.get_batch_queue_panel()
    assert panel.is_visible()
    items = ui.get_batch_queue_items()
    assert len(items) == 1
    combined_visible = panel.inner_text() + "\n" + ui.get_sanitize_output_text()
    assert "pdf.client@example.com" not in combined_visible
    assert "123-45-6789" not in combined_visible
    assert "[EMAIL_1]" in combined_visible
    assert "[SSN_1]" in combined_visible
    pro_e2e_session.net.assert_zero_egress(["pdf.client@example.com", "123-45-6789"])


def test_T1_F11_04_pro_multi_file_batch_queue_download_txt_and_zip(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-BATCH"))
    ui.close_active_modal()

    txt_path = pro_e2e_session.io.uploads / "a_notes.txt"
    txt_path.write_text("Note for batch.a@example.com", encoding="utf-8")
    docx_path = make_synthetic_docx(
        pro_e2e_session.io.uploads / "b_memo.docx",
        paragraphs=["Memo for batch.b@example.com"],
    )
    xlsx_path = make_synthetic_xlsx(
        pro_e2e_session.io.uploads / "c_sheet.xlsx",
        shared_strings=["Contact"],
        rows=[["Contact"], ["batch.c@example.com"]],
    )

    ui.upload_files([txt_path, docx_path, xlsx_path])
    items = ui.get_batch_queue_items()
    assert len(items) == 3

    txt_dl = ui.download_batch_txt(pro_e2e_session.io.downloads)
    txt_content = txt_dl.read_text(encoding="utf-8")
    assert "[EMAIL_1]" in txt_content
    for raw_email in ("batch.a@example.com", "batch.b@example.com", "batch.c@example.com"):
        assert raw_email not in txt_content

    zip_dl = ui.download_batch_zip(pro_e2e_session.io.downloads)
    with zipfile.ZipFile(zip_dl, "r") as zf:
        assert zf.testzip() is None
        names = zf.namelist()
        assert len(names) >= 3
        archive_text = "\n".join(zf.read(n).decode("utf-8", errors="replace") for n in names)
        assert "[EMAIL_1]" in archive_text
        for raw_email in ("batch.a@example.com", "batch.b@example.com", "batch.c@example.com"):
            assert raw_email not in archive_text

    pro_e2e_session.net.assert_zero_egress(
        ["batch.a@example.com", "batch.b@example.com", "batch.c@example.com"]
    )


def test_T1_F11_05_pro_batch_rehydrate_and_clear_all_batch(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-REHYD"))
    ui.close_active_modal()

    docx_path = make_synthetic_docx(
        pro_e2e_session.io.uploads / "rehyd.docx",
        paragraphs=["Send invoice to rehyd.batch@example.com"],
    )
    ui.upload_files([docx_path])
    assert len(ui.get_batch_queue_items()) == 1

    ui.click_batch_rehydrate()
    restored = ui.rehydrate_text("Approved for [EMAIL_1].")
    assert "rehyd.batch@example.com" in restored

    ui.switch_mode("sanitize")
    ui.clear_batch_queue()
    assert ui.get_batch_queue_items() == []
    pro_e2e_session.console.assert_no_errors()


# ---------------------------------------------------------------------------
# F12: Pro Downloads Modal, /downloads/*.zip & MV3 Extension Contract (R4 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F12_01_downloads_zip_endpoint_mime_cache_and_contents(e2e_session: E2ESession) -> None:
    zip_url = f"{e2e_session.base_url.rstrip('/')}/downloads/promptveil-pro-extension.zip"
    with urllib.request.urlopen(zip_url, timeout=5.0) as resp:
        status = int(resp.status)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        payload = resp.read()

    assert status == 200
    assert "application/zip" in headers.get("content-type", "").lower()
    assert headers.get("x-content-type-options", "").lower() == "nosniff"
    assert headers.get("cross-origin-resource-policy", "").lower() == "same-origin"
    assert "max-age=" in headers.get("cache-control", "").lower()

    with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
        assert zf.testzip() is None
        names = set(zf.namelist())
        assert "manifest.json" in names
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest.get("manifest_version") == 3

        action = manifest.get("action") or {}
        default_popup = action.get("default_popup")
        assert isinstance(default_popup, str) and default_popup
        popup_rel = default_popup.lstrip("./")
        assert popup_rel in names
        assert {"dist/popup.bundle.js", "popup.css"}.issubset(names)
        popup_html = zf.read(popup_rel).decode("utf-8")
        assert "popup.css" in popup_html
        assert "dist/popup.bundle.js" in popup_html

        icon_paths: list[str] = [
            p for p in (manifest.get("icons") or {}).values() if isinstance(p, str) and p
        ]
        default_icon = action.get("default_icon")
        if isinstance(default_icon, str) and default_icon:
            icon_paths.append(default_icon)
        elif isinstance(default_icon, dict):
            icon_paths.extend(p for p in default_icon.values() if isinstance(p, str) and p)
        assert len(icon_paths) >= 1
        for icon_path in icon_paths:
            assert icon_path.lstrip("./") in names

        content_scripts = manifest.get("content_scripts") or []
        cs_js: list[str] = [
            p for cs in content_scripts for p in cs.get("js", []) if isinstance(p, str) and p
        ]
        cs_css: list[str] = [
            p for cs in content_scripts for p in cs.get("css", []) if isinstance(p, str) and p
        ]
        assert "dist/content.bundle.js" in cs_js
        assert "content.css" in cs_css
        for asset_path in cs_js + cs_css:
            assert asset_path.lstrip("./") in names

        required_assets = {
            "manifest.json",
            popup_rel,
            "popup.css",
            "dist/popup.bundle.js",
            *{p.lstrip("./") for p in icon_paths},
            *{p.lstrip("./") for p in cs_js + cs_css},
        }
        for asset in required_assets:
            assert zf.getinfo(asset).file_size > 0, f"Empty extension ZIP member: {asset}"

        all_hosts = " ".join(
            list(manifest.get("host_permissions") or [])
            + [m for cs in content_scripts for m in (cs.get("matches") or [])]
        )
        for domain in (
            "chatgpt.com",
            "claude.ai",
            "gemini.google.com",
            "chat.deepseek.com",
            "giga.chat",
            "alice.yandex.ru",
        ):
            assert domain in all_hosts


def test_T1_F12_02_free_user_cannot_use_pro_downloads_while_pro_unlocks_modal(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    free_btn = page.locator("[data-testid='open-pro-downloads-btn'], #open-pro-downloads-btn")
    if free_btn.count() > 0 and free_btn.first.is_visible() and free_btn.first.is_enabled():
        free_btn.first.click()
        page.wait_for_timeout(120)
        assert not page.locator("[data-testid='modal-pro-downloads'], #modal-pro-downloads").is_visible()
        ui.close_active_modal()

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-DL"))
    ui.close_active_modal()

    modal = ui.open_pro_downloads_modal()
    assert modal.is_visible()
    ui.close_active_modal()
    pro_e2e_session.console.assert_no_errors()


def test_T1_F12_03_pro_downloads_modal_1click_zip_download(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-ZIP"))
    ui.close_active_modal()

    zip_path = ui.download_extension_zip(pro_e2e_session.io.downloads)
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path, "r") as zf:
        assert zf.testzip() is None
        assert "manifest.json" in zf.namelist()
    pro_e2e_session.net.assert_zero_egress()
    pro_e2e_session.console.assert_no_errors()


def test_T1_F12_04_pro_downloads_modal_browser_guides_and_ru_en_parity(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-GUIDE"))
    ui.close_active_modal()

    modal_ru = ui.open_pro_downloads_modal()
    ru_txt = modal_ru.inner_text()
    assert "Chrome" in ru_txt
    assert "Edge" in ru_txt
    assert re.search(r"Яндекс|Yandex", ru_txt, re.I)
    verify_russian_purity(page)
    ui.close_active_modal()

    ui.switch_language("en")
    modal_en = ui.open_pro_downloads_modal()
    en_txt = modal_en.inner_text()
    assert "Chrome" in en_txt
    assert "Edge" in en_txt
    assert re.search(r"Yandex", en_txt, re.I)
    ui.close_active_modal()


def test_T1_F12_05_sw_precaches_and_serves_extension_zip_metadata_cleanly(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    status, _, sw_body = fetch_http_response(f"{pro_e2e_session.base_url.rstrip('/')}/sw.js")
    assert status == 200
    assert "/downloads/promptveil-pro-extension.zip" not in sw_body
    assert "/og-image.png" not in sw_body
    assert "/dist/pro-documents-" in sw_body

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-SW"))
    ui.close_active_modal()
    zip_path = ui.download_extension_zip(pro_e2e_session.io.downloads)
    assert zip_path.stat().st_size > 100
    pro_e2e_session.console.assert_no_errors()
    pro_e2e_session.net.assert_zero_egress()


# ---------------------------------------------------------------------------
# F13: Multi-Project Rulebook Profiles, Extended Pro Packs & Templates (R5 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F13_01_default_profile_osnovnoi_in_free_and_pro_create_switch_persist(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    free_opts = ui.get_rulebook_profile_options()
    assert any("Основной" in opt for opt in free_opts)
    ui.close_open_drawer()

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PROF"))
    ui.close_active_modal()

    ui.create_rulebook_profile("Клиент А")
    ui.add_custom_rule("AlphaSecret")
    ui.close_open_drawer()

    assert "[CUSTOM_1]" in ui.sanitize_text("Use AlphaSecret in brief")

    ui.select_rulebook_profile("Основной")
    assert "AlphaSecret" not in ui.get_rulebook_text()
    ui.close_open_drawer()
    assert "AlphaSecret" in ui.sanitize_text("Use AlphaSecret in brief")

    ui.select_rulebook_profile("Клиент А")
    ui.close_open_drawer()
    assert "[CUSTOM_1]" in ui.sanitize_text("Use AlphaSecret in brief")

    stored_profiles = page.evaluate("() => localStorage.getItem('promptveil_profiles_v1') || ''")
    assert "Клиент А" in stored_profiles
    assert "AlphaSecret" in stored_profiles

    page.reload(wait_until="networkidle")
    assert any("Клиент А" in opt for opt in ui.get_rulebook_profile_options())
    ui.select_rulebook_profile("Клиент А")
    ui.close_open_drawer()
    assert "[CUSTOM_1]" in ui.sanitize_text("Reload AlphaSecret check")


def test_T1_F13_02_pro_profile_rename_and_delete(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-REN"))
    ui.close_active_modal()

    ui.create_rulebook_profile("NDA Альфа")
    ui.rename_rulebook_profile("NDA Бета")
    opts_after_rename = ui.get_rulebook_profile_options()
    assert any("NDA Бета" in o for o in opts_after_rename)
    assert not any("NDA Альфа" in o for o in opts_after_rename)

    ui.delete_rulebook_profile()
    opts_after_del = ui.get_rulebook_profile_options()
    assert not any("NDA Бета" in o for o in opts_after_del)
    assert any("Основной" in o for o in opts_after_del)
    pro_e2e_session.console.assert_no_errors()


def test_T1_F13_03_per_profile_json_export_and_import_isolation(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PJSON"))
    ui.close_active_modal()

    ui.create_rulebook_profile("Клиент А")
    ui.add_custom_rule("IsolatedClientToken")
    exported = ui.export_rules_json(pro_e2e_session.io.downloads)
    assert "IsolatedClientToken" in exported.read_text(encoding="utf-8")

    ui.delete_custom_rule("IsolatedClientToken")
    ui.create_rulebook_profile("Клиент Б")
    ui.import_rules_json(exported)
    assert "IsolatedClientToken" in ui.get_rulebook_text()

    ui.select_rulebook_profile("Основной")
    assert "IsolatedClientToken" not in ui.get_rulebook_text()
    ui.close_open_drawer()
    assert "IsolatedClientToken" in ui.sanitize_text("Check IsolatedClientToken")


def test_T1_F13_04_pro_extended_industry_word_packs_apply_and_mask(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PACKS"))
    ui.close_active_modal()

    drawer = ui.open_rulebook_drawer()
    for pack_key in ("corporate_ma", "devsecops", "banking_fintech", "crossborder_nda"):
        pack_btn = drawer.locator(f"[data-testid='word-pack-{pack_key}'], [data-pack='{pack_key}']")
        assert pack_btn.count() >= 1 and pack_btn.first.is_visible()
        assert not pack_btn.first.is_disabled()

    before = ui.get_rulebook_badge_count()
    ui.apply_industry_word_pack("devsecops")
    after_dev = ui.get_rulebook_badge_count()
    assert after_dev > before

    ui.apply_industry_word_pack("corporate_ma")
    assert ui.get_rulebook_badge_count() > after_dev

    first_term = (
        drawer.locator(
            "[data-testid='rules-list'] .rule-term-text, "
            "[data-testid='rules-list'] [data-term], "
            "[data-testid='rules-list'] .rule-term"
        )
        .first.inner_text()
        .strip()
    )
    assert first_term
    ui.close_open_drawer()

    out = ui.sanitize_text(f"Internal note covers {first_term} today.")
    assert re.search(r"\[[A-Z_]+_1\]", out)
    assert first_term not in out


def test_T1_F13_05_pro_prompt_templates_1click_insert_and_mask_ru_en(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-TPL"))
    ui.close_active_modal()

    bar = ui.get_prompt_templates_bar()
    assert bar.is_visible()
    first_btn = bar.locator(".prompt-template-btn, button").first
    tid = (
        first_btn.get_attribute("data-template-id")
        or first_btn.get_attribute("data-template")
        or first_btn.inner_text().strip()
    )
    ui.click_prompt_template(tid)
    raw_ru = ui.get_prompt_input().input_value()
    assert len(raw_ru.strip()) > 10
    assert ui.get_sanitize_output_text().strip()

    ui.switch_language("en")
    bar_en = ui.get_prompt_templates_bar()
    first_btn_en = bar_en.locator(".prompt-template-btn, button").first
    tid_en = (
        first_btn_en.get_attribute("data-template-id")
        or first_btn_en.get_attribute("data-template")
        or first_btn_en.inner_text().strip()
    )
    ui.click_prompt_template(tid_en)
    raw_en = ui.get_prompt_input().input_value()
    assert len(raw_en.strip()) > 10

    stored_profiles = page.evaluate("() => localStorage.getItem('promptveil_profiles_v1') || ''")
    assert raw_ru[:24] not in stored_profiles
    assert raw_en[:24] not in stored_profiles


# ---------------------------------------------------------------------------
# F8 Additions: Spark Admin Themes, CSP, RU Purity & Privacy Proof (R6 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T1_F8_11_pro_modals_and_batch_panel_spark_admin_dark_light_themes(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-THEME"))
    ui.close_active_modal()

    docx_a = make_synthetic_docx(pro_e2e_session.io.uploads / "theme_a.docx", paragraphs=["a@example.com"])
    docx_b = make_synthetic_docx(pro_e2e_session.io.uploads / "theme_b.docx", paragraphs=["b@example.com"])
    ui.upload_files([docx_a, docx_b])

    theme_btn = page.locator("[data-testid='theme-toggle-btn']")
    theme_btn.click()
    assert page.evaluate("() => document.documentElement.dataset.theme") == "dark"
    assert page.evaluate("() => localStorage.getItem('promptveil_theme_v1')") == "dark"

    assert ui.get_batch_queue_panel().is_visible()
    assert ui.get_prompt_templates_bar().is_visible()
    ui.open_pro_license_modal("header")
    ui.close_active_modal()
    ui.open_pro_downloads_modal()
    ui.close_active_modal()
    ui.open_rulebook_drawer()
    ui.close_open_drawer()

    theme_btn.click()
    assert page.evaluate("() => document.documentElement.dataset.theme") == "light"
    assert page.evaluate("() => localStorage.getItem('promptveil_theme_v1')") == "light"
    pro_e2e_session.console.assert_no_errors()


def test_T1_F8_12_strict_csp_no_eval_no_inline_handlers_on_all_new_templates(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    assert page.locator("template").count() >= 6

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-CSP"))
    ui.close_active_modal()

    for opener in (
        lambda: ui.open_pro_license_modal("header"),
        ui.open_pro_downloads_modal,
        lambda: ui.open_plan_request_modal("pro"),
        lambda: ui.open_privacy_proof_modal("header"),
    ):
        opener()
        ui.close_active_modal()

    violations = page.evaluate(
        """() => {
            const bad = [];
            const checkRoot = (root, label) => {
                for (const el of root.querySelectorAll('*')) {
                    if (el.tagName === 'SCRIPT' && (!el.hasAttribute('src') || (el.textContent || '').trim())) {
                        bad.push(`${label}:SCRIPT`);
                    }
                    if (el.tagName === 'STYLE') {
                        bad.push(`${label}:STYLE`);
                    }
                    for (const attr of el.attributes) {
                        const n = attr.name.toLowerCase();
                        if (n === 'style' || n.startsWith('on')) bad.push(`${label}:${n}`);
                        if ((n === 'href' || n === 'src') && attr.value.trim().toLowerCase().startsWith('javascript:')) {
                            bad.push(`${label}:js-url`);
                        }
                    }
                }
            };
            checkRoot(document, 'dom');
            for (const tpl of document.querySelectorAll('template')) {
                checkRoot(tpl.content, tpl.id || 'template');
            }
            return bad;
        }"""
    )
    assert violations == []

    proof = ui.open_privacy_proof_modal("header")
    assert "нарушений CSP в документе приложения: 0" in proof.inner_text()
    ui.close_active_modal()


def test_T1_F8_13_full_ru_purity_across_all_new_r2_to_r5_ui_surfaces(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    ui.open_pro_license_modal("header")
    verify_russian_purity(page)
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-RU"))
    verify_russian_purity(page)
    ui.close_active_modal()

    ui.open_pro_downloads_modal()
    verify_russian_purity(page)
    ui.close_active_modal()

    ui.open_rulebook_drawer()
    verify_russian_purity(page)
    ui.close_open_drawer()

    docx_path = make_synthetic_docx(
        pro_e2e_session.io.uploads / "ru_purity.docx",
        paragraphs=["Почта ru.purity@example.com"],
    )
    ui.upload_files([docx_path])
    assert ui.get_batch_queue_panel().is_visible()
    assert ui.get_prompt_templates_bar().is_visible()
    verify_russian_purity(page)


def test_T1_F8_14_zero_egress_across_full_pro_workflow(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-EGRESS"))
    ui.close_active_modal()

    ui.create_rulebook_profile("Сделка Зеро")
    ui.add_custom_rule("ZeroEgressSecret")
    ui.apply_industry_word_pack("banking_fintech")
    ui.close_open_drawer()

    bar = ui.get_prompt_templates_bar()
    tpl_btn = bar.locator(".prompt-template-btn, button").first
    tid = (
        tpl_btn.get_attribute("data-template-id")
        or tpl_btn.get_attribute("data-template")
        or tpl_btn.inner_text().strip()
    )
    ui.click_prompt_template(tid)

    docx_p = make_synthetic_docx(
        pro_e2e_session.io.uploads / "egress_a.docx",
        paragraphs=["Contact egress.docx@example.com with ZeroEgressSecret"],
    )
    pdf_p = make_synthetic_pdf(
        pro_e2e_session.io.uploads / "egress_b.pdf",
        text_lines=["Contact egress.pdf@example.com"],
    )
    ui.upload_files([docx_p, pdf_p])

    ui.download_batch_zip(pro_e2e_session.io.downloads)
    ui.click_batch_rehydrate()
    ui.rehydrate_text("Done [EMAIL_1]")

    pro_e2e_session.net.assert_zero_egress(
        ["egress.docx@example.com", "egress.pdf@example.com", "ZeroEgressSecret"]
    )
    pro_e2e_session.console.assert_no_errors()


def test_T1_F8_15_privacy_proof_zero_bytes_user_text_with_profiles_and_pro(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PRIV"))
    ui.close_active_modal()

    ui.create_rulebook_profile("СекретПроект")
    ui.add_custom_rule("SecretRuleKeyword")
    ui.close_open_drawer()

    ui.sanitize_text("Sensitive prompt text for proof.user@example.com and SecretRuleKeyword")

    allowed_keys = verify_allowed_local_storage_keys(page)
    assert "promptveil_pro_license_v1" in allowed_keys
    assert "promptveil_profiles_v1" in allowed_keys

    all_storage_values = page.evaluate(
        "() => Object.keys(localStorage).map(k => localStorage.getItem(k) || '').join('\\n')"
    )
    assert "proof.user@example.com" not in all_storage_values
    assert "Sensitive prompt text" not in all_storage_values

    modal = ui.open_privacy_proof_modal("header")
    ui.run_privacy_proof_check()
    txt = modal.inner_text()
    assert "неизвестные ключи: 0" in txt
    assert "0 байт" in txt
    assert "0 запросов" in txt
    ui.close_active_modal()


# ---------------------------------------------------------------------------
# F14: Dedicated /pro/ & /en/pro/ Checkout & Activation Page (R1-R3 — 10 Tests)
# ---------------------------------------------------------------------------


_FORBIDDEN_CHECKOUT_LEGACY_STRINGS: tuple[str, ...] = (
    "30 дней бесплатно",
    "30 days free",
    "490 ₽",
    "390 ₽",
    "1 990 ₽",
    "1 590 ₽",
    "billing-month-btn",
)


def test_T1_F14_01_pro_checkout_routes_render_ru_en_csp_and_static_parity(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    base = raw_session.base_url.rstrip("/")

    verify_csp_and_security_headers(f"{base}/pro/")
    verify_csp_and_security_headers(f"{base}/en/pro/")

    raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    assert raw_session.ui.get_document_lang().lower() == "ru"
    verify_russian_purity(page)
    hreflangs_ru = page.evaluate(
        "() => Array.from(document.querySelectorAll('link[rel=\"alternate\"][hreflang]')).map(el => el.getAttribute('hreflang'))"
    )
    assert {"ru", "en", "x-default"}.issubset(set(hreflangs_ru))
    assert not page.locator("[data-testid='checkout-order-panel'], #checkout-order-panel").is_visible()
    assert raw_session.ui.get_checkout_activation_panel().is_visible()
    ru_body = page.evaluate("() => document.body.innerText || ''")
    for legacy in _FORBIDDEN_CHECKOUT_LEGACY_STRINGS:
        assert legacy not in ru_body

    raw_session.net.phase = "load"
    page.goto(f"{base}/en/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    assert raw_session.ui.get_document_lang().lower() == "en"
    hreflangs_en = page.evaluate(
        "() => Array.from(document.querySelectorAll('link[rel=\"alternate\"][hreflang]')).map(el => el.getAttribute('hreflang'))"
    )
    assert {"ru", "en", "x-default"}.issubset(set(hreflangs_en))
    assert not page.locator("[data-testid='checkout-order-panel'], #checkout-order-panel").is_visible()
    assert raw_session.ui.get_checkout_activation_panel().is_visible()
    en_body = page.evaluate("() => document.body.innerText || ''")
    for legacy in _FORBIDDEN_CHECKOUT_LEGACY_STRINGS:
        assert legacy not in en_body

    raw_session.console.assert_no_errors()


def test_T1_F14_02_main_page_pricing_links_navigate_to_pro_checkout_ru_en(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    base = raw_session.base_url.rstrip("/")

    raw_session.net.phase = "load"
    page.goto(f"{base}/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    ui.open_pricing()
    ru_link = ui.get_pricing_pro_checkout_link()
    assert ru_link.is_visible()
    assert (ru_link.get_attribute("href") or "").rstrip("/").endswith("/pro")
    assert page.locator("[data-testid='open-pro-modal-btn'], #open-pro-modal-btn").first.is_visible()
    assert page.locator("[data-testid='pricing-activate-pro-btn'], #pricing-activate-pro-btn").first.is_visible()
    assert page.locator("[data-testid='open-team-modal-btn'], #open-team-modal-btn").first.is_visible()

    raw_session.net.phase = "load"
    ui.open_pro_checkout_from_pricing()
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()
    assert page.url.rstrip("/").endswith("/pro")
    assert ui.get_document_lang().lower() == "ru"

    raw_session.net.phase = "load"
    page.goto(f"{base}/en/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    ui.open_pricing()
    en_link = ui.get_pricing_pro_checkout_link()
    assert en_link.is_visible()
    assert (en_link.get_attribute("href") or "").rstrip("/").endswith("/en/pro")
    assert page.locator("[data-testid='open-pro-modal-btn'], #open-pro-modal-btn").first.is_visible()
    assert page.locator("[data-testid='pricing-activate-pro-btn'], #pricing-activate-pro-btn").first.is_visible()
    assert page.locator("[data-testid='open-team-modal-btn'], #open-team-modal-btn").first.is_visible()

    raw_session.net.phase = "load"
    ui.open_pro_checkout_from_pricing()
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()
    assert page.url.rstrip("/").endswith("/en/pro")
    assert ui.get_document_lang().lower() == "en"
    raw_session.console.assert_no_errors()


def test_T1_F14_03_checkout_tariff_selection_updates_active_plan_state(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    base = raw_session.base_url.rstrip("/")

    raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    plans = ("pro-monthly", "pro-annual", "pro-lifetime", "team-pack")
    for plan in plans:
        ui.select_checkout_plan(plan)
        assert ui.is_checkout_option_active(ui.get_checkout_plan_locator(plan))
        for other in plans:
            if other != plan:
                assert not ui.is_checkout_option_active(ui.get_checkout_plan_locator(other))

    raw_session.net.assert_zero_egress()
    raw_session.console.assert_no_errors()


def test_T1_F14_04_checkout_payment_method_selection_card_sbp_invoice(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    base = raw_session.base_url.rstrip("/")

    raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    methods = ("card", "sbp", "invoice")
    for method in methods:
        ui.select_checkout_payment(method)
        assert ui.is_checkout_option_active(ui.get_checkout_payment_locator(method))
        for other in methods:
            if other != method:
                assert not ui.is_checkout_option_active(ui.get_checkout_payment_locator(other))

    raw_session.net.assert_zero_egress()
    raw_session.console.assert_no_errors()


def test_T1_F14_05_checkout_submit_generates_pv_ord_receipt_zero_egress(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    base = raw_session.base_url.rstrip("/")

    raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    ui.select_checkout_plan("team-pack")
    ui.select_checkout_payment("invoice")
    ui.fill_checkout_buyer(
        name="Алексей Вектор",
        email="alexey.checkout@example.com",
        company="ООО Вектор",
        accept_terms=True,
    )
    ui.submit_checkout_order()

    order_panel = ui.get_checkout_order_panel()
    assert order_panel.is_visible()
    order_id = ui.get_checkout_order_id()
    assert re.match(r"^PV-ORD-[A-Za-z0-9-]+$", order_id)
    assert "ООО Вектор" in order_panel.inner_text()

    verify_allowed_local_storage_keys(page)
    all_storage = page.evaluate(
        "() => Object.keys(localStorage).map(k => localStorage.getItem(k) || '').join('\\n')"
    )
    assert "PV-ORD-" not in all_storage
    assert "alexey.checkout@example.com" not in all_storage
    assert "Алексей Вектор" not in all_storage

    for req in raw_session.net.requests:
        hay = f"{req.url} {req.post_data or ''}"
        for pii in ("alexey.checkout@example.com", "Алексей Вектор", "ООО Вектор", order_id):
            assert pii not in hay
    raw_session.net.assert_zero_egress(["alexey.checkout@example.com", "ООО Вектор", order_id])
    raw_session.console.assert_no_errors()


def test_T1_F14_06_checkout_copy_and_download_receipt_with_ru_en_parity(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    base = raw_session.base_url.rstrip("/")

    raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    ui.select_checkout_plan("pro-annual")
    ui.select_checkout_payment("sbp")
    ui.fill_checkout_buyer(
        name="Мария Соколова",
        email="maria.receipt@example.com",
        accept_terms=True,
    )
    ui.submit_checkout_order()

    ru_order_id = ui.get_checkout_order_id()
    assert ru_order_id.startswith("PV-ORD-")
    ui.copy_checkout_receipt()
    clip_ru = ui.read_clipboard_text()
    if clip_ru is not None:
        assert ru_order_id in clip_ru
        assert "maria.receipt@example.com" in clip_ru

    ru_receipt = ui.download_checkout_receipt(raw_session.io.downloads)
    assert ru_receipt.is_file() and ru_receipt.stat().st_size > 20
    ru_receipt_txt = ru_receipt.read_text(encoding="utf-8")
    assert ru_order_id in ru_receipt_txt
    assert "maria.receipt@example.com" in ru_receipt_txt
    raw_session.net.assert_zero_egress(["maria.receipt@example.com", ru_order_id])

    raw_session.net.phase = "load"
    page.goto(f"{base}/en/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    ui.select_checkout_plan("pro-monthly")
    ui.select_checkout_payment("card")
    ui.fill_checkout_buyer(
        name="John Doe",
        email="john.receipt@example.com",
        accept_terms=True,
    )
    ui.submit_checkout_order()

    en_order_id = ui.get_checkout_order_id()
    assert en_order_id.startswith("PV-ORD-")
    ui.copy_checkout_receipt()
    clip_en = ui.read_clipboard_text()
    if clip_en is not None:
        assert en_order_id in clip_en
        assert "john.receipt@example.com" in clip_en

    en_receipt = ui.download_checkout_receipt(raw_session.io.downloads)
    assert en_receipt.is_file() and en_receipt.stat().st_size > 20
    en_receipt_txt = en_receipt.read_text(encoding="utf-8")
    assert en_order_id in en_receipt_txt
    assert "john.receipt@example.com" in en_receipt_txt
    raw_session.net.assert_zero_egress(["john.receipt@example.com", en_order_id])
    raw_session.console.assert_no_errors()


def test_T1_F14_07_checkout_offline_pv1_verify_only_and_activate(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    token = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="PV-E2E-CHK-01",
        label="Покупатель Оформление",
    )
    ui.verify_checkout_token_only(token)
    diag = ui.get_checkout_token_diagnostics()
    assert "PV-E2E-CHK-01" in diag
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None
    assert not page.locator("[data-testid='checkout-pro-unlocked'], #checkout-pro-unlocked").is_visible()

    ui.activate_checkout_token()
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") == token
    assert "PV-E2E-CHK-01" in ui.get_checkout_token_diagnostics()
    assert ui.get_checkout_unlocked_panel().is_visible()
    verify_allowed_local_storage_keys(page)

    for req in pro_raw_session.net.requests:
        assert token not in f"{req.url} {req.post_data or ''}"
    pro_raw_session.net.assert_zero_egress([token, "PV-E2E-CHK-01"])
    pro_raw_session.console.assert_no_errors()


def test_T1_F14_08_checkout_url_fragment_code_autofill_and_auto_verify(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    token = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="PV-E2E-FRAG-01",
        label="Фрагмент Покупатель",
    )

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/#code={token}", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    page.wait_for_timeout(250)

    inp_val = page.locator("[data-testid='checkout-token-input'], #checkout-token-input").first.input_value()
    assert token in inp_val
    assert "PV-E2E-FRAG-01" in ui.get_checkout_token_diagnostics()

    for req in pro_raw_session.net.requests:
        hay = f"{req.url} {req.post_data or ''}"
        assert token not in hay
        assert "#code=" not in hay

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/en/pro/#code={token}", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    page.wait_for_timeout(250)

    en_inp_val = page.locator("[data-testid='checkout-token-input'], #checkout-token-input").first.input_value()
    assert token in en_inp_val
    assert "PV-E2E-FRAG-01" in ui.get_checkout_token_diagnostics()

    for req in pro_raw_session.net.requests:
        hay = f"{req.url} {req.post_data or ''}"
        assert token not in hay
        assert "#code=" not in hay
    pro_raw_session.net.assert_zero_egress([token, "PV-E2E-FRAG-01"])
    pro_raw_session.console.assert_no_errors()


def test_T1_F14_09_checkout_pvkey_upload_and_download_roundtrip(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    token = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="PV-E2E-PVKEY-01",
        label="Файл Покупатель",
    )
    pvkey_upload = pro_raw_session.io.uploads / "license.pvkey"
    pvkey_upload.write_text(
        f"# PromptVeil Pro License\n# Key ID: PV-E2E-PVKEY-01\n{token}\n",
        encoding="utf-8",
    )

    ui.upload_checkout_pvkey(pvkey_upload)
    inp_val = page.locator("[data-testid='checkout-token-input'], #checkout-token-input").first.input_value()
    assert token in inp_val
    assert "PV-E2E-PVKEY-01" in ui.get_checkout_token_diagnostics()

    if page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") != token:
        ui.activate_checkout_token()

    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") == token
    assert ui.get_checkout_unlocked_panel().is_visible()

    dl_pvkey = ui.download_checkout_pvkey(pro_raw_session.io.downloads)
    assert dl_pvkey.is_file() and dl_pvkey.suffix.lower() == ".pvkey"
    assert token in dl_pvkey.read_text(encoding="utf-8")

    for req in pro_raw_session.net.requests:
        assert token not in f"{req.url} {req.post_data or ''}"
    pro_raw_session.net.assert_zero_egress([token, "PV-E2E-PVKEY-01"])
    pro_raw_session.console.assert_no_errors()


def test_T1_F14_10_checkout_activation_unlocks_extension_zip_download(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    assert not page.locator("[data-testid='checkout-pro-unlocked'], #checkout-pro-unlocked").is_visible()

    token = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="PV-E2E-ZIP-01",
        label="Архив Покупатель",
    )
    ui.activate_checkout_token(token)
    unlocked = ui.get_checkout_unlocked_panel()
    assert unlocked.is_visible()
    assert unlocked.locator("a[href*='promptveil-pro-extension.zip']").count() >= 1
    assert unlocked.locator("a[href='/'], a[href='../']").count() >= 1

    zip_path = ui.download_checkout_extension_zip(pro_raw_session.io.downloads)
    with zipfile.ZipFile(zip_path, "r") as zf:
        assert zf.testzip() is None
        names = zf.namelist()
        assert "manifest.json" in names
        assert len(names) == 9

    pro_raw_session.net.assert_zero_egress([token, "PV-E2E-ZIP-01"])
    pro_raw_session.console.assert_no_errors()
