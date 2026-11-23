"""Tier 2: Boundary & Corner Cases (89 Tests: T2-F1-01..T2-F14-08)."""

from __future__ import annotations

import base64
from collections import Counter
import io
import json
import re
import time
from typing import Any
import urllib.request
import zipfile

import pytest

from conftest import E2ESession, EphemeralProKeys
from doc_fixtures import (
    make_corrupted_docx,
    make_corrupted_pdf,
    make_oversized_file,
    make_scanned_image_pdf,
    make_synthetic_docx,
    make_synthetic_pdf,
    make_synthetic_xlsx,
)
from monitors import (
    fetch_http_response,
    verify_ai_launcher_links,
    verify_csp_and_security_headers,
    verify_responsive_layout,
)


pytestmark = [pytest.mark.tier2]


def _t2_data(test_cases_data: dict[str, Any], case_id: str) -> dict[str, Any]:
    return dict(test_cases_data["tier2"][case_id])


# ---------------------------------------------------------------------------
# F1 Boundaries (15 Tests)
# ---------------------------------------------------------------------------


def test_T2_F1_01_empty_and_whitespace_input(e2e_session: E2ESession) -> None:
    out_empty = e2e_session.ui.sanitize_text("")
    assert out_empty == ""
    assert e2e_session.ui.get_vault_rows() == []
    out_ws = e2e_session.ui.sanitize_text("   \n\t  \n")
    assert out_ws.strip() == ""
    assert e2e_session.ui.get_vault_rows() == []

    # Clean SessionVault reset when manually cleared back to empty
    out_first = e2e_session.ui.sanitize_text("first@example.com")
    assert "[EMAIL_1]" in out_first
    assert len(e2e_session.ui.get_vault_rows()) == 1
    assert e2e_session.ui.sanitize_text("") == ""
    assert e2e_session.ui.get_vault_rows() == []
    out_second = e2e_session.ui.sanitize_text("second@example.com")
    assert "[EMAIL_1]" in out_second
    assert "[EMAIL_2]" not in out_second


def test_T2_F1_02_oversized_input_55kb_performance(e2e_session: E2ESession) -> None:
    payload = "start@example.com " + ("Lorem ipsum dolor sit amet. " * 2000) + " DE89 3704 0044 0532 0130 00"
    assert len(payload) > 55_000
    t0 = time.monotonic()
    out = e2e_session.ui.sanitize_text(payload, wait_ms=2500)
    elapsed = time.monotonic() - t0
    assert elapsed < 3.0, f"55KB scan took {elapsed:.2f}s (>= 3.0s)"
    assert "[EMAIL_1]" in out and "[IBAN_1]" in out
    assert "start@example.com" not in out


def test_T2_F1_03_invalid_luhn_vs_valid_luhn(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-03")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 2
    for valid in case["valid_values"]:
        assert valid not in out
    for invalid in case["invalid_values"]:
        assert invalid in out


def test_T2_F1_04_invalid_iban_mod97_vs_valid_iban(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-04")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("IBAN") == 1
    assert "[IBAN_1]" in out
    for valid in case["valid_values"]:
        assert valid not in out
    for invalid in case["invalid_values"]:
        assert invalid in out


def test_T2_F1_05_invalid_ssn_area_group_serial(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-05")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("SSN") == 1
    assert "[SSN_1]" in out
    for invalid in case["invalid_values"]:
        assert invalid in out


def test_T2_F1_06_dates_and_ips_not_flagged_as_phones(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-06")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("PHONE") == 0
    for d in case["literal_dates"]:
        assert d in out
    assert "[IP_1]" in out


def test_T2_F1_07_phone_digit_length_boundaries(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-07")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("PHONE") == 1
    assert "[PHONE_1]" in out
    assert case["valid_phone"] not in out
    for inv in case["invalid_phones"]:
        assert inv in out


def test_T2_F1_08_version_strings_and_invalid_octets_not_ipv4(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-08")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("IPV4") == 1
    assert "[IP_1]" in out
    assert case["valid_ip"] not in out
    for inv in case["invalid_ips"]:
        assert inv in out


def test_T2_F1_09_urls_paths_uuids_low_entropy_not_high_entropy(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-09")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("HIGH_ENTROPY") == 0
    assert "550e8400-e29b-41d4-a716-446655440000" in out
    assert "aaaaaaaaaaaaaaaaaaaaaaaa" in out


def test_T2_F1_10_env_placeholders_and_short_rhs_skipped(
    e2e_session: E2ESession, test_cases_data: dict[str, Any]
) -> None:
    case = _t2_data(test_cases_data, "T2-F1-10")
    out = e2e_session.ui.sanitize_text(case["input"])
    assert e2e_session.ui.get_category_chip_count("ENV_SECRET") == 1
    assert "[ENV_SECRET_1]" in out
    assert case["valid_secret"] not in out
    for skipped in case["skipped_values"]:
        assert skipped in out


def test_T2_F1_11_overlap_priority_api_key_over_env_and_entropy(e2e_session: E2ESession) -> None:
    out = e2e_session.ui.sanitize_text("OPENAI_API_KEY=sk-proj-TestSynthKey000111222333444")
    assert out.strip() == "OPENAI_API_KEY=[API_KEY_1]"
    assert e2e_session.ui.get_category_chip_count("HIGH_ENTROPY") == 0


def test_T2_F1_12_overlap_priority_jwt_over_high_entropy(e2e_session: E2ESession) -> None:
    out = e2e_session.ui.sanitize_text(
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyOTk5OSIsImF1ZCI6InByb2QifQ.v9Kp2mQx7Rt4Lz8Nw3Yc6Bf1"
    )
    assert out.strip() == "token=[JWT_1]"
    assert e2e_session.ui.get_category_chip_count("HIGH_ENTROPY") == 0


def test_T2_F1_13_overlap_priority_custom_over_email(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("vip@example.com")
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text("vip@example.com")
    assert out.strip() == "[CUSTOM_1]"
    assert e2e_session.ui.get_category_chip_count("EMAIL") == 0


def test_T2_F1_14_cyrillic_unicode_word_boundary_edge_cases(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Иван")
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text("Иван и Иванов пришли в Иван-город.")
    assert "[CUSTOM_1]" in out
    assert "Иванов" in out


def test_T2_F1_15_longest_first_custom_rule_priority(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Вектор")
    e2e_session.ui.add_custom_rule("ООО Вектор Плюс")
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text("Контрагент ООО Вектор Плюс оплатил.")
    assert out.strip() == "Контрагент [CUSTOM_1] оплатил."
    custom_rows = [r for r in e2e_session.ui.get_vault_rows() if r.category == "CUSTOM"]
    assert len(custom_rows) == 1


def test_T2_F1_16_ru_fio_stopwords_card_priority_and_custom_over_org(
    e2e_session: E2ESession,
) -> None:
    e2e_session.ui.add_custom_rule("ООО «Вектор»")
    e2e_session.ui.close_open_drawer()
    prompt = (
        "Добрый день! Карта 4111 1111 1111 1111, карта 4276 3800 1234 5678, "
        "номер 4276 3800 1234 5678 и компания ООО «Вектор»."
    )
    out = e2e_session.ui.sanitize_text(prompt)
    assert "Добрый день" in out
    assert "[CARD_1]" in out
    assert "[POSSIBLE_CARD_1]" in out
    assert "номер 4276 3800 1234 5678" in out
    assert "[CUSTOM_1]" in out
    assert e2e_session.ui.get_category_chip_count("RU_ORG") == 0
    assert e2e_session.ui.get_category_chip_count("RU_FIO") == 0


# ---------------------------------------------------------------------------
# F2 Boundaries (5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F2_01_email1_vs_email10_and_email11_non_collision(e2e_session: E2ESession) -> None:
    emails = [f"e{i}@example.com" for i in range(1, 12)]
    e2e_session.ui.sanitize_text(" ".join(emails))
    restored = e2e_session.ui.rehydrate_text("First [EMAIL_1], tenth [EMAIL_10], eleventh [EMAIL_11].")
    assert restored.strip() == "First e1@example.com, tenth e10@example.com, eleventh e11@example.com."


def test_T2_F2_02_literal_token_like_text_no_double_substitution(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("tag_[EMAIL_1]")
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("tag_[EMAIL_1] x@example.com")
    restored = e2e_session.ui.rehydrate_text("Item [CUSTOM_1] and [EMAIL_1].")
    assert restored.strip() == "Item tag_[EMAIL_1] and x@example.com."


def test_T2_F2_03_empty_reply_in_rehydrate(e2e_session: E2ESession) -> None:
    restored = e2e_session.ui.rehydrate_text("")
    assert restored == ""
    assert e2e_session.ui.get_unresolved_tokens() == []


def test_T2_F2_04_regex_metacharacters_in_restored_secret(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("API_PASSWORD=a$1$&b\\\\(c)d")
    restored = e2e_session.ui.rehydrate_text("Use [ENV_SECRET_1]")
    assert restored.strip() == "Use a$1$&b\\\\(c)d"


def test_T2_F2_05_multiple_distinct_unresolved_tokens(e2e_session: E2ESession) -> None:
    restored = e2e_session.ui.rehydrate_text("Check [EMAIL_99] and [API_KEY_42] and [CUSTOM_7].")
    assert "[EMAIL_99]" in restored
    assert "[API_KEY_42]" in restored
    assert "[CUSTOM_7]" in restored
    unresolved = e2e_session.ui.get_unresolved_tokens()
    assert {"[EMAIL_99]", "[API_KEY_42]", "[CUSTOM_7]"}.issubset(set(unresolved))


# ---------------------------------------------------------------------------
# F3 Boundaries (5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F3_01_disable_all_categories_simultaneously(e2e_session: E2ESession) -> None:
    raw = "a@example.com +1 415 555 0199 192.0.2.1"
    e2e_session.ui.sanitize_text(raw)
    e2e_session.ui.toggle_category_chip("EMAIL")
    e2e_session.ui.toggle_category_chip("PHONE")
    e2e_session.ui.toggle_category_chip("IPV4")
    assert e2e_session.ui.get_sanitize_output_text().strip() == raw
    rows = e2e_session.ui.get_vault_rows()
    assert len(rows) == 3
    assert all(not r.enabled for r in rows)


def test_T2_F3_02_toggle_zero_count_category_chip(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Email only a@example.com")
    assert e2e_session.ui.get_category_chip_count("IBAN") == 0

    page = e2e_session.page
    e2e_session.ui._expand_all_categories_if_needed("IBAN")
    chips_container = page.locator("[data-testid='category-chips']")
    iban_chip = page.locator("[data-testid='category-chips'] [data-category='IBAN' i]")
    toggle_all_btn = page.locator("[data-testid='toggle-all-categories-btn']")
    has_toggle_all = toggle_all_btn.count() > 0 and toggle_all_btn.first.is_visible()
    has_iban_chip = (iban_chip.count() > 0 and iban_chip.first.is_visible()) or (
        chips_container.count() == 0
    )

    if has_iban_chip or has_toggle_all:
        e2e_session.ui.toggle_category_chip("IBAN")
        assert e2e_session.ui.get_category_chip_count("IBAN") == 0
    else:
        assert all(not iban_chip.nth(i).is_visible() for i in range(iban_chip.count()))

    assert e2e_session.ui.get_category_chip_count("EMAIL") == 1
    assert e2e_session.ui.get_sanitize_output_text().strip() == "Email only [EMAIL_1]"


def test_T2_F3_03_toggle_one_occurrence_of_repeated_value(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("a@example.com, b@example.com, a@example.com")
    e2e_session.ui.toggle_vault_entity("a@example.com")
    assert e2e_session.ui.get_sanitize_output_text().strip() == "a@example.com, [EMAIL_2], a@example.com"


def test_T2_F3_04_entity_toggle_state_when_rescanning_edited_prompt(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("a@example.com b@example.com")
    e2e_session.ui.toggle_vault_entity("a@example.com")
    out = e2e_session.ui.sanitize_text("a@example.com b@example.com c@example.com")
    assert "[EMAIL_" in out
    assert len(e2e_session.ui.get_vault_rows()) >= 2


def test_T2_F3_05_rehydrate_behavior_with_disabled_entity(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("a@example.com b@example.com")
    e2e_session.ui.toggle_vault_entity("a@example.com")
    restored = e2e_session.ui.rehydrate_text("Sent to a@example.com and [EMAIL_2].")
    assert restored.strip() == "Sent to a@example.com and b@example.com."


def test_T2_F3_06_counter_sync_across_repeats_and_toggles(e2e_session: E2ESession) -> None:
    page = e2e_session.page
    e2e_session.ui.add_custom_rule("Секрет")
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("a@example.com a@example.com 192.0.2.5 Секрет")

    def _read_counters() -> tuple[int, int, int]:
        metrics = e2e_session.ui.get_telemetry_masked_count()
        all_chip = page.locator("[data-testid='category-chips'] [data-category='ALL']")
        all_cnt = int(all_chip.get_attribute("data-count") or "0")
        badge_txt = (page.locator("#rehydrate-ready-badge").inner_text() or "").strip()
        badge_matches = re.findall(r"\d+", badge_txt)
        badge_cnt = int(badge_matches[0]) if badge_matches else 0
        return metrics, all_cnt, badge_cnt

    assert _read_counters() == (4, 4, 4)

    e2e_session.ui.toggle_category_chip("IPV4")
    assert _read_counters() == (3, 3, 3)

    e2e_session.ui.toggle_vault_entity("a@example.com")
    assert _read_counters() == (1, 1, 1)

    e2e_session.ui.toggle_vault_entity("Секрет")
    assert _read_counters() == (0, 0, 0)

    e2e_session.ui.toggle_category_chip("IPV4")
    assert _read_counters() == (1, 1, 1)


# ---------------------------------------------------------------------------
# F4 Boundaries (5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F4_01_empty_whitespace_custom_rule_rejected(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("")
    drawer = e2e_session.ui.open_rulebook_drawer()
    assert drawer.locator("#rulebook-alert").is_visible()
    assert e2e_session.page.evaluate(
        "() => document.activeElement === document.querySelector(\"[data-testid='rule-term-input']\")"
    ) is True
    e2e_session.ui.add_custom_rule("   ")
    assert drawer.locator("#rulebook-alert").is_visible()
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_rules_v1') || '[]'")
    parsed = json.loads(stored)
    if isinstance(parsed, dict):
        rules = parsed.get("rules", parsed.get("items"))
        assert isinstance(rules, list), f"Unexpected dict schema in promptveil_rules_v1: {parsed!r}"
    elif isinstance(parsed, list):
        rules = parsed
    else:
        raise AssertionError(f"Unexpected type in promptveil_rules_v1: {type(parsed).__name__}")
    assert all(str(r.get("term", r) if isinstance(r, dict) else r).strip() for r in rules)


def test_T2_F4_02_duplicate_custom_rule_conflict(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("Acme Corp")
    e2e_session.ui.add_custom_rule("Acme Corp")
    drawer_txt = e2e_session.ui.get_rulebook_text()
    assert drawer_txt.count("Acme Corp") == 1


def test_T2_F4_03_regex_special_chars_in_custom_rule(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("C++ (v2.0) [Internal]")
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text("Use C++ (v2.0) [Internal] today.")
    assert "[CUSTOM_1]" in out
    assert "C++ (v2.0) [Internal]" not in out


def test_T2_F4_04_malformed_json_import_rejected(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("KeepMeRule")
    bad_json = e2e_session.io.uploads / "bad.json"
    bad_json.write_text("{not valid json", encoding="utf-8")
    e2e_session.ui.import_rules_json(bad_json)
    drawer = e2e_session.ui.open_rulebook_drawer()
    assert e2e_session.ui.get_visible_error_notice(drawer) or e2e_session.ui.get_visible_error_notice(), (
        "Expected visible error notice for malformed JSON import"
    )
    bad_schema = e2e_session.io.uploads / "bad_schema.json"
    bad_schema.write_text('{"wrong": 123}', encoding="utf-8")
    e2e_session.ui.import_rules_json(bad_schema)
    assert e2e_session.ui.get_visible_error_notice(drawer) or e2e_session.ui.get_visible_error_notice(), (
        "Expected visible error notice for invalid schema JSON import"
    )
    assert "KeepMeRule" in e2e_session.ui.get_rulebook_text()


def test_T2_F4_05_import_json_duplicate_merge(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("RuleA")
    e2e_session.ui.add_custom_rule("RuleB")
    exported = e2e_session.ui.export_rules_json(e2e_session.io.downloads)
    e2e_session.ui.delete_custom_rule("RuleB")
    e2e_session.ui.import_rules_json(exported)
    drawer_txt = e2e_session.ui.get_rulebook_text()
    assert drawer_txt.count("RuleA") == 1
    assert drawer_txt.count("RuleB") == 1


def test_T2_F4_06_rulebook_novalidate_empty_focus_and_stale_duplicate_clear(
    e2e_session: E2ESession,
) -> None:
    drawer = e2e_session.ui.open_rulebook_drawer()
    assert drawer.locator("#add-rule-form").get_attribute("novalidate") is not None

    drawer.locator("[data-testid='add-rule-btn']").click()
    assert drawer.locator("#rulebook-alert").is_visible()
    assert drawer.locator("#rulebook-alert").get_attribute("role") == "alert"
    assert e2e_session.page.evaluate(
        "() => document.activeElement === document.querySelector(\"[data-testid='rule-term-input']\")"
    ) is True

    e2e_session.ui.add_custom_rule("AcmeDup")
    assert drawer.locator("#rulebook-alert").is_visible()
    assert drawer.locator("#rulebook-alert").get_attribute("role") == "status"
    assert "inline-alert--success" in (drawer.locator("#rulebook-alert").get_attribute("class") or "")
    e2e_session.ui.add_custom_rule("AcmeDup")
    assert drawer.locator("#rulebook-alert").is_visible()
    assert drawer.locator("#rulebook-alert").get_attribute("role") == "alert"

    term_input = drawer.locator("[data-testid='rule-term-input']")
    term_input.fill("AcmeNext")
    term_input.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    assert not drawer.locator("#rulebook-alert").is_visible()

    e2e_session.ui.add_custom_rule("AcmeDup")
    assert drawer.locator("#rulebook-alert").is_visible()
    assert drawer.locator("#rulebook-alert").get_attribute("role") == "alert"
    drawer.locator("#rule-case-input").click()
    assert not drawer.locator("#rulebook-alert").is_visible()


# ---------------------------------------------------------------------------
# F5 & F6 Boundaries (5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F6_01_unsupported_file_extension_rejected(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("Safe existing text")
    bad_file = e2e_session.io.uploads / "dummy.png"
    bad_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    e2e_session.ui.upload_file(bad_file)
    assert e2e_session.ui.get_prompt_input().input_value() == "Safe existing text"
    assert e2e_session.ui.get_visible_error_notice(), "Expected visible error notice for unsupported .png file"
    e2e_session.net.assert_zero_egress()


def test_T2_F6_02_empty_zero_byte_txt_file(e2e_session: E2ESession) -> None:
    empty_file = e2e_session.io.uploads / "empty.txt"
    empty_file.write_bytes(b"")
    e2e_session.ui.upload_file(empty_file)
    e2e_session.net.assert_zero_egress()


def test_T2_F6_03_utf8_cyrillic_non_ascii_filename_csv(e2e_session: E2ESession) -> None:
    csv_file = e2e_session.io.uploads / "отчёт_клиенты.csv"
    csv_file.write_text("ФИО,Телефон\nМария Соколова,+7 903 555 12 34", encoding="utf-8-sig")
    e2e_session.ui.upload_file(csv_file)
    out = e2e_session.ui.get_sanitize_output_text()
    assert "ФИО,Телефон" in out
    assert "[FIO_1],[PHONE_1]" in out
    assert "Мария Соколова" not in out
    assert "\ufffd" not in out


def test_T2_F6_04_large_local_log_file_60kb(e2e_session: E2ESession) -> None:
    chunk = "2026-11-19 INFO worker heartbeat ok\n" * 1700
    content = (
        "u1@example.com 192.0.2.10\n"
        + chunk
        + "u2@example.com 198.51.100.20 u3@example.com\n"
    )
    assert len(content.encode("utf-8")) > 60_000
    large_log = e2e_session.io.uploads / "large.log"
    large_log.write_text(content, encoding="utf-8")
    t0 = time.monotonic()
    e2e_session.ui.upload_file(large_log)
    elapsed = time.monotonic() - t0
    assert elapsed < 3.0
    out = e2e_session.ui.get_sanitize_output_text()
    assert "[EMAIL_1]" in out and "[EMAIL_3]" in out and "[IP_2]" in out
    e2e_session.net.assert_zero_egress()


def test_T2_F5_01_preset_reselection_after_user_edit(e2e_session: E2ESession) -> None:
    e2e_session.ui.select_preset("client_contract")
    first_prompt = e2e_session.ui.get_prompt_input().input_value()
    e2e_session.ui.sanitize_text("")
    assert e2e_session.ui.get_prompt_input().input_value() == ""
    e2e_session.ui.select_preset("client_contract")
    assert e2e_session.ui.get_prompt_input().input_value() == first_prompt


# ---------------------------------------------------------------------------
# F7 & F8 Boundaries (10 Tests)
# ---------------------------------------------------------------------------


def test_T2_F8_01_xss_script_in_prompt_and_output(e2e_session: E2ESession) -> None:
    out = e2e_session.ui.sanitize_text("<script>window.__xss=1;alert(1)</script> mail x@example.com")
    assert "<script>window.__xss=1;alert(1)</script>" in out
    assert "[EMAIL_1]" in out
    assert e2e_session.page.evaluate("() => window.__xss === undefined") is True


def test_T2_F8_02_xss_img_onerror_in_custom_rule_and_vault(e2e_session: E2ESession) -> None:
    payload = "<img src=x onerror=window.__xssImg=1>"
    e2e_session.ui.add_custom_rule(payload)
    e2e_session.ui.close_open_drawer()
    out = e2e_session.ui.sanitize_text(f"Ping {payload}")
    assert "[CUSTOM_1]" in out
    assert e2e_session.page.evaluate("() => document.querySelectorAll('img[src=\"x\"]').length") == 0
    assert e2e_session.page.evaluate("() => window.__xssImg === undefined") is True


def test_T2_F8_03_xss_payload_in_rehydrate_reply(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("x@example.com")
    restored = e2e_session.ui.rehydrate_text("<svg onload=window.__xssSvg=1>Hello [EMAIL_1]</svg>")
    assert "x@example.com" in restored
    assert e2e_session.page.evaluate("() => document.querySelectorAll('svg[onload]').length") == 0
    assert e2e_session.page.evaluate("() => window.__xssSvg === undefined") is True


def test_T2_F8_04_csp_blocks_external_fetch(e2e_session: E2ESession) -> None:
    with e2e_session.console.allow_expected_csp_errors():
        blocked = e2e_session.page.evaluate(
            """async () => {
                try {
                    await fetch('https://example.com/leak');
                    return false;
                } catch (err) {
                    return true;
                }
            }"""
        )
    assert blocked is True


def test_T2_F8_05_corrupted_localstorage_recovery(raw_session: E2ESession) -> None:
    raw_session.page.goto(f"{raw_session.base_url}/", wait_until="networkidle")
    raw_session.page.evaluate(
        """() => {
            localStorage.setItem('promptveil_audit_persist_v1', 'true');
            localStorage.setItem('promptveil_rules_v1', '{broken');
            localStorage.setItem('promptveil_audit_v1', '{also_broken');
        }"""
    )
    raw_session.page.reload(wait_until="networkidle")
    assert raw_session.ui.get_prompt_input().is_visible()
    out = raw_session.ui.sanitize_text("Recover test@example.com")
    assert "[EMAIL_1]" in out


def test_T2_F7_01_audit_hash_determinism_and_distinctness(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("x@example.com")
    h1 = e2e_session.ui.get_audit_hashes()
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("x@example.com")
    h2 = e2e_session.ui.get_audit_hashes()
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.sanitize_text("y@example.com")
    h3 = e2e_session.ui.get_audit_hashes()
    assert len(h1) >= 1 and len(h2) >= 2 and len(h3) >= 3
    c1 = Counter(h1)
    c2 = Counter(h2)
    # Same input processed twice increases occurrence frequency of its deterministic SHA-256 digest(s)
    assert any(c2[h] > c1[h] for h in c1), f"Expected recurring hash count increase: h1={h1}, h2={h2}"
    # Distinct input introduces at least one brand-new SHA-256 digest
    assert len(set(h3) - set(h2)) >= 1, f"Expected new distinct hash for y@example.com: h2={h2}, h3={h3}"


def test_T2_F7_02_audit_receipt_after_rehydrate_zero_raw_pii(e2e_session: E2ESession) -> None:
    e2e_session.ui.sanitize_text("SSN 123-45-6789")
    e2e_session.ui.rehydrate_text("OK [SSN_1]")
    hashes = e2e_session.ui.get_audit_hashes()
    assert len(hashes) >= 2
    assert "123-45-6789" not in e2e_session.ui.get_audit_drawer_text()
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None


def test_T2_F7_03_clear_audit_log_idempotency(e2e_session: E2ESession) -> None:
    e2e_session.ui.clear_audit_log()
    e2e_session.ui.clear_audit_log()
    assert e2e_session.ui.get_audit_hashes() == []


def test_T2_F7_04_audit_ram_default_opt_in_persist_and_uncheck_clears_storage(
    e2e_session: E2ESession,
) -> None:
    e2e_session.ui.sanitize_text("RAM default a@example.com")
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None
    assert len(e2e_session.ui.get_audit_hashes()) >= 1
    e2e_session.page.reload(wait_until="networkidle")
    assert e2e_session.ui.get_audit_hashes() == []
    e2e_session.ui.close_open_drawer()

    e2e_session.ui.sanitize_text("Opt in b@example.com")
    e2e_session.ui.set_audit_persistence(True)
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || ''")
    assert re.search(r"[0-9a-f]{64}", stored, re.I) is not None
    e2e_session.page.reload(wait_until="networkidle")
    assert len(e2e_session.ui.get_audit_hashes()) >= 1

    e2e_session.ui.set_audit_persistence(False)
    assert e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None


def test_T2_F8_06_404_on_non_existent_static_path(raw_session: E2ESession) -> None:
    status, _, _ = fetch_http_response(f"{raw_session.base_url}/nonexistent-path-xyz")
    assert status == 404


def test_T2_F8_07_query_string_fragment_isolation(raw_session: E2ESession) -> None:
    raw_session.page.goto(
        f"{raw_session.base_url}/?utm_source=<script>alert(1)</script>",
        wait_until="networkidle",
    )
    assert raw_session.ui.get_prompt_input().is_visible()
    raw_session.console.assert_no_errors()


# ---------------------------------------------------------------------------
# F9 Boundaries: Persistent AI Launchers & Gemini (R1 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F9_01_launchers_empty_input_and_clipboard_denied_fallback(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    assert ui.is_ai_launchers_ready() is False
    ui.sanitize_text("temp.clear@example.com")
    assert ui.is_ai_launchers_ready() is True
    ui.click_clear_input()
    assert ui.is_ai_launchers_ready() is False

    ui.sanitize_text("clip.fail@example.com")
    page.evaluate(
        """() => {
            Object.defineProperty(navigator, 'clipboard', {
                configurable: true,
                value: { writeText: () => Promise.reject(new Error('blocked')) },
            });
            document.execCommand = () => false;
        }"""
    )

    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        banner_alert = page.locator("[data-testid='status-banner'][role='alert']")
        banner_alert.wait_for(state="visible", timeout=3000)
        alert_text = banner_alert.inner_text().strip()
        assert alert_text == "Доступ к буферу обмена ограничен — используйте Ctrl+C / Cmd+C."
    finally:
        page.context.unroute("https://gemini.google.com/**")

    e2e_session.console.assert_no_errors()


def test_T2_F9_02_fast_click_launcher_under_debounce_flushes_latest_input(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    ui.sanitize_text("old.prompt@example.com")
    inp = ui.get_prompt_input()
    inp.fill("fast.gemini@example.com")

    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        copied = ui.read_clipboard_text() or ""
        assert copied == "[EMAIL_2]"
        assert "[EMAIL_1]" not in copied
        assert "fast.gemini@example.com" not in copied
        assert "old.prompt@example.com" not in copied
    finally:
        page.context.unroute("https://gemini.google.com/**")

    restored = ui.rehydrate_text(copied)
    assert "fast.gemini@example.com" in restored
    assert "old.prompt@example.com" not in restored

    e2e_session.net.assert_zero_egress(["fast.gemini@example.com", "old.prompt@example.com"])


def test_T2_F9_03_launcher_on_step2_with_auto_sanitize_off_still_masks(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    ui.set_auto_sanitize(False)
    ui.get_prompt_input().fill("Send manual.ai@example.com safely")
    ui.switch_mode("rehydrate")

    page.evaluate("async () => navigator.clipboard.writeText('SENTINEL_STEP2')")
    page.context.route("https://chatgpt.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("chatgpt")
        pop_info.value.close()
        copied = ui.read_clipboard_text() or ""
        assert copied == "Send [EMAIL_1] safely"
        assert "manual.ai@example.com" not in copied
        assert re.search(r"скопирован|copied", ui.get_status_banner_text(), re.I)
    finally:
        page.context.unroute("https://chatgpt.com/**")

    e2e_session.net.assert_zero_egress(["manual.ai@example.com"])


def test_T2_F9_04_launcher_after_clear_and_reset_clears_ready_state(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    ui.sanitize_text("clear.leak@example.com")
    assert ui.is_ai_launchers_ready() is True
    ui.click_clear_input()
    ui.switch_mode("rehydrate")
    assert ui.is_ai_launchers_ready() is False

    ui.switch_mode("sanitize")
    ui.sanitize_text("reset.leak@example.com")
    assert ui.is_ai_launchers_ready() is True
    ui.click_reset_session_to_zero("workbench")
    ui.switch_mode("rehydrate")
    assert ui.is_ai_launchers_ready() is False

    page.evaluate("() => navigator.clipboard.writeText('SENTINEL_CLEAN')")
    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        clipboard_now = ui.read_clipboard_text() or ""
        assert clipboard_now == "SENTINEL_CLEAN"
        assert "reset.leak@example.com" not in clipboard_now
    finally:
        page.context.unroute("https://gemini.google.com/**")


def test_T2_F9_05_mobile_390x844_launchers_step1_and_step2_tap_targets_and_overflow(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    verify_responsive_layout(page, 390, 844)
    ui.sanitize_text("mobile.launcher@example.com")
    verify_ai_launcher_links(page)

    pills = page.locator("#ai-launchers-bar .ai-launcher-pill")
    assert pills.count() == 6
    for idx in range(6):
        box = pills.nth(idx).bounding_box()
        assert box is not None
        assert box["height"] >= 43.5
        assert box["width"] >= 43.5

    ui.switch_mode("rehydrate")
    verify_responsive_layout(page, 390, 844)
    assert ui.is_ai_launchers_ready() is True
    for idx in range(6):
        pill = pills.nth(idx)
        assert pill.is_visible()
        box = pill.bounding_box()
        assert box is not None
        assert box["height"] >= 43.5
        assert box["width"] >= 43.5


# ---------------------------------------------------------------------------
# F10 Boundaries: Ed25519 Pro License System & Pricing (R2 — 6 Tests)
# ---------------------------------------------------------------------------


def test_T2_F10_01_reject_malformed_empty_and_wrong_prefix_pro_keys(
    pro_e2e_session: E2ESession,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    bad_payload_b64 = base64.urlsafe_b64encode(b"not-json").decode("ascii").rstrip("=")
    dummy_sig_b64 = base64.urlsafe_b64encode(b"\x01" * 64).decode("ascii").rstrip("=")

    invalid_tokens = [
        "",
        "   \t\n  ",
        f"PV2.{bad_payload_b64}.{dummy_sig_b64}",
        "PV1.onlytwo",
        "PV1.not!b64!.sig!",
        f"PV1.{bad_payload_b64}.{dummy_sig_b64}",
    ]
    ui.open_pro_license_modal("header")
    for token in invalid_tokens:
        ui.activate_pro_key(token)
        alert = page.locator("#pro-license-alert, [data-testid='pro-license-alert']")
        assert alert.is_visible()
        assert ui.get_pro_badge_text() == "Free"
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    ui.close_active_modal()
    pro_e2e_session.console.assert_no_errors()


def test_T2_F10_02_reject_tampered_payload_or_invalid_ed25519_signature(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    valid = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-TAMPER")
    prefix, payload_b64, sig_b64 = valid.split(".")
    assert prefix == "PV1"

    # Tamper payload: escalate tier from "pro" to "owner" while keeping original signature
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    payload_obj = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    payload_obj["tier"] = "owner"
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload_obj, separators=(",", ":")).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    tampered_payload_token = f"PV1.{tampered_payload_b64}.{sig_b64}"

    # Tamper signature: flip first character cleanly
    flipped_char = "B" if sig_b64[0] != "B" else "C"
    tampered_sig_token = f"PV1.{payload_b64}.{flipped_char}{sig_b64[1:]}"

    ui.open_pro_license_modal("header")
    for bad_token in (tampered_payload_token, tampered_sig_token):
        ui.activate_pro_key(bad_token)
        alert = page.locator("#pro-license-alert, [data-testid='pro-license-alert']")
        assert alert.is_visible()
        assert "Ed25519" in alert.inner_text()
        assert ui.get_pro_badge_text() == "Free"
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    ui.close_active_modal()


def test_T2_F10_03_reject_expired_pro_token_exp_boundary(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    expired_token = ephemeral_pro_keys.issue_token(
        tier="pro", key_id="PV-E2E-EXP", exp="2020-01-01T00:00:00.000Z"
    )
    ui.open_pro_license_modal("header")
    ui.activate_pro_key(expired_token)
    alert = page.locator("#pro-license-alert, [data-testid='pro-license-alert']")
    assert alert.is_visible()
    assert re.search(r"ист[её]к|expired", alert.inner_text(), re.I)
    assert ui.get_pro_badge_text() == "Free"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    future_token = ephemeral_pro_keys.issue_token(
        tier="pro", key_id="PV-E2E-FUT", exp="2099-12-31T23:59:59.000Z"
    )
    ui.activate_pro_key(future_token)
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.remove_pro_key()
    assert ui.get_pro_badge_text() == "Free"

    lifetime_token = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-LIFE", exp=None)
    ui.activate_pro_key(lifetime_token)
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.close_active_modal()


def test_T2_F10_04_corrupted_localstorage_pro_license_recovery(
    pro_raw_session: E2ESession,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    page.goto(f"{pro_raw_session.base_url}/", wait_until="networkidle")

    for corrupt_val in ("{broken_json", "PV1.bad.sig"):
        page.evaluate(
            "val => localStorage.setItem('promptveil_pro_license_v1', val)",
            corrupt_val,
        )
        page.reload(wait_until="networkidle")
        assert ui.get_pro_badge_text() == "Free"
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    assert "[EMAIL_1]" in ui.sanitize_text("Recover free@example.com")
    pro_raw_session.console.assert_no_errors()


def test_T2_F10_05_pure_js_ed25519_fallback_when_webcrypto_ed25519_unavailable(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    page.evaluate(
        """() => {
            const failVerify = () => Promise.reject(
                new DOMException('Ed25519 is not supported', 'NotSupportedError')
            );
            if (globalThis.SubtleCrypto && SubtleCrypto.prototype) {
                SubtleCrypto.prototype.verify = failVerify;
            }
            if (globalThis.crypto && globalThis.crypto.subtle) {
                try {
                    globalThis.crypto.subtle.verify = failVerify;
                } catch {
                    Object.defineProperty(globalThis.crypto.subtle, 'verify', {
                        configurable: true,
                        value: failVerify,
                    });
                }
            }
        }"""
    )

    valid_token = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PUREJS")
    ui.activate_pro_key(valid_token)
    assert ui.get_pro_badge_text() == "Pro Активен"
    assert "PV-E2E-PUREJS" in ui.get_pro_status_card_text()

    ui.remove_pro_key()
    assert ui.get_pro_badge_text() == "Free"

    prefix, payload_b64, sig_b64 = valid_token.split(".")
    flipped = "B" if sig_b64[0] != "B" else "C"
    tampered_token = f"{prefix}.{payload_b64}.{flipped}{sig_b64[1:]}"
    ui.activate_pro_key(tampered_token)
    assert page.locator("#pro-license-alert, [data-testid='pro-license-alert']").is_visible()
    assert ui.get_pro_badge_text() == "Free"
    ui.close_active_modal()
    pro_e2e_session.console.assert_no_errors()


def test_T2_F10_06_mobile_390x844_pro_badge_modal_and_pricing_layout(
    pro_e2e_session: E2ESession,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    verify_responsive_layout(page, 390, 844)
    badge = page.locator("[data-testid='open-pro-license-btn'], #open-pro-license-btn").first
    assert badge.is_visible()
    badge_box = badge.bounding_box()
    assert badge_box is not None and badge_box["height"] >= 43.5 and badge_box["width"] >= 43.5

    modal = ui.open_pro_license_modal("header")
    assert modal.is_visible()
    verify_responsive_layout(page, 390, 844)
    act_box = page.locator("[data-testid='pro-license-activate-btn']").bounding_box()
    assert act_box is not None and act_box["height"] >= 43.5
    ui.close_active_modal()

    ui.open_pricing()
    verify_responsive_layout(page, 390, 844)
    for testid in ("pricing-card-free", "pricing-card-pro", "pricing-card-team"):
        card = page.locator(f"[data-testid='{testid}']")
        assert card.is_visible()
        cbox = card.bounding_box()
        assert cbox is not None and cbox["x"] >= -0.5 and (cbox["x"] + cbox["width"]) <= 390.5


# ---------------------------------------------------------------------------
# F11 Boundaries: Local Batch & .docx/.xlsx/.pdf Scrubber (R3 — 6 Tests)
# ---------------------------------------------------------------------------


def test_T2_F11_01_free_user_docx_pdf_xlsx_and_over_2mb_show_upgrade_prompt(
    e2e_session: E2ESession,
) -> None:
    ui = e2e_session.ui
    ui.get_prompt_input().fill("Baseline safe text")

    docx_p = make_synthetic_docx(e2e_session.io.uploads / "free_block.docx", paragraphs=["x@example.com"])
    pdf_p = make_synthetic_pdf(e2e_session.io.uploads / "free_block.pdf", text_lines=["y@example.com"])
    xlsx_p = make_synthetic_xlsx(
        e2e_session.io.uploads / "free_block.xlsx",
        shared_strings=["Mail"],
        rows=[["Mail"], ["z@example.com"]],
    )
    over_2mb = make_oversized_file(
        e2e_session.io.uploads / "free_over_2mb.txt", 2 * 1024 * 1024 + 4096, ext=".txt"
    )

    for doc_path in (docx_p, pdf_p, xlsx_p):
        ui.upload_files([doc_path])
        banner = ui.get_file_pro_upgrade_banner()
        assert banner.is_visible()
        assert ui.get_prompt_input().input_value() == "Baseline safe text"

    ui.upload_files([over_2mb])
    notice = ui.get_visible_error_notice()
    assert re.search(r"2\s*(?:mb|мб)", notice, re.I)
    assert ui.get_prompt_input().input_value() == "Baseline safe text"
    e2e_session.net.assert_zero_egress(["x@example.com", "y@example.com", "z@example.com"])


def test_T2_F11_02_corrupted_docx_xlsx_and_encrypted_pdf_rejected_cleanly(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-CORRUPT"))
    ui.close_active_modal()

    bad_docx = make_corrupted_docx(pro_e2e_session.io.uploads / "broken.docx")
    bad_xlsx = pro_e2e_session.io.uploads / "missing_sheets.xlsx"
    with zipfile.ZipFile(bad_xlsx, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
    bad_pdf = make_corrupted_pdf(pro_e2e_session.io.uploads / "broken.pdf")
    encrypted_pdf = pro_e2e_session.io.uploads / "encrypted.pdf"
    encrypted_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Filter /Standard /V 2 /R 3 >>\nendobj\ntrailer\n<< /Encrypt 2 0 R >>\n%%EOF\n"
    )

    for bad_path in (bad_docx, bad_xlsx, bad_pdf, encrypted_pdf):
        ui.upload_files([bad_path])
        err = ui.get_visible_error_notice() or ui.get_status_banner_text()
        assert err

    pro_e2e_session.console.assert_no_errors()


def test_T2_F11_03_scanned_image_only_pdf_shows_honest_ru_en_notice(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-SCAN"))
    ui.close_active_modal()

    scan_pdf = make_scanned_image_pdf(pro_e2e_session.io.uploads / "scan_only.pdf")
    ui.upload_files([scan_pdf])
    ru_notice = ui.get_visible_error_notice() or ui.get_status_banner_text()
    if not ru_notice:
        batch_panel = pro_e2e_session.page.locator("[data-testid='batch-queue-panel'], #batch-queue-panel").first
        if batch_panel.count() > 0 and batch_panel.is_visible():
            ru_notice = ui.get_batch_queue_panel().inner_text()
    assert re.search(r"скан|изображ|ocr|текст\w*\s+не\s+найден|без\s+текст", ru_notice, re.I)

    ui.switch_language("en")
    ui.upload_files([scan_pdf])
    en_notice = ui.get_visible_error_notice() or ui.get_status_banner_text()
    if not en_notice:
        batch_panel = pro_e2e_session.page.locator("[data-testid='batch-queue-panel'], #batch-queue-panel").first
        if batch_panel.count() > 0 and batch_panel.is_visible():
            en_notice = ui.get_batch_queue_panel().inner_text()
    assert re.search(r"scan|image|ocr|no\s+(?:extractable\s+)?text", en_notice, re.I)
    pro_e2e_session.console.assert_no_errors()


def test_T2_F11_04_pro_50mb_boundary_accepted_and_over_50mb_rejected(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-50MB"))
    ui.close_active_modal()

    over_50mb = make_oversized_file(
        pro_e2e_session.io.uploads / "too_large_50mb.txt",
        50 * 1024 * 1024 + 1024,
        ext=".txt",
    )
    ui.upload_files([over_50mb])
    err = ui.get_visible_error_notice() or ui.get_status_banner_text()
    assert re.search(r"50\s*(?:mb|мб)", err, re.I)

    valid_3mb = make_oversized_file(
        pro_e2e_session.io.uploads / "valid_3mb.txt",
        3 * 1024 * 1024,
        ext=".txt",
    )
    ui.upload_files([valid_3mb])
    assert len(ui.get_prompt_input().input_value()) >= 1024 or len(ui.get_batch_queue_items()) >= 1
    pro_e2e_session.console.assert_no_errors()


def test_T2_F11_05_mixed_valid_and_invalid_batch_plus_cyrillic_filenames(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-MIX"))
    ui.close_active_modal()

    valid_docx = make_synthetic_docx(
        pro_e2e_session.io.uploads / "договор_клиента.docx",
        paragraphs=["Contact cyr.batch@example.com"],
    )
    corrupt_pdf = make_corrupted_pdf(pro_e2e_session.io.uploads / "повреждённый.pdf")
    valid_csv = pro_e2e_session.io.uploads / "клиенты.csv"
    valid_csv.write_text("email\ncsv.batch@example.com\n", encoding="utf-8")

    ui.upload_files([valid_docx, corrupt_pdf, valid_csv])
    panel_txt = ui.get_batch_queue_panel().inner_text()
    assert "договор_клиента.docx" in panel_txt
    assert "клиенты.csv" in panel_txt
    assert "\ufffd" not in panel_txt
    assert "cyr.batch@example.com" not in panel_txt
    assert "csv.batch@example.com" not in panel_txt
    assert len(ui.get_batch_queue_items()) >= 2
    pro_e2e_session.console.assert_no_errors()


def test_T2_F11_06_mobile_390x844_batch_queue_and_upgrade_banner_layout(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    verify_responsive_layout(page, 390, 844)
    docx_a = make_synthetic_docx(pro_e2e_session.io.uploads / "mob_a.docx", paragraphs=["m1@example.com"])
    xlsx_b = make_synthetic_xlsx(
        pro_e2e_session.io.uploads / "mob_b.xlsx",
        shared_strings=["Mail"],
        rows=[["Mail"], ["m2@example.com"]],
    )
    ui.upload_files([docx_a])
    assert ui.get_file_pro_upgrade_banner().is_visible()
    verify_responsive_layout(page, 390, 844)

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-MOBBATCH"))
    ui.close_active_modal()
    ui.upload_files([docx_a, xlsx_b])

    panel = ui.get_batch_queue_panel()
    assert panel.is_visible()
    verify_responsive_layout(page, 390, 844)
    for btn_sel in (
        "[data-testid='batch-clear-btn'], #batch-clear-btn",
        "[data-testid='batch-download-txt-btn'], #batch-download-txt-btn",
        "[data-testid='batch-download-zip-btn'], #batch-download-zip-btn",
        "[data-testid='batch-rehydrate-btn'], #batch-rehydrate-btn",
    ):
        btn = panel.locator(btn_sel).first
        if btn.is_visible():
            box = btn.bounding_box()
            assert box is not None and box["height"] >= 43.5


# ---------------------------------------------------------------------------
# F12 Boundaries: Pro Downloads Modal, /downloads/*.zip & MV3 Extension (R4 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F12_01_downloads_missing_or_path_traversal_returns_404(
    raw_session: E2ESession,
) -> None:
    base = raw_session.base_url.rstrip("/")
    st_missing, _, _ = fetch_http_response(f"{base}/downloads/nonexistent.zip")
    assert st_missing == 404

    st_trav, _, body_trav = fetch_http_response(f"{base}/downloads/..%2F..%2Fapp/main.py")
    assert st_trav != 200
    assert "FastAPI" not in body_trav


def test_T2_F12_02_pro_downloads_modal_blocked_after_key_removal(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-REM"))
    ui.close_active_modal()
    modal = ui.open_pro_downloads_modal()
    assert modal.is_visible()
    ui.close_active_modal()

    ui.remove_pro_key()
    ui.close_active_modal()
    assert ui.get_pro_badge_text() == "Free"

    dl_trigger = page.locator("[data-testid='open-pro-downloads-btn'], #open-pro-downloads-btn")
    if dl_trigger.count() > 0 and dl_trigger.first.is_visible() and dl_trigger.first.is_enabled():
        dl_trigger.first.click()
        page.wait_for_timeout(120)
        assert not page.locator("[data-testid='modal-pro-downloads'], #modal-pro-downloads").is_visible()


def test_T2_F12_03_pro_downloads_modal_reopen_idempotency_and_escape_focus(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-REOPEN"))
    ui.close_active_modal()

    modal = ui.open_pro_downloads_modal()
    assert modal.is_visible()
    assert page.locator("[data-testid='modal-pro-downloads'], #modal-pro-downloads").count() == 1

    page.keyboard.press("Tab")
    in_modal = page.evaluate(
        """() => {
            const m = document.querySelector("[data-testid='modal-pro-downloads'], #modal-pro-downloads");
            return Boolean(m && m.contains(document.activeElement));
        }"""
    )
    assert in_modal is True

    page.keyboard.press("Escape")
    page.wait_for_timeout(120)
    assert not modal.is_visible()

    reopened = ui.open_pro_downloads_modal()
    assert reopened.is_visible()
    assert page.locator("[data-testid='modal-pro-downloads'], #modal-pro-downloads").count() == 1
    ui.close_active_modal()


def test_T2_F12_04_extension_zip_contains_zero_secrets_and_exact_six_ai_hosts(
    e2e_session: E2ESession,
) -> None:
    zip_url = f"{e2e_session.base_url.rstrip('/')}/downloads/promptveil-pro-extension.zip"
    with urllib.request.urlopen(zip_url, timeout=5.0) as resp:
        assert int(resp.status) == 200
        payload = resp.read()

    expected_origin_patterns = {
        "https://chatgpt.com/*",
        "https://claude.ai/*",
        "https://gemini.google.com/*",
        "https://chat.deepseek.com/*",
        "https://giga.chat/*",
        "https://alice.yandex.ru/*",
    }
    with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
        assert zf.testzip() is None
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        host_perms = [
            p for p in (manifest.get("host_permissions") or []) if isinstance(p, str)
        ]
        cs_matches = [
            m
            for cs in (manifest.get("content_scripts") or [])
            for m in (cs.get("matches") or [])
            if isinstance(m, str)
        ]
        all_matches = host_perms + cs_matches

        for entry in all_matches:
            for forbidden in ("<all_urls>", "*://*/*", "https://*/*", "http://*/*"):
                assert forbidden not in entry, f"Forbidden wildcard {forbidden!r} in {entry!r}"

        assert len(cs_matches) >= 6
        assert set(all_matches) == expected_origin_patterns

        for member in zf.namelist():
            if member.endswith((".js", ".json", ".html", ".css", ".txt")):
                content = zf.read(member).decode("utf-8", errors="replace")
                for secret_marker in ("BEGIN PRIVATE KEY", "PV-CLIENT-"):
                    assert secret_marker not in content
                assert re.search(r"PV1\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}", content) is None


def test_T2_F12_05_mobile_390x844_pro_downloads_modal_and_cta_tap_targets(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-MOBDL"))
    ui.close_active_modal()
    ui.close_open_drawer()

    verify_responsive_layout(page, 390, 844)
    modal = ui.open_pro_downloads_modal()
    assert modal.is_visible()
    verify_responsive_layout(page, 390, 844)

    dl_btn = modal.locator("[data-testid='download-extension-zip-btn'], #download-extension-zip-btn").first
    box = dl_btn.bounding_box()
    assert box is not None and box["height"] >= 43.5
    ui.close_active_modal()


# ---------------------------------------------------------------------------
# F13 Boundaries: Multi-Project Rulebook Profiles, Packs & Templates (R5 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F13_01_free_user_cannot_create_custom_profile_or_apply_pro_packs(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    drawer = ui.open_rulebook_drawer()
    before_storage = page.evaluate("() => localStorage.getItem('promptveil_profiles_v1')")
    create_btn = drawer.locator("[data-testid='profile-create-btn'], #profile-create-btn").first
    if create_btn.is_visible() and not create_btn.is_disabled():
        name_input = drawer.locator("[data-testid='profile-name-input'], #profile-name-input")
        if name_input.count() > 0 and name_input.first.is_visible():
            name_input.first.fill("ShouldNotCreate")
        create_btn.click()
        page.wait_for_timeout(120)
        assert "ShouldNotCreate" not in (
            page.evaluate("() => localStorage.getItem('promptveil_profiles_v1') || ''")
        )

    before_rules = ui.get_rulebook_badge_count()
    for pack_key in ("corporate_ma", "devsecops", "banking_fintech", "crossborder_nda"):
        pack_btn = drawer.locator(f"[data-testid='word-pack-{pack_key}'], [data-pack='{pack_key}']").first
        if pack_btn.is_visible() and not pack_btn.is_disabled():
            pack_btn.click()
            page.wait_for_timeout(100)
    assert ui.get_rulebook_badge_count() == before_rules
    assert page.evaluate("() => localStorage.getItem('promptveil_profiles_v1')") == before_storage
    ui.close_open_drawer()


def test_T2_F13_02_empty_duplicate_and_xss_profile_name_rejected_inert(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-PROFVAL"))
    ui.close_active_modal()

    drawer = ui.open_rulebook_drawer()
    initial_opts = ui.get_rulebook_profile_options()

    for bad_name in ("", "   ", "Основной"):
        ui.create_rulebook_profile(bad_name)
        assert ui.get_rulebook_profile_options() == initial_opts
        alert = drawer.locator("#rulebook-alert, [role='alert']")
        assert alert.count() >= 1 and alert.first.is_visible()

    ui.create_rulebook_profile("Клиент А")
    after_create = ui.get_rulebook_profile_options()
    assert len(after_create) == len(initial_opts) + 1
    ui.create_rulebook_profile("Клиент А")
    assert ui.get_rulebook_profile_options() == after_create

    xss_name = "<img src=x onerror=window.__xssProf=1>"
    ui.create_rulebook_profile(xss_name)
    assert page.evaluate("() => window.__xssProf === undefined") is True
    assert page.evaluate("() => document.querySelectorAll('img[src=\"x\"]').length") == 0
    ui.close_open_drawer()


def test_T2_F13_03_cannot_delete_default_osnovnoi_profile(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-DELDEF"))
    ui.close_active_modal()

    ui.open_rulebook_drawer()
    ui.delete_rulebook_profile()
    opts = ui.get_rulebook_profile_options()
    assert any("Основной" in o for o in opts)
    ui.close_open_drawer()
    pro_e2e_session.console.assert_no_errors()


def test_T2_F13_04_corrupted_localstorage_profiles_recovery(
    pro_raw_session: E2ESession,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    page.goto(f"{pro_raw_session.base_url}/", wait_until="networkidle")

    for bad_json in ("{broken", "[null, {}]"):
        page.evaluate("val => localStorage.setItem('promptveil_profiles_v1', val)", bad_json)
        page.reload(wait_until="networkidle")
        opts = ui.get_rulebook_profile_options()
        assert any("Основной" in o for o in opts)
        ui.close_open_drawer()

    pro_raw_session.console.assert_no_errors()


def test_T2_F13_05_mobile_390x844_rulebook_profiles_packs_and_templates_fit(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-MOBPROF"))
    ui.close_active_modal()

    ui.create_rulebook_profile("Клиент А")
    ui.create_rulebook_profile("NDA Бета")
    ui.close_open_drawer()

    verify_responsive_layout(page, 390, 844)
    tpl_bar = ui.get_prompt_templates_bar()
    assert tpl_bar.is_visible()
    tpl_btns = tpl_bar.locator(".prompt-template-btn, button")
    for idx in range(tpl_btns.count()):
        b = tpl_btns.nth(idx)
        if b.is_visible():
            box = b.bounding_box()
            assert box is not None and box["height"] >= 43.5

    drawer = ui.open_rulebook_drawer()
    verify_responsive_layout(page, 390, 844)
    dbox = drawer.bounding_box()
    assert dbox is not None and dbox["x"] >= -0.5 and (dbox["x"] + dbox["width"]) <= 390.5
    ui.close_open_drawer()


# ---------------------------------------------------------------------------
# F8 Boundary Additions: CSP, Retranslation, Quota & Mobile 390x844 (R6 — 5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F8_08_csp_blocks_fetch_and_eval_even_when_pro_unlocked(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-CSPUNLOCK"))
    ui.close_active_modal()
    ui.create_rulebook_profile("CSP Профиль")
    ui.add_custom_rule("CspRuleSecret")
    ui.close_open_drawer()

    with pro_e2e_session.console.allow_expected_csp_errors():
        blocked = page.evaluate(
            """async () => {
                const cspEvents = [];
                const onViolation = (e) => {
                    cspEvents.push({
                        effectiveDirective: e.effectiveDirective || '',
                        violatedDirective: e.violatedDirective || '',
                    });
                };
                document.addEventListener('securitypolicyviolation', onViolation);
                try {
                    const s = document.createElement('script');
                    s.textContent = 'window.__cspInlineProbe = 1;';
                    document.head.appendChild(s);
                    s.remove();

                    try {
                        setTimeout('window.__cspTimerEvalProbe = 1;', 0);
                    } catch {
                        // Ignore synchronous CSP throw if any
                    }

                    let fetchBlocked = false;
                    try {
                        await fetch('https://example.com/csp-probe');
                    } catch {
                        fetchBlocked = true;
                    }

                    await new Promise((resolve) => setTimeout(resolve, 150));

                    return {
                        inlineProbeUndefined: window.__cspInlineProbe === undefined,
                        timerEvalProbeUndefined: window.__cspTimerEvalProbe === undefined,
                        fetchBlocked,
                        cspEvents,
                        inlineHandlerCount: document.querySelectorAll('[onclick], [onerror], [onload]').length,
                    };
                } finally {
                    document.removeEventListener('securitypolicyviolation', onViolation);
                }
            }"""
        )
    assert blocked["inlineProbeUndefined"] is True
    assert blocked["timerEvalProbeUndefined"] is True
    assert blocked["fetchBlocked"] is True
    assert len(blocked["cspEvents"]) >= 2
    directives = [
        (ev.get("effectiveDirective") or ev.get("violatedDirective") or "").lower()
        for ev in blocked["cspEvents"]
    ]
    assert any(d.startswith("script-src") for d in directives)
    assert any(d.startswith("connect-src") for d in directives)
    assert blocked["inlineHandlerCount"] == 0


def test_T2_F8_09_banner_retranslation_ru_en_for_pro_and_batch_notices(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    docx_p = make_synthetic_docx(e2e_session.io.uploads / "retrans.docx", paragraphs=["x@example.com"])
    ui.upload_files([docx_p])
    ru_banner = ui.get_file_pro_upgrade_banner()
    ru_txt = ru_banner.inner_text().strip()
    assert ru_txt

    ui.switch_language("en")
    en_banner = ui.get_file_pro_upgrade_banner()
    assert en_banner.is_visible()
    en_txt = en_banner.inner_text().strip()
    assert en_txt and en_txt != ru_txt

    ui.open_pro_license_modal("header")
    ui.activate_pro_key("PV1.bad.sig")
    en_alert = page.locator("#pro-license-alert, [data-testid='pro-license-alert']").inner_text()
    assert re.search(r"ed25519|malformed|invalid", en_alert, re.I)
    ui.close_active_modal()

    ui.switch_language("ru")
    ui.open_pro_license_modal("header")
    ui.activate_pro_key("PV1.bad.sig")
    ru_alert = page.locator("#pro-license-alert, [data-testid='pro-license-alert']").inner_text()
    assert re.search(r"подпис|поврежд", ru_alert, re.I)
    ui.close_active_modal()


def test_T2_F8_10_404_page_and_en_route_csp_headers_preserved(
    raw_session: E2ESession,
) -> None:
    base = raw_session.base_url.rstrip("/")
    verify_csp_and_security_headers(f"{base}/en/")
    verify_csp_and_security_headers(f"{base}/404.html")

    st_missing, headers_missing, _ = fetch_http_response(f"{base}/nonexistent-csp-route")
    assert st_missing == 404
    csp_missing = headers_missing.get("content-security-policy", "").lower()
    assert "script-src 'self'" in csp_missing
    assert "connect-src 'self'" in csp_missing

    raw_session.page.goto(f"{base}/en/", wait_until="networkidle")
    assert raw_session.ui.get_document_lang().lower() == "en"
    raw_session.page.goto(f"{base}/404.html", wait_until="networkidle")
    raw_session.console.assert_no_errors()


def test_T2_F8_11_quota_exceeded_during_pro_activation_or_profile_save(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    page.evaluate(
        """() => {
            Storage.prototype.setItem = function() {
                throw new DOMException('QuotaExceededError', 'QuotaExceededError');
            };
        }"""
    )

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-QUOTA"))
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.close_active_modal()

    ui.add_custom_rule("QuotaRuleInRam")
    ui.close_open_drawer()
    alert = page.locator("[data-testid='status-banner'][role='alert'], [role='alert']").first
    assert alert.is_visible()
    assert "[CUSTOM_1]" in ui.sanitize_text("Keep QuotaRuleInRam working in RAM")
    pro_e2e_session.console.assert_no_errors()


def test_T2_F8_12_mobile_390x844_all_new_interactive_controls_44px_and_zero_overflow(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-MOBALL"))
    ui.close_active_modal()

    docx_a = make_synthetic_docx(pro_e2e_session.io.uploads / "mob_all_a.docx", paragraphs=["a@example.com"])
    xlsx_b = make_synthetic_xlsx(
        pro_e2e_session.io.uploads / "mob_all_b.xlsx",
        shared_strings=["Mail"],
        rows=[["Mail"], ["b@example.com"]],
    )
    ui.upload_files([docx_a, xlsx_b])

    def _assert_44px(loc_str: str) -> None:
        loc = page.locator(loc_str)
        for idx in range(loc.count()):
            el = loc.nth(idx)
            if el.is_visible():
                box = el.bounding_box()
                assert box is not None and box["height"] >= 43.5, f"{loc_str}[{idx}] height={box}"

    for theme in ("light", "dark"):
        cur_theme = page.evaluate("() => document.documentElement.dataset.theme || 'light'")
        if cur_theme != theme:
            page.locator("[data-testid='theme-toggle-btn']").click()
        for lang in ("ru", "en"):
            if ui.get_document_lang().lower() != lang:
                ui.switch_language(lang)

            verify_responsive_layout(page, 390, 844)
            _assert_44px("#ai-launchers-bar .ai-launcher-pill")
            _assert_44px("#batch-queue-panel button")
            _assert_44px("#prompt-templates-bar button")

            ui.switch_mode("rehydrate")
            verify_responsive_layout(page, 390, 844)
            _assert_44px("#ai-launchers-bar .ai-launcher-pill")
            ui.switch_mode("sanitize")

            ui.open_pricing()
            verify_responsive_layout(page, 390, 844)

            ui.open_pro_license_modal("header")
            verify_responsive_layout(page, 390, 844)
            _assert_44px("#modal-pro-license .pro-license-form button, #modal-pro-license .modal-footer button")
            ui.close_active_modal()

            ui.open_pro_downloads_modal()
            verify_responsive_layout(page, 390, 844)
            _assert_44px(
                "#modal-pro-downloads .modal-footer button, "
                "#download-extension-zip-btn, "
                "#modal-pro-downloads button:not(.drawer-close)"
            )
            ui.close_active_modal()

            ui.open_rulebook_drawer()
            verify_responsive_layout(page, 390, 844)
            ui.close_open_drawer()


# ---------------------------------------------------------------------------
# F14 Boundaries: /pro/ & /en/pro/ Checkout Validation, Tokens & Mobile (R1-R3 — 8 Tests)
# ---------------------------------------------------------------------------


def test_T2_F14_01_checkout_rejects_empty_and_invalid_buyer_name_or_email(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    base = raw_session.base_url.rstrip("/")

    invalid_cases = (
        ("", "valid@example.com"),
        ("   ", "valid@example.com"),
        ("Ivan", ""),
        ("Ivan", "not-an-email"),
        ("Ivan", "user@"),
        ("Ivan", "@domain.com"),
        ("Ivan", "bad space@example.com"),
    )

    for route in ("/pro/", "/en/pro/"):
        raw_session.net.phase = "load"
        page.goto(f"{base}{route}", wait_until="networkidle")
        raw_session.net.assert_clean_load()
        raw_session.net.start_interactive_phase()

        for bad_name, bad_email in invalid_cases:
            ui.fill_checkout_buyer(name=bad_name, email=bad_email, accept_terms=True)
            ui.submit_checkout_order()
            order_panel = page.locator("[data-testid='checkout-order-panel'], #checkout-order-panel")
            assert not order_panel.is_visible()
            has_invalid_control = bool(
                page.evaluate(
                    """() => {
                        const n = document.querySelector('#checkout-name, [data-testid="checkout-name"]');
                        const e = document.querySelector('#checkout-email, [data-testid="checkout-email"]');
                        return Boolean((n && !n.checkValidity()) || (e && !e.checkValidity()));
                    }"""
                )
            )
            err_notice = ui.get_visible_error_notice()
            assert has_invalid_control or bool(err_notice)

    raw_session.net.assert_zero_egress()
    raw_session.console.assert_no_errors()


def test_T2_F14_02_checkout_requires_checked_terms_before_submit(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    ui = raw_session.ui
    base = raw_session.base_url.rstrip("/")

    raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    raw_session.net.assert_clean_load()
    raw_session.net.start_interactive_phase()

    ui.fill_checkout_buyer(
        name="Ольга Смирнова",
        email="olga.terms@example.com",
        accept_terms=False,
    )
    ui.submit_checkout_order()
    assert not page.locator("[data-testid='checkout-order-panel'], #checkout-order-panel").is_visible()

    ui.fill_checkout_buyer(accept_terms=True)
    ui.submit_checkout_order()
    assert ui.get_checkout_order_panel().is_visible()
    assert ui.get_checkout_order_id().startswith("PV-ORD-")
    raw_session.net.assert_zero_egress(["olga.terms@example.com"])
    raw_session.console.assert_no_errors()


def test_T2_F14_03_checkout_rejects_malformed_tampered_and_expired_pv1_tokens(
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

    valid = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-T2-TOK", label="Граница")
    prefix, payload_b64, sig_b64 = valid.split(".")
    pad = "=" * ((4 - len(payload_b64) % 4) % 4)
    payload_obj = json.loads(base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii")).decode("utf-8"))
    payload_obj["tier"] = "owner"
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload_obj, separators=(",", ":")).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    flipped_sig_char = "A" if sig_b64[0] != "A" else "B"
    tampered_sig = f"{prefix}.{payload_b64}.{flipped_sig_char}{sig_b64[1:]}"
    expired_token = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="PV-E2E-T2-EXP",
        label="Просрочен",
        exp="2020-01-01T00:00:00.000Z",
    )

    bad_vectors = (
        "",
        "   \n\t  ",
        f"PV2.{payload_b64}.{sig_b64}",
        "PV1.onlytwo",
        "PV1.not!b64!.sig!",
        f"{prefix}.{tampered_payload_b64}.{sig_b64}",
        tampered_sig,
        expired_token,
    )

    for vec in bad_vectors:
        ui.verify_checkout_token_only(vec)
        assert page.locator("[data-testid='checkout-token-diagnostics'], #checkout-token-diagnostics").is_visible()
        assert not page.locator("[data-testid='checkout-pro-unlocked'], #checkout-pro-unlocked").is_visible()
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

        ui.activate_checkout_token(vec)
        assert page.locator("[data-testid='checkout-token-diagnostics'], #checkout-token-diagnostics").is_visible()
        assert not page.locator("[data-testid='checkout-pro-unlocked'], #checkout-pro-unlocked").is_visible()
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    pro_raw_session.net.assert_zero_egress([valid, expired_token])
    pro_raw_session.console.assert_no_errors()


def test_T2_F14_04_checkout_rejects_invalid_and_empty_pvkey_file_uploads(
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

    valid = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-T2-FILE", label="Файл")
    prefix, payload_b64, sig_b64 = valid.split(".")
    flipped = "A" if sig_b64[0] != "A" else "B"
    tampered = f"{prefix}.{payload_b64}.{flipped}{sig_b64[1:]}"

    empty_pvkey = pro_raw_session.io.uploads / "empty.pvkey"
    empty_pvkey.write_text("", encoding="utf-8")

    no_tok_pvkey = pro_raw_session.io.uploads / "no_token.pvkey"
    no_tok_pvkey.write_text("# comment only\nhello world\n", encoding="utf-8")

    tampered_pvkey = pro_raw_session.io.uploads / "tampered.pvkey"
    tampered_pvkey.write_text(f"# Tampered\n{tampered}\n", encoding="utf-8")

    corrupt_pvkey = pro_raw_session.io.uploads / "corrupt.pvkey"
    corrupt_pvkey.write_bytes(b"\x00\xff\xfe\x89PNG\r\n\x1a\n")

    for bad_file in (empty_pvkey, no_tok_pvkey, tampered_pvkey, corrupt_pvkey):
        ui.upload_checkout_pvkey(bad_file)
        assert page.locator("[data-testid='checkout-token-diagnostics'], #checkout-token-diagnostics").is_visible()
        assert not page.locator("[data-testid='checkout-pro-unlocked'], #checkout-pro-unlocked").is_visible()
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    pro_raw_session.net.assert_zero_egress([valid, tampered])
    pro_raw_session.console.assert_no_errors()


def test_T2_F14_05_checkout_zero_raw_card_pan_cvv_fields_and_strict_csp(
    raw_session: E2ESession,
) -> None:
    page = raw_session.page
    base = raw_session.base_url.rstrip("/")

    for route in ("/pro/", "/en/pro/"):
        raw_session.net.phase = "load"
        page.goto(f"{base}{route}", wait_until="networkidle")
        raw_session.net.assert_clean_load()
        raw_session.net.start_interactive_phase()

        raw_card_fields = page.evaluate(
            """() => {
                const bad = [];
                const forbiddenAc = new Set(['cc-number', 'cc-csc', 'cc-exp', 'cc-exp-month', 'cc-exp-year']);
                const forbiddenRe = /\\b(pan|card[-_ ]?number|cvv|cvc|csc|expiry)\\b/i;
                for (const el of document.querySelectorAll('input, textarea, select')) {
                    const ac = (el.getAttribute('autocomplete') || '').toLowerCase().trim();
                    if (forbiddenAc.has(ac)) bad.push(`autocomplete:${ac}`);
                    const meta = [el.id, el.name, el.getAttribute('data-testid'), el.getAttribute('placeholder')].join(' ');
                    if (forbiddenRe.test(meta)) bad.push(`attr:${meta}`);
                }
                return bad;
            }"""
        )
        assert raw_card_fields == []

        inline_violations = page.evaluate(
            """() => {
                const bad = [];
                const checkRoot = (root, label) => {
                    for (const el of root.querySelectorAll('*')) {
                        if (el.tagName === 'SCRIPT' && (!el.hasAttribute('src') || (el.textContent || '').trim())) {
                            bad.push(`${label}:SCRIPT`);
                        }
                        if (el.tagName === 'STYLE') bad.push(`${label}:STYLE`);
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
        assert inline_violations == []

    raw_session.console.assert_no_errors()


def test_T2_F14_06_checkout_xss_inputs_and_fragment_escaped_inert(
    pro_raw_session: E2ESession,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/#code=<img src=x onerror=window.__xssFrag=1>", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    page.wait_for_timeout(150)

    assert page.evaluate("() => window.__xssFrag === undefined") is True
    assert page.locator("img[src='x']").count() == 0

    ui.fill_checkout_buyer(
        name="<img src=x onerror=window.__xssName=1>",
        email="xss.safe@example.com",
        company="<script>window.__xssComp=1</script>",
        accept_terms=True,
    )
    ui.submit_checkout_order()
    assert ui.get_checkout_order_panel().is_visible()

    ui.verify_checkout_token_only("<svg onload=window.__xssTok=1>")
    assert page.evaluate(
        "() => window.__xssName === undefined && window.__xssComp === undefined && window.__xssTok === undefined"
    ) is True
    assert page.locator("img[src='x'], svg[onload]").count() == 0
    pro_raw_session.net.assert_zero_egress(["xss.safe@example.com"])
    pro_raw_session.console.assert_no_errors()


def test_T2_F14_07_checkout_mobile_390x844_zero_overflow_and_44px_tap_targets(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    def _assert_44px(loc_str: str) -> None:
        loc = page.locator(loc_str)
        for idx in range(loc.count()):
            el = loc.nth(idx)
            if el.is_visible():
                box = el.bounding_box()
                assert box is not None and box["height"] >= 43.5, f"{loc_str}[{idx}] height={box}"

    for route in ("/pro/", "/en/pro/"):
        pro_raw_session.net.phase = "load"
        page.goto(f"{base}{route}", wait_until="networkidle")
        pro_raw_session.net.assert_clean_load()
        pro_raw_session.net.start_interactive_phase()

        verify_responsive_layout(page, 390, 844)
        ui.fill_checkout_buyer(
            name="Mobile Buyer",
            email="mobile.buyer@example.com",
            accept_terms=True,
        )
        ui.submit_checkout_order()
        assert ui.get_checkout_order_panel().is_visible()
        verify_responsive_layout(page, 390, 844)

        token = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-E2E-MOB-CHK", label="Мобильный")
        ui.activate_checkout_token(token)
        assert ui.get_checkout_unlocked_panel().is_visible()
        verify_responsive_layout(page, 390, 844)

        _assert_44px("[data-plan], [data-payment]")
        _assert_44px(
            "#checkout-submit-btn, #checkout-copy-receipt-btn, #checkout-download-receipt-btn, "
            "#checkout-activate-btn, #checkout-verify-only-btn, #checkout-download-pvkey-btn"
        )

    pro_raw_session.console.assert_no_errors()


def test_T2_F14_08_checkout_dark_light_theme_and_csp_blocks_egress(
    pro_raw_session: E2ESession,
) -> None:
    page = pro_raw_session.page
    base = pro_raw_session.base_url.rstrip("/")

    for route in ("/pro/", "/en/pro/"):
        pro_raw_session.net.phase = "load"
        page.goto(f"{base}{route}", wait_until="networkidle")
        pro_raw_session.net.assert_clean_load()
        pro_raw_session.net.start_interactive_phase()

        theme_btn = page.locator("[data-testid='theme-toggle-btn'], #theme-toggle-btn").first
        theme_btn.click()
        assert page.evaluate("() => document.documentElement.dataset.theme") == "dark"
        assert page.evaluate("() => localStorage.getItem('promptveil_theme_v1')") == "dark"
        verify_responsive_layout(page, 1440, 900)

        theme_btn.click()
        assert page.evaluate("() => document.documentElement.dataset.theme") == "light"
        assert page.evaluate("() => localStorage.getItem('promptveil_theme_v1')") == "light"

    with pro_raw_session.console.allow_expected_csp_errors():
        blocked = page.evaluate(
            """async () => {
                const cspEvents = [];
                const onViolation = (e) => {
                    cspEvents.push({
                        effectiveDirective: e.effectiveDirective || '',
                        violatedDirective: e.violatedDirective || '',
                    });
                };
                document.addEventListener('securitypolicyviolation', onViolation);
                try {
                    const s = document.createElement('script');
                    s.textContent = 'window.__cspCheckoutProbe = 1;';
                    document.head.appendChild(s);
                    s.remove();

                    let fetchBlocked = false;
                    try {
                        await fetch('https://example.com/csp-probe');
                    } catch {
                        fetchBlocked = true;
                    }
                    await new Promise((resolve) => setTimeout(resolve, 150));
                    return {
                        inlineProbeUndefined: window.__cspCheckoutProbe === undefined,
                        fetchBlocked,
                        cspEvents,
                    };
                } finally {
                    document.removeEventListener('securitypolicyviolation', onViolation);
                }
            }"""
        )
    assert blocked["inlineProbeUndefined"] is True
    assert blocked["fetchBlocked"] is True
    directives = [
        (ev.get("effectiveDirective") or ev.get("violatedDirective") or "").lower()
        for ev in blocked["cspEvents"]
    ]
    assert any(d.startswith("script-src") for d in directives)
    assert any(d.startswith("connect-src") for d in directives)
    pro_raw_session.console.assert_no_errors()
