"""Tier 1: Isolated Happy-Path E2E Feature Coverage (51 Tests: T1-F1-01..T1-F8-06)."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from conftest import E2ESession
from monitors import verify_csp_and_security_headers, verify_health_endpoint


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
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || ''")
    assert re.search(r"[0-9a-f]{64}", stored, re.I) is not None


def test_T1_F7_02_zero_raw_pii_in_audit_store(e2e_session: E2ESession) -> None:
    secrets = ["alice.secret@example.com", "123-45-6789", "AKIAIOSFODNN7EXAMPLE"]
    e2e_session.ui.sanitize_text("PII " + " ".join(secrets))
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || ''")
    drawer_text = e2e_session.ui.get_audit_drawer_text()
    for s in secrets:
        assert s not in stored
        assert s not in drawer_text


def test_T1_F7_03_audit_persistence_across_reload(e2e_session: E2ESession) -> None:
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
    stored = e2e_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1') || '[]'")
    assert json.loads(stored) == []


# ---------------------------------------------------------------------------
# F8: FastAPI Host, CSP, /health, Security & UI States (6 Tests)
# ---------------------------------------------------------------------------


def test_T1_F8_01_health_endpoint_contract(raw_session: E2ESession) -> None:
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
