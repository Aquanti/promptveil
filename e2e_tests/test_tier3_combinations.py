"""Tier 3: Cross-Feature Pairwise & Multi-Feature Combinations (14 Tests: T3-01..T3-14)."""

from __future__ import annotations

import base64
import io
import json
import re
import urllib.request
import zipfile

import pytest
from playwright.sync_api import BrowserContext

from conftest import E2ESession, EphemeralProKeys
from doc_fixtures import (
    make_scanned_image_pdf,
    make_synthetic_docx,
    make_synthetic_pdf,
    make_synthetic_xlsx,
)
from locators import PromptVeilUI
from monitors import (
    ConsoleErrorMonitor,
    verify_allowed_local_storage_keys,
    verify_russian_purity,
)


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


def test_T3_10_persistent_launchers_step1_step2_gemini_and_clipboard_flush(
    e2e_session: E2ESession,
) -> None:
    page = e2e_session.page
    ui = e2e_session.ui

    ui.set_auto_sanitize(False)
    ui.get_prompt_input().fill("Draft for gemini.t3@example.com")

    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        assert ui.read_clipboard_text() == "Draft for [EMAIL_1]"
        assert "gemini.t3@example.com" not in (ui.read_clipboard_text() or "")
        assert re.search(r"скопирован|copied", ui.get_status_banner_text(), re.I)
    finally:
        page.context.unroute("https://gemini.google.com/**")

    ui.switch_mode("rehydrate")
    assert page.locator("[data-testid='panel-rehydrate']").is_visible()
    assert ui.get_ai_launchers_bar().is_visible()
    assert ui.is_ai_launchers_ready() is True
    assert ui.get_ai_launcher("gemini").is_visible()

    page.evaluate("async () => navigator.clipboard.writeText('SENTINEL')")
    page.context.route("https://claude.ai/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("claude")
        pop_info.value.close()
        assert ui.read_clipboard_text() == "Draft for [EMAIL_1]"
    finally:
        page.context.unroute("https://claude.ai/**")

    ui.switch_mode("sanitize")
    ui.click_clear_input()
    ui.switch_mode("rehydrate")
    assert ui.is_ai_launchers_ready() is False

    e2e_session.net.assert_zero_egress(["gemini.t3@example.com"])
    e2e_session.console.assert_no_errors()


def test_T3_11_pro_license_unlock_tamper_purejs_fallback_and_proof_zero_keys(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    assert ui.get_pro_badge_text() == "Free"
    valid_pro = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T3-PRO", label="T3 Pro")
    prefix, payload_b64, sig_b64 = valid_pro.split(".")
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    payload_obj = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    payload_obj["tier"] = "owner"
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload_obj, separators=(",", ":")).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    tampered_token = f"{prefix}.{tampered_payload_b64}.{sig_b64}"

    ui.open_pro_license_modal("header")
    ui.activate_pro_key(tampered_token)
    assert page.locator("#pro-license-alert, [data-testid='pro-license-alert']").is_visible()
    assert ui.get_pro_badge_text() == "Free"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    ui.activate_pro_key(valid_pro)
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.close_active_modal()

    pro_e2e_session.net.assert_zero_egress(["PV-T3-PRO"])
    pro_e2e_session.net.phase = "load"
    page.reload(wait_until="networkidle")
    pro_e2e_session.net.assert_clean_load()
    pro_e2e_session.net.start_interactive_phase()
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.open_pro_license_modal("header")
    assert "PV-T3-PRO" in ui.get_pro_status_card_text()

    owner_tok = ephemeral_pro_keys.issue_token(tier="owner", key_id="PV-T3-OWN", label="T3 Owner")
    ui.activate_pro_key(owner_tok)
    assert ui.get_pro_badge_text() == "Owner Pro"
    assert "PV-T3-OWN" in ui.get_pro_status_card_text()

    # Force pure-JS Ed25519 fallback by rejecting WebCrypto verify
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
    ui.remove_pro_key()
    assert ui.get_pro_badge_text() == "Free"
    ui.activate_pro_key(valid_pro)
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.close_active_modal()

    ui.sanitize_text("Secret pro.proof@example.com")
    proof = ui.open_privacy_proof_modal("header")
    ui.run_privacy_proof_check()
    proof_txt = proof.inner_text()
    assert "неизвестные ключи: 0" in proof_txt
    assert "0 байт" in proof_txt
    assert "0 запросов" in proof_txt
    assert "нарушений CSP в документе приложения: 0" in proof_txt
    ui.close_active_modal()
    verify_allowed_local_storage_keys(page)

    ui.open_pro_license_modal("header")
    ui.remove_pro_key()
    ui.close_active_modal()
    assert ui.get_pro_badge_text() == "Free"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    pro_e2e_session.net.assert_zero_egress(["pro.proof@example.com", "PV-T3-PRO", "PV-T3-OWN"])
    pro_e2e_session.console.assert_no_errors()


def test_T3_12_free_vs_pro_document_gate_batch_office_pdf_scanned_and_rehydrate(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    contract_docx = make_synthetic_docx(
        pro_e2e_session.io.uploads / "contract.docx",
        paragraphs=["Lead counsel doc.lead@example.com"],
        table_rows=[["Tax ID", "7707083893"]],
        header_text="Internal Contract",
    )
    ledger_xlsx = make_synthetic_xlsx(
        pro_e2e_session.io.uploads / "ledger.xlsx",
        shared_strings=["Payee Email", "IBAN"],
        rows=[["Payee Email", "IBAN"], ["xlsx.pay@example.org", "DE89370400440532013000"]],
    )
    memo_pdf = make_synthetic_pdf(
        pro_e2e_session.io.uploads / "memo.pdf",
        text_lines=["Exec contact pdf.exec@example.com", "Card 4276 3800 1234 5678"],
        compressed=True,
        use_tounicode=True,
    )
    scan_pdf = make_scanned_image_pdf(pro_e2e_session.io.uploads / "scan.pdf")

    ui.upload_files([contract_docx])
    assert ui.get_file_pro_upgrade_banner().is_visible()
    assert ui.get_batch_queue_items() == []

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T3-DOC"))
    ui.close_active_modal()

    ui.upload_files([contract_docx, ledger_xlsx, memo_pdf])
    items = ui.get_batch_queue_items()
    assert len(items) == 3

    panel_txt = ui.get_batch_queue_panel().inner_text()
    sanitized_out = ui.get_sanitize_output_text()
    raw_secrets = [
        "doc.lead@example.com",
        "7707083893",
        "xlsx.pay@example.org",
        "DE89370400440532013000",
        "pdf.exec@example.com",
        "4276 3800 1234 5678",
    ]
    for raw in raw_secrets:
        assert raw not in panel_txt
        assert raw not in sanitized_out

    verify_russian_purity(page)

    dl_txt = ui.download_batch_txt(pro_e2e_session.io.downloads)
    txt_body = dl_txt.read_text(encoding="utf-8")
    for fname in ("=== contract.docx ===", "=== ledger.xlsx ===", "=== memo.pdf ==="):
        assert fname in txt_body
    assert "[EMAIL_1]" in txt_body
    for raw in raw_secrets:
        assert raw not in txt_body

    dl_zip = ui.download_batch_zip(pro_e2e_session.io.downloads)
    with zipfile.ZipFile(dl_zip, "r") as zf:
        assert zf.testzip() is None
        sanitized_members = [n for n in zf.namelist() if n.endswith(".sanitized.txt")]
        assert len(sanitized_members) >= 3
        archive_text = "\n".join(zf.read(n).decode("utf-8", errors="replace") for n in sanitized_members)
        for raw in raw_secrets:
            assert raw not in archive_text

    ui.click_batch_rehydrate()
    restored = ui.get_rehydrate_output_text()
    for raw in raw_secrets:
        assert raw in restored
    assert ui.get_unresolved_tokens() == []

    ui.switch_mode("sanitize")
    ui.clear_batch_queue()
    assert ui.get_batch_queue_items() == []

    ui.upload_files([scan_pdf])
    banner_el = page.locator("[data-testid='input-error-banner'], #input-error-banner").first
    scan_notice = banner_el.inner_text().strip() if banner_el.count() > 0 and banner_el.is_visible() else ""
    if not scan_notice:
        scan_notice = ui.get_batch_queue_panel().inner_text()
    assert re.search(r"скан|OCR|текстового слоя|scanned|text layer", scan_notice, re.I)

    pro_e2e_session.net.assert_zero_egress(raw_secrets)
    pro_e2e_session.console.assert_no_errors()


def test_T3_13_multi_project_profiles_pro_packs_templates_and_proof_isolation(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    free_opts = ui.get_rulebook_profile_options()
    assert any("Основной" in o for o in free_opts)
    before_free_rules = ui.get_rulebook_badge_count()
    drawer = ui.open_rulebook_drawer()
    for pack_key in ("corporate_ma", "devsecops", "banking_fintech", "crossborder_nda"):
        pack_btn = drawer.locator(f"[data-testid='word-pack-{pack_key}'], [data-pack='{pack_key}']").first
        if pack_btn.is_visible() and not pack_btn.is_disabled():
            pack_btn.click()
            page.wait_for_timeout(80)
    assert ui.get_rulebook_badge_count() == before_free_rules
    ui.close_open_drawer()

    tpl_bar_free = page.locator("[data-testid='prompt-templates-bar'], #prompt-templates-bar")
    if tpl_bar_free.count() > 0 and tpl_bar_free.first.is_visible():
        before_val = ui.get_prompt_input().input_value()
        first_tpl = tpl_bar_free.first.locator(".prompt-template-btn, button").first
        if first_tpl.is_visible() and not first_tpl.is_disabled():
            first_tpl.click()
            page.wait_for_timeout(80)
            assert ui.get_prompt_input().input_value() == before_val

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T3-PROF"))
    ui.close_active_modal()

    ui.create_rulebook_profile("Клиент А")
    ui.add_custom_rule("SigmaProjectA")
    ui.create_rulebook_profile("NDA Альфа")
    drawer = ui.open_rulebook_drawer()
    ui.apply_industry_word_pack("corporate_ma")
    first_ma_term = (
        drawer.locator(
            "[data-testid='rules-list'] .rule-term-text, "
            "[data-testid='rules-list'] [data-term], "
            "[data-testid='rules-list'] .rule-term"
        )
        .first.inner_text()
        .strip()
    )
    assert first_ma_term
    ui.close_open_drawer()

    masked_nda = ui.sanitize_text(f"Check {first_ma_term} and SigmaProjectA")
    assert first_ma_term not in masked_nda
    assert "SigmaProjectA" in masked_nda

    ui.select_rulebook_profile("Клиент А")
    ui.close_open_drawer()
    masked_a = ui.sanitize_text(f"Check {first_ma_term} and SigmaProjectA")
    assert "SigmaProjectA" not in masked_a
    assert first_ma_term in masked_a

    ui.rename_rulebook_profile("Клиент А-2")
    assert any("Клиент А-2" in o for o in ui.get_rulebook_profile_options())
    exported = ui.export_rules_json(pro_e2e_session.io.downloads)
    ui.delete_rulebook_profile()
    assert not any("Клиент А-2" in o for o in ui.get_rulebook_profile_options())

    ui.create_rulebook_profile("Клиент Б")
    ui.import_rules_json(exported)
    assert "SigmaProjectA" in ui.get_rulebook_text()
    ui.close_open_drawer()

    tpl_bar = ui.get_prompt_templates_bar()
    first_btn = tpl_bar.locator(".prompt-template-btn, button").first
    tid = (
        first_btn.get_attribute("data-template-id")
        or first_btn.get_attribute("data-template")
        or first_btn.inner_text().strip()
    )
    ui.click_prompt_template(tid)
    raw_tpl = ui.get_prompt_input().input_value()
    assert len(raw_tpl.strip()) > 10
    assert ui.get_sanitize_output_text().strip()
    stored_profiles = page.evaluate("() => localStorage.getItem('promptveil_profiles_v1') || ''")
    assert raw_tpl[:24] not in stored_profiles

    proof = ui.open_privacy_proof_modal("header")
    ui.run_privacy_proof_check()
    proof_txt = proof.inner_text()
    assert "неизвестные ключи: 0" in proof_txt
    assert "0 байт" in proof_txt
    ui.close_active_modal()
    verify_allowed_local_storage_keys(page)

    pro_e2e_session.net.assert_zero_egress(["SigmaProjectA", first_ma_term])
    pro_e2e_session.console.assert_no_errors()


def test_T3_14_pro_downloads_modal_extension_zip_headers_and_sw_offline(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
    browser_context: BrowserContext,
    base_url: str,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    # Part A: /downloads/promptveil-pro-extension.zip headers, PKZIP, MV3 manifest & Pro loaded offline .docx
    zip_url = f"{base_url.rstrip('/')}/downloads/promptveil-pro-extension.zip"
    with urllib.request.urlopen(zip_url, timeout=5.0) as resp:
        assert int(resp.status) == 200
        headers = {k.lower(): v for k, v in resp.headers.items()}
        payload = resp.read()
    assert "application/zip" in headers.get("content-type", "").lower()
    assert headers.get("x-content-type-options", "").lower() == "nosniff"
    assert headers.get("cross-origin-resource-policy", "").lower() == "same-origin"

    with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
        assert zf.testzip() is None
        names = set(zf.namelist())
        assert "manifest.json" in names
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest.get("manifest_version") == 3

        action = manifest.get("action") or {}
        default_popup = action.get("default_popup")
        assert isinstance(default_popup, str) and default_popup
        assert default_popup.lstrip("./") in names
        assert {"dist/popup.bundle.js", "popup.css"}.issubset(names)

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
        assert len(cs_js) >= 1
        for asset_path in cs_js + cs_css:
            assert asset_path.lstrip("./") in names

        all_hosts = " ".join(
            list(manifest.get("host_permissions", []))
            + [m for cs in content_scripts for m in cs.get("matches", [])]
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
        for member in zf.namelist():
            if member.endswith((".js", ".json", ".html", ".css", ".txt")):
                content = zf.read(member).decode("utf-8", errors="replace")
                for marker in ("BEGIN PRIVATE KEY", "PV-CLIENT-"):
                    assert marker not in content
                assert re.search(r"PV1\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}", content) is None

    dl_trigger = page.locator("[data-testid='open-pro-downloads-btn'], #open-pro-downloads-btn")
    if dl_trigger.count() > 0 and dl_trigger.first.is_visible() and dl_trigger.first.is_enabled():
        dl_trigger.first.click()
        page.wait_for_timeout(120)
        assert not page.locator("[data-testid='modal-pro-downloads'], #modal-pro-downloads").is_visible()
        ui.close_active_modal()

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T3-DL"))
    ui.close_active_modal()

    dl_modal = ui.open_pro_downloads_modal()
    dl_text = dl_modal.inner_text()
    assert "Chrome" in dl_text and "Edge" in dl_text
    assert re.search(r"Яндекс|Yandex", dl_text, re.I)
    ui.close_active_modal()

    ext_zip = ui.download_extension_zip(pro_e2e_session.io.downloads)
    with zipfile.ZipFile(ext_zip, "r") as zf:
        assert zf.testzip() is None
        assert "manifest.json" in zf.namelist()

    offline_docx = make_synthetic_docx(
        pro_e2e_session.io.uploads / "offline_pro.docx",
        paragraphs=["Offline secret off.pro@example.com"],
    )
    try:
        page.context.set_offline(True)
        ui.upload_files([offline_docx])
        assert len(ui.get_batch_queue_items()) == 1
        assert "off.pro@example.com" not in ui.get_batch_queue_panel().inner_text()
        ui.click_batch_rehydrate()
        assert "off.pro@example.com" in ui.get_rehydrate_output_text()
    finally:
        page.context.set_offline(False)

    pro_e2e_session.net.assert_zero_egress(["off.pro@example.com"])
    pro_e2e_session.console.assert_no_errors()

    # Part B: SW-enabled BrowserContext verifies SW precache of extension .zip & offline reload
    sw_page = browser_context.new_page()
    sw_console = ConsoleErrorMonitor(page=sw_page)
    sw_console.attach()
    try:
        sw_page.goto(f"{base_url.rstrip('/')}/", wait_until="networkidle")
        sw_ready = sw_page.evaluate(
            """async () => {
                if (!('serviceWorker' in navigator)) return false;
                const reg = await navigator.serviceWorker.ready;
                return Boolean(reg && reg.active);
            }"""
        )
        assert sw_ready is True
        sw_page.reload(wait_until="networkidle")

        # Warm on-demand SWR cache for optional assets while online, then test offline access.
        warmed_zip_status = sw_page.evaluate(
            "async () => (await fetch('/downloads/promptveil-pro-extension.zip')).status"
        )
        assert warmed_zip_status == 200

        try:
            browser_context.set_offline(True)
            sw_page.reload(wait_until="domcontentloaded")
            sw_page.locator("[data-testid='raw-prompt-input']").wait_for(state="visible", timeout=5000)

            cached_zip = sw_page.evaluate(
                """async () => {
                    const res = await fetch('/downloads/promptveil-pro-extension.zip');
                    const buf = await res.arrayBuffer();
                    const bytes = new Uint8Array(buf);
                    return {
                        status: res.status,
                        len: bytes.length,
                        magic: bytes.length >= 2 ? String.fromCharCode(bytes[0], bytes[1]) : '',
                    };
                }"""
            )
            assert cached_zip["status"] == 200
            assert cached_zip["len"] > 100
            assert cached_zip["magic"] == "PK"

            sw_ui = PromptVeilUI(sw_page)
            masked_sw = sw_ui.sanitize_text("SW offline sw.user@example.ru")
            assert "[EMAIL_1]" in masked_sw
            assert "sw.user@example.ru" in sw_ui.rehydrate_text(masked_sw)
        finally:
            browser_context.set_offline(False)

        sw_console.assert_no_errors()
    finally:
        sw_console.detach()
        sw_page.close()
