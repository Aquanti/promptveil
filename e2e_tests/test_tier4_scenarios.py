"""Tier 4: Real-World Application Scenarios (11 Tests: T4-01..T4-11)."""

from __future__ import annotations

import io
import json
import re
import urllib.request
import zipfile
from typing import Any

import pytest

from conftest import E2ESession, EphemeralProKeys
from doc_fixtures import make_synthetic_docx, make_synthetic_pdf, make_synthetic_xlsx
from monitors import (
    verify_allowed_local_storage_keys,
    verify_responsive_layout,
    verify_russian_purity,
)


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


def test_T4_07_corporate_ma_legal_batch_office_pdf_workflow(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    theme_btn = page.locator("[data-testid='theme-toggle-btn']")
    theme_btn.click()
    assert page.evaluate("() => document.documentElement.dataset.theme") == "dark"

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T4-MA", label="M&A Legal"))
    ui.close_active_modal()

    ui.create_rulebook_profile("Сделка M&A Восток")
    drawer = ui.open_rulebook_drawer()
    ui.apply_industry_word_pack("corporate_ma")
    ui.apply_industry_word_pack("crossborder_nda")
    ma_term = (
        drawer.locator(
            "[data-testid='rules-list'] .rule-term-text, "
            "[data-testid='rules-list'] [data-term], "
            "[data-testid='rules-list'] .rule-term"
        )
        .first.inner_text()
        .strip()
    )
    assert ma_term
    ui.close_open_drawer()

    tpl_bar = ui.get_prompt_templates_bar()
    first_btn = tpl_bar.locator(".prompt-template-btn, button").first
    tid = (
        first_btn.get_attribute("data-template-id")
        or first_btn.get_attribute("data-template")
        or first_btn.inner_text().strip()
    )
    ui.click_prompt_template(tid)
    assert ui.get_sanitize_output_text().strip()

    nda_docx = make_synthetic_docx(
        pro_e2e_session.io.uploads / "nda_draft.docx",
        paragraphs=[f"Signed by Алексей Смирнов regarding {ma_term} and legal.ma@acme.test."],
        table_rows=[["INN", "7707083893"], ["OGRN", "1027700132195"]],
        header_text="M&A Confidentiality Draft",
    )
    cap_xlsx = make_synthetic_xlsx(
        pro_e2e_session.io.uploads / "cap_table.xlsx",
        shared_strings=["IBAN", "Card", "Phone"],
        rows=[
            ["IBAN", "Card", "Phone"],
            ["DE89370400440532013000", "4111 1111 1111 1111", "+7 (916) 555-01-23"],
        ],
    )
    term_pdf = make_synthetic_pdf(
        pro_e2e_session.io.uploads / "term_sheet.pdf",
        text_lines=["Deal contact deals@target.example", "Taxpayer SSN 123-45-6789"],
        compressed=True,
        use_tounicode=True,
    )

    ui.upload_files([nda_docx, cap_xlsx, term_pdf])
    items = ui.get_batch_queue_items()
    assert len(items) == 3

    raw_secrets = [
        "7707083893",
        "1027700132195",
        "Алексей Смирнов",
        ma_term,
        "legal.ma@acme.test",
        "DE89370400440532013000",
        "4111 1111 1111 1111",
        "+7 (916) 555-01-23",
        "deals@target.example",
        "123-45-6789",
    ]
    panel_txt = ui.get_batch_queue_panel().inner_text()
    sanitized_out = ui.get_sanitize_output_text()
    for secret in raw_secrets:
        assert secret not in panel_txt
        assert secret not in sanitized_out

    zip_path = ui.download_batch_zip(pro_e2e_session.io.downloads)
    with zipfile.ZipFile(zip_path, "r") as zf:
        assert zf.testzip() is None
        sanitized_entries = [n for n in zf.namelist() if n.endswith(".sanitized.txt")]
        assert len(sanitized_entries) >= 3
        archive_body = "\n".join(zf.read(n).decode("utf-8", errors="replace") for n in sanitized_entries)
        for secret in raw_secrets:
            assert secret not in archive_body

    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        clip = ui.read_clipboard_text() or ""
        assert len(clip.strip()) > 0
        for secret in raw_secrets:
            assert secret not in clip
    finally:
        page.context.unroute("https://gemini.google.com/**")

    ui.click_batch_rehydrate()
    restored = ui.get_rehydrate_output_text()
    for secret in raw_secrets:
        assert secret in restored
    assert ui.get_unresolved_tokens() == []

    proof = ui.open_privacy_proof_modal("header")
    ui.run_privacy_proof_check()
    proof_txt = proof.inner_text()
    assert "неизвестные ключи: 0" in proof_txt
    assert "0 байт" in proof_txt
    assert "0 запросов" in proof_txt
    verify_allowed_local_storage_keys(page)

    ui.click_reset_session_to_zero("modal")
    assert ui.get_batch_queue_items() == []
    assert ui.get_vault_rows() == []

    pro_e2e_session.net.assert_zero_egress(raw_secrets)
    pro_e2e_session.console.assert_no_errors()


def test_T4_08_devsecops_multi_profile_step2_launcher_and_en_ru_switch(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui

    page.goto(f"{pro_raw_session.base_url}/en/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="owner", key_id="PV-T4-OWN", label="SecOps Lead"))
    assert ui.get_pro_badge_text() == "Owner Pro"
    ui.close_active_modal()

    ui.create_rulebook_profile("Prod Incident K8s")
    drawer = ui.open_rulebook_drawer()
    ui.apply_industry_word_pack("devsecops")
    devops_term = (
        drawer.locator(
            "[data-testid='rules-list'] .rule-term-text, "
            "[data-testid='rules-list'] [data-term], "
            "[data-testid='rules-list'] .rule-term"
        )
        .first.inner_text()
        .strip()
    )
    assert devops_term
    ui.close_open_drawer()

    # strict mode automatically enables and disables #detect-uuid-toggle (do not call set_detect_uuid after strict)
    ui.set_sensitivity_mode("strict")
    assert page.locator("[data-testid='detect-uuid-toggle']").is_checked() is True

    inc_env = pro_raw_session.io.uploads / "incident.env"
    inc_env.write_text(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=Sup3rSynthPass!99\n",
        encoding="utf-8",
    )
    kube_log = pro_raw_session.io.uploads / "kube.log"
    kube_log.write_text(
        f"Pod IP 203.0.113.77 trace 550e8400-e29b-41d4-a716-446655440000 term {devops_term}\n",
        encoding="utf-8",
    )
    runbook_pdf = make_synthetic_pdf(
        pro_raw_session.io.uploads / "runbook.pdf",
        text_lines=[
            "Pager oncall@k8s-synth.example",
            "Fallback sk-proj-TestSynthKey000111222333444",
        ],
        compressed=True,
        use_tounicode=True,
    )

    ui.upload_files([inc_env, kube_log, runbook_pdf])
    assert len(ui.get_batch_queue_items()) == 3

    raw_secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "Sup3rSynthPass!99",
        "203.0.113.77",
        "550e8400-e29b-41d4-a716-446655440000",
        devops_term,
        "oncall@k8s-synth.example",
        "sk-proj-TestSynthKey000111222333444",
    ]
    sanitized_combined = ui.get_sanitize_output_text()
    for secret in raw_secrets:
        assert secret not in sanitized_combined

    page.context.route("https://chat.deepseek.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("deepseek")
        pop_info.value.close()
        step1_clip = ui.read_clipboard_text() or ""
        assert step1_clip.strip()
        for secret in raw_secrets:
            assert secret not in step1_clip
    finally:
        page.context.unroute("https://chat.deepseek.com/**")

    ui.switch_mode("rehydrate")
    assert ui.is_ai_launchers_ready() is True
    page.evaluate("async () => navigator.clipboard.writeText('SENTINEL')")
    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        step2_clip = ui.read_clipboard_text() or ""
        assert step2_clip.strip() and step2_clip != "SENTINEL"
        for secret in raw_secrets:
            assert secret not in step2_clip
    finally:
        page.context.unroute("https://gemini.google.com/**")

    restored = ui.rehydrate_text(step2_clip)
    for secret in raw_secrets:
        assert secret in restored

    pro_raw_session.net.assert_zero_egress(raw_secrets)
    pro_raw_session.net.phase = "load"
    ui.switch_language("ru")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    verify_russian_purity(page)

    pro_raw_session.net.assert_zero_egress(raw_secrets)
    pro_raw_session.console.assert_no_errors()


def test_T4_09_mobile_390x844_pro_workflow_and_key_deactivation_downgrade(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    verify_responsive_layout(page, 390, 844)
    top_rail_h = page.locator("header.top-rail").evaluate("el => el.getBoundingClientRect().height")
    assert top_rail_h <= 64.5
    badge = page.locator("[data-testid='open-pro-license-btn'], #open-pro-license-btn").first
    if badge.is_visible():
        badge_box = badge.bounding_box()
        assert badge_box is not None and badge_box["width"] >= 43.5 and badge_box["height"] >= 43.5

    ui.open_pro_license_modal("header")
    verify_responsive_layout(page, 390, 844)
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T4-MOB", label="Mobile Pro"))
    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.close_active_modal()

    ui.create_rulebook_profile("Mobile Pro")
    drawer = ui.open_rulebook_drawer()
    ui.apply_industry_word_pack("banking_fintech")
    dbox = drawer.bounding_box()
    assert dbox is not None and dbox["x"] >= -0.5 and (dbox["x"] + dbox["width"]) <= 390.5
    verify_responsive_layout(page, 390, 844)
    ui.close_open_drawer()

    mob_docx = make_synthetic_docx(
        pro_e2e_session.io.uploads / "mob_doc.docx",
        paragraphs=["Mobile contact mob.a@example.com"],
    )
    mob_xlsx = make_synthetic_xlsx(
        pro_e2e_session.io.uploads / "mob_sheet.xlsx",
        shared_strings=["Mail"],
        rows=[["Mail"], ["mob.b@example.org"]],
    )
    ui.upload_files([mob_docx, mob_xlsx])
    batch_panel = ui.get_batch_queue_panel()
    assert batch_panel.is_visible()
    verify_responsive_layout(page, 390, 844)
    for sel in (
        "[data-testid='batch-clear-btn'], #batch-clear-btn",
        "[data-testid='batch-download-txt-btn'], #batch-download-txt-btn",
        "[data-testid='batch-download-zip-btn'], #batch-download-zip-btn",
        "[data-testid='batch-rehydrate-btn'], #batch-rehydrate-btn",
    ):
        btn = batch_panel.locator(sel).first
        if btn.is_visible():
            bbox = btn.bounding_box()
            assert bbox is not None and bbox["height"] >= 43.5

    tpl_bar = ui.get_prompt_templates_bar()
    assert tpl_bar.is_visible()
    verify_responsive_layout(page, 390, 844)

    for mode in ("sanitize", "rehydrate"):
        ui.switch_mode(mode)
        assert ui.get_ai_launchers_bar().is_visible()
        pills = page.locator("#ai-launchers-bar .ai-launcher-pill")
        assert pills.count() == 6
        for idx in range(pills.count()):
            pbox = pills.nth(idx).bounding_box()
            assert pbox is not None and pbox["height"] >= 43.5

    assert ui.is_ai_launchers_ready() is True
    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        clip = ui.read_clipboard_text() or ""
        assert "mob.a@example.com" not in clip and "mob.b@example.org" not in clip
    finally:
        page.context.unroute("https://gemini.google.com/**")

    dl_modal = ui.open_pro_downloads_modal()
    verify_responsive_layout(page, 390, 844)
    dl_btn = dl_modal.locator("[data-testid='download-extension-zip-btn'], #download-extension-zip-btn").first
    dl_box = dl_btn.bounding_box()
    assert dl_box is not None and dl_box["height"] >= 43.5
    ui.close_active_modal()

    # Key deactivation downgrade -> back to Free
    ui.open_pro_license_modal("header")
    ui.remove_pro_key()
    ui.close_active_modal()

    assert ui.get_pro_badge_text() == "Free"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None
    assert not page.locator("[data-testid='batch-queue-panel'], #batch-queue-panel").is_visible()

    ui.switch_mode("sanitize")
    ui.upload_files([mob_docx])
    assert ui.get_file_pro_upgrade_banner().is_visible()

    dl_trigger = page.locator("[data-testid='open-pro-downloads-btn'], #open-pro-downloads-btn")
    if dl_trigger.count() > 0 and dl_trigger.first.is_visible() and dl_trigger.first.is_enabled():
        dl_trigger.first.click()
        page.wait_for_timeout(120)
        assert not page.locator("[data-testid='modal-pro-downloads'], #modal-pro-downloads").is_visible()
        ui.close_active_modal()

    ui.select_rulebook_profile("Основной")
    ui.close_open_drawer()
    ui.click_clear_input()
    assert "[EMAIL_1]" in ui.sanitize_text("Downgraded free.user@example.ru")
    verify_responsive_layout(page, 390, 844)

    pro_e2e_session.net.assert_zero_egress(["mob.a@example.com", "mob.b@example.org", "free.user@example.ru"])
    pro_e2e_session.console.assert_no_errors()


def test_T4_10_full_buyer_journey_checkout_receipt_pv1_pvkey_zip_to_pro_workbench_ru(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    # 1. Start on / and navigate via #pricing-pro-checkout-link -> /pro/
    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    verify_russian_purity(page)

    ui.open_pricing()
    pro_raw_session.net.phase = "load"
    ui.open_pro_checkout_from_pricing()
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    assert page.url.rstrip("/").endswith("/pro")
    verify_russian_purity(page)

    # 2. Select tariff & payment, fill buyer form, submit -> PV-ORD-...
    ui.select_checkout_plan("pro-annual")
    ui.select_checkout_payment("sbp")
    ui.fill_checkout_buyer(
        name="Елена Соколова",
        email="elena.buyer@example.ru",
        company="ООО «Восток-Право»",
        accept_terms=True,
    )
    ui.submit_checkout_order()

    assert ui.get_checkout_order_panel().is_visible()
    order_id = ui.get_checkout_order_id()
    assert re.match(r"^PV-ORD-[A-Za-z0-9-]+$", order_id)

    # 3. Copy & download receipt
    ui.copy_checkout_receipt()
    clip = ui.read_clipboard_text()
    if clip is not None:
        assert order_id in clip
    receipt_path = ui.download_checkout_receipt(pro_raw_session.io.downloads)
    assert receipt_path.is_file() and order_id in receipt_path.read_text(encoding="utf-8")

    # 4. Verify-only then activate ephemeral PV1. token
    tok = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="PV-T4-BUYER",
        label=f"Годовая подписка ({order_id})",
    )
    ui.verify_checkout_token_only(tok)
    assert "PV-T4-BUYER" in ui.get_checkout_token_diagnostics()
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    ui.activate_checkout_token()
    assert ui.get_checkout_unlocked_panel().is_visible()
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") == tok

    # 5. Download .pvkey & extension ZIP, verify HTTP 200 & PKZIP integrity
    pvkey_path = ui.download_checkout_pvkey(pro_raw_session.io.downloads)
    assert pvkey_path.suffix.lower() == ".pvkey" and tok in pvkey_path.read_text(encoding="utf-8")

    zip_path = ui.download_checkout_extension_zip(pro_raw_session.io.downloads)
    with zipfile.ZipFile(zip_path, "r") as zf:
        assert zf.testzip() is None
        names = set(zf.namelist())
        assert {"manifest.json", "dist/popup.bundle.js"}.issubset(names)
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest.get("manifest_version") == 3

    with urllib.request.urlopen(f"{base}/downloads/promptveil-pro-extension.zip", timeout=5.0) as resp:
        assert int(resp.status) == 200
        with zipfile.ZipFile(io.BytesIO(resp.read()), "r") as zf_http:
            assert zf_http.testzip() is None

    # 6. Return to / and exercise unlocked Pro workbench (.docx batch + custom profile + pack)
    pro_raw_session.net.phase = "load"
    ui.return_to_workbench_from_checkout()
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    assert ui.get_pro_badge_text() == "Pro Активен"
    ui.create_rulebook_profile("Аудит Соколовой")
    ui.apply_industry_word_pack("corporate_ma")
    ui.close_open_drawer()

    docx_p = make_synthetic_docx(
        pro_raw_session.io.uploads / "buyer_audit.docx",
        paragraphs=["Контакт клиента: buyer.secret@example.ru"],
    )
    ui.upload_files([docx_p])
    assert len(ui.get_batch_queue_items()) == 1
    assert "buyer.secret@example.ru" not in ui.get_batch_queue_panel().inner_text()
    ui.click_batch_rehydrate()
    assert "buyer.secret@example.ru" in ui.get_rehydrate_output_text()

    verify_allowed_local_storage_keys(page)
    verify_russian_purity(page)

    for req in pro_raw_session.net.requests:
        hay = f"{req.url} {req.post_data or ''}"
        for sensitive in (tok, "elena.buyer@example.ru", "Елена Соколова", "buyer.secret@example.ru"):
            assert sensitive not in hay
    pro_raw_session.net.assert_zero_egress(
        [tok, "elena.buyer@example.ru", "buyer.secret@example.ru", "PV-T4-BUYER"]
    )
    pro_raw_session.console.assert_no_errors()


def test_T4_11_en_buyer_fragment_code_pvkey_upload_and_mobile_checkout_workflow(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    # 1. Mobile 390x844 on /en/ -> /en/pro/
    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/en/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    verify_responsive_layout(page, 390, 844)
    ui.open_pricing()
    pro_raw_session.net.phase = "load"
    ui.open_pro_checkout_from_pricing()
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    assert page.url.rstrip("/").endswith("/en/pro")
    assert ui.get_document_lang().lower() == "en"
    verify_responsive_layout(page, 390, 844)
    verify_responsive_layout(page, 1440, 900)

    # 2. Submit EN order
    ui.select_checkout_plan("pro-lifetime")
    ui.select_checkout_payment("invoice")
    ui.fill_checkout_buyer(
        name="Alice Mercer",
        email="alice.mercer@example.com",
        company="Mercer Legal LLC",
        accept_terms=True,
    )
    ui.submit_checkout_order()
    assert ui.get_checkout_order_panel().is_visible()
    assert ui.get_checkout_order_id().startswith("PV-ORD-")

    # 3. #code=PV1... fragment auto-fill & auto-verify without HTTP transmission
    tok = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="PV-T4-FRAG",
        label="Alice Mercer Fragment",
    )
    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/en/pro/#code={tok}", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    page.wait_for_timeout(250)

    inp = page.locator("[data-testid='checkout-token-input'], #checkout-token-input").first
    assert tok in inp.input_value()
    assert "PV-T4-FRAG" in ui.get_checkout_token_diagnostics()

    for req in pro_raw_session.net.requests:
        hay = f"{req.url} {req.post_data or ''}"
        assert tok not in hay
        assert "#code=" not in hay

    # 4. Clear input & upload .pvkey file -> activate
    ui.enter_checkout_token("")
    pvkey_file = pro_raw_session.io.uploads / "mercer.pvkey"
    pvkey_file.write_text(f"# PromptVeil Pro License\n{tok}\n", encoding="utf-8")
    ui.upload_checkout_pvkey(pvkey_file)
    assert tok in inp.input_value()

    if page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") != tok:
        ui.activate_checkout_token()
    assert ui.get_checkout_unlocked_panel().is_visible()

    # 5. Return to /en/ and execute Pro prompt template
    pro_raw_session.net.phase = "load"
    ui.return_to_workbench_from_checkout()
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    assert ui.get_pro_badge_text() == "Pro Active"
    ui.click_prompt_template("contract_review")
    assert ui.get_sanitize_output_text().strip()

    verify_allowed_local_storage_keys(page)
    pro_raw_session.net.assert_zero_egress(["alice.mercer@example.com", "PV-T4-FRAG", tok])
    pro_raw_session.console.assert_no_errors()
