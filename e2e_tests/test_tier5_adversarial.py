"""Tier 5: White-Box Adversarial Regression & Coverage Hardening Tests."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
import zlib
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Locator, Page

from conftest import E2ESession, EphemeralProKeys, STATIC_APP_DIR, start_static_dir_server
from doc_fixtures import make_synthetic_docx
from locators import PromptVeilUI
from monitors import (
    ConsoleErrorMonitor,
    NetworkMonitor,
    fetch_http_response,
    verify_csp_and_security_headers,
    verify_russian_purity,
)


pytestmark = [pytest.mark.tier5]


def _first_visible_locator(page: Page, selector: str) -> Locator:
    """Return the first visible element matching selector (avoiding hidden .first matches)."""
    loc = page.locator(selector)
    for idx in range(loc.count()):
        item = loc.nth(idx)
        try:
            if item.is_visible():
                return item
        except Exception:  # noqa: BLE001
            continue
    return loc.locator(":visible").first


# ---------------------------------------------------------------------------
# 1. JS Engine Hardening (detector.js & vault.js)
# ---------------------------------------------------------------------------


def test_T5_01_credit_card_trailing_space_digits_and_20_digit_boundary(
    e2e_session: E2ESession,
) -> None:
    """F1: Valid Luhn cards followed by space-separated digits mask cleanly; 20+ continuous digits do not."""
    prompts = [
        ("Card 4111111111111111 99", "4111111111111111", "[CARD_1]", " 99"),
        ("Card 4000000000006 12", "4000000000006", "[CARD_2]", " 12"),
        ("Card 4111 1111 1111 1111 12", "4111 1111 1111 1111", "[CARD_3]", " 12"),
    ]
    for raw_text, card_val, expected_tok, trailing in prompts:
        out = e2e_session.ui.sanitize_text(raw_text)
        assert expected_tok in out, f"Expected {expected_tok} for {raw_text!r}, got {out!r}"
        assert card_val not in out
        assert out.strip().endswith(trailing.strip()), f"Trailing digits lost in {out!r}"

    neg_out = e2e_session.ui.sanitize_text("Long 41111111111111111111 and date 2026-11-19")
    assert "[CARD_" not in neg_out
    assert "41111111111111111111" in neg_out
    assert "2026-11-19" in neg_out


def test_T5_02_env_secret_opposite_escaped_quotes_and_hash(
    e2e_session: E2ESession,
) -> None:
    """F2: .env RHS handles opposite quotes, escaped quotes, and # inside unquoted values while ignoring inline comments."""
    payload = "\n".join(
        [
            'DB_PASSWORD="my\'secret\'pass"',
            "API_SECRET='pass\"with\"quotes'",
            'ALT_SECRET="my\\"secret\\"pass"',
            "HASH_PASSWORD=Sup3r#Secret99",
            "HASH_SECRET=Sup3rSecret#99",
            "COMMENT_SECRET=secretvalue # inline comment stays",
        ]
    )
    out = e2e_session.ui.sanitize_text(payload)
    for raw_secret in (
        "my'secret'pass",
        'pass"with"quotes',
        'my\\"secret\\"pass',
        "Sup3r#Secret99",
        "Sup3rSecret#99",
        "secretvalue",
    ):
        assert raw_secret not in out, f"Secret leaked in output: {raw_secret!r} -> {out!r}"
    assert " # inline comment stays" in out
    assert e2e_session.ui.get_category_chip_count("ENV_SECRET") == 6


def test_T5_03_high_entropy_colon_delimiter_and_url_path_safety(
    e2e_session: E2ESession,
) -> None:
    """F8: apikey:<secret> masks only <secret>; URLs (incl. :port/path) and Windows paths stay unmasked."""
    payload = (
        "apikey:K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD "
        "https://example.com:8443/v1/users/profile_overview_page "
        "postgres://db.internal:5432/production_analytics_ledger_v2 "
        "redis://cache.internal:6379/session_store_namespace "
        r"C:\Users\Demo\Documents\report_final.pdf "
        r"C:\Users\Demo\VeryLongFolderName123"
    )
    out = e2e_session.ui.sanitize_text(payload)
    assert "apikey:[SECRET_1]" in out
    assert "K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD" not in out
    assert "https://example.com:8443/v1/users/profile_overview_page" in out
    assert "postgres://db.internal:5432/production_analytics_ledger_v2" in out
    assert "redis://cache.internal:6379/session_store_namespace" in out
    assert r"C:\Users\Demo\Documents\report_final.pdf" in out
    assert r"C:\Users\Demo\VeryLongFolderName123" in out
    assert e2e_session.ui.get_category_chip_count("HIGH_ENTROPY") == 1


def test_T5_04_iban_unlisted_prefix_and_phone_ipv4_custom_nfd_boundaries(
    e2e_session: E2ESession,
) -> None:
    """F9 & F10: Unlisted IBAN prefix backtracks cleanly; PHONE/IPV4/CUSTOM NFD boundaries reject false positives."""
    iban_out = e2e_session.ui.sanitize_text("XX11 DE89 3704 0044 0532 0130 00")
    assert iban_out.strip() == "XX11 [IBAN_1]"
    assert "DE89 3704 0044 0532 0130 00" not in iban_out

    false_pos_out = e2e_session.ui.sanitize_text(
        "ID-89165550123 тел89165550123 ver1.2.3.4 host10.0.0.1"
    )
    assert "[PHONE_" not in false_pos_out
    assert "[IP_" not in false_pos_out
    assert "ID-89165550123" in false_pos_out
    assert "тел89165550123" in false_pos_out
    assert "ver1.2.3.4" in false_pos_out
    assert "host10.0.0.1" in false_pos_out

    e2e_session.ui.add_custom_rule("И")
    e2e_session.ui.close_open_drawer()
    nfd_out = e2e_session.ui.sanitize_text("И\u0306ван / И")
    assert nfd_out == "И\u0306ван / [CUSTOM_1]"


def test_T5_05_vault_toggle_value_and_toggle_token_after_prealloc_disable(
    e2e_session: E2ESession,
) -> None:
    """F7: SessionVault.toggleValue/toggleToken flips back to true after pre-allocation toggleToken(token, false)."""
    res = e2e_session.page.evaluate(
        """async () => {
            const { SessionVault } = await import('/js/vault.js');
            const v1 = new SessionVault();
            v1.toggleToken('[EMAIL_1]', false);
            const s1 = v1.sanitize('alice@example.com');
            const flippedVal = v1.toggleValue('EMAIL', 'alice@example.com');
            const s2 = v1.sanitize('alice@example.com');

            const v2 = new SessionVault();
            v2.toggleToken('[EMAIL_1]', false);
            v2.sanitize('alice@example.com');
            const flippedTok = v2.toggleToken('[EMAIL_1]');
            const s3 = v2.sanitize('alice@example.com');
            return {
                s1Enabled: s1.entities[0].enabled,
                flippedVal,
                s2Text: s2.sanitizedText,
                s2Enabled: s2.entities[0].enabled,
                flippedTok,
                s3Text: s3.sanitizedText,
                s3Enabled: s3.entities[0].enabled,
            };
        }"""
    )
    assert res["s1Enabled"] is False
    assert res["flippedVal"] is True
    assert res["s2Enabled"] is True
    assert res["s2Text"] == "[EMAIL_1]"
    assert res["flippedTok"] is True
    assert res["s3Enabled"] is True
    assert res["s3Text"] == "[EMAIL_1]"


# ---------------------------------------------------------------------------
# 2. Storage, Concurrency & Validation Hardening (storage.js & app.js)
# ---------------------------------------------------------------------------


def test_T5_06_malformed_null_audit_log_recovery(raw_session: E2ESession) -> None:
    """F3: Seeding [null, 123, {}] in promptveil_audit_v1 does not crash init() or audit drawer."""
    raw_session.page.goto(f"{raw_session.base_url}/", wait_until="networkidle")
    raw_session.ui.sanitize_text("Ram default ram@example.com")
    assert raw_session.page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None

    raw_session.ui.set_audit_persistence(True)
    raw_session.ui.close_open_drawer()
    raw_session.page.evaluate(
        """() => {
            localStorage.setItem('promptveil_audit_v1', '[null, 123, {}, []]');
        }"""
    )
    raw_session.page.reload(wait_until="networkidle")
    raw_session.console.assert_no_errors()

    assert raw_session.ui.get_audit_hashes() == []
    raw_session.ui.close_open_drawer()
    out = raw_session.ui.sanitize_text("Recover ok@example.com")
    assert "[EMAIL_1]" in out
    assert len(raw_session.ui.get_audit_hashes()) >= 1


def test_T5_07_concurrent_append_audit_order_and_clear_epoch(
    e2e_session: E2ESession,
) -> None:
    """F4: appendAuditReceipt preserves invocation order and clearAuditLog aborts mid-flight pre-clear writes."""
    res = e2e_session.page.evaluate(
        """async () => {
            const {
                appendAuditReceipt,
                clearAuditLog,
                loadAuditLog,
            } = await import('/js/storage.js');

            clearAuditLog();
            const manyEntities = Array.from({ length: 60 }, (_, i) => ({
                category: 'EMAIL',
                value: `u${i}@example.com`,
                token: `[EMAIL_${i + 1}]`,
            }));

            // 1. Concurrent order preservation: SANITIZE invoked first, REHYDRATE second -> [REHYDRATE, SANITIZE]
            const pA = appendAuditReceipt({
                action: 'SANITIZE',
                inputText: 'first',
                outputText: 'first_out',
                entities: manyEntities,
            });
            const pB = appendAuditReceipt({
                action: 'REHYDRATE',
                inputText: 'second',
                outputText: 'second_out',
                entities: [],
                replacedCount: 1,
            });
            await Promise.all([pA, pB]);
            const order = loadAuditLog().map((r) => r.action);

            // 2. Mid-flight clearAuditLog must prevent stale receipt resurrection
            clearAuditLog();
            const pStale = appendAuditReceipt({
                action: 'SANITIZE',
                inputText: 'stale',
                outputText: 'stale_out',
                entities: manyEntities,
            });
            clearAuditLog();
            const staleResult = await pStale;
            const afterClear = loadAuditLog();
            return {
                order,
                staleAborted: staleResult.aborted,
                afterClearCount: afterClear.length,
            };
        }"""
    )
    assert res["order"] == ["REHYDRATE", "SANITIZE"]
    assert res["staleAborted"] is True
    assert res["afterClearCount"] == 0


def test_T5_08_quota_exceeded_memory_fallback_consistency_and_alert(
    e2e_session: E2ESession,
) -> None:
    """F5: QuotaExceededError keeps memoryFallbackStore consistent across UI state and surfaces role='alert'."""
    e2e_session.page.evaluate(
        """() => {
            Storage.prototype.setItem = function() {
                throw new DOMException('QuotaExceededError', 'QuotaExceededError');
            };
        }"""
    )
    e2e_session.ui.add_custom_rule("QuotaRuleTerm")
    e2e_session.ui.close_open_drawer()

    alert_el = _first_visible_locator(
        e2e_session.page,
        "[data-testid='status-banner'][role='alert'], [role='alert']",
    )
    assert alert_el.is_visible()
    alert_text = alert_el.inner_text()
    assert re.search(
        r"quota|storage|memory fallback|хранилищ|памяти|квот|переполн|лимит",
        alert_text,
        re.I,
    )

    out = e2e_session.ui.sanitize_text("Quota user quota@example.com QuotaRuleTerm")
    assert "[EMAIL_1]" in out and "[CUSTOM_1]" in out
    assert len(e2e_session.ui.get_audit_hashes()) >= 1
    e2e_session.ui.close_open_drawer()

    # Self-consistent standalone /js/storage.js memory-fallback check
    standalone_count = e2e_session.page.evaluate(
        """async () => {
            const { saveRules, loadRules } = await import('/js/storage.js');
            saveRules([{ id: 'q1', term: 'StandaloneQuota', label: 'CUSTOM', enabled: true, caseSensitive: false }]);
            return loadRules().filter(r => r.term === 'StandaloneQuota').length;
        }"""
    )
    assert standalone_count == 1


def test_T5_09_duplicate_rule_id_import_single_delete(
    e2e_session: E2ESession,
) -> None:
    """F6: Importing two rules with colliding IDs deduplicates IDs so deleting one leaves the other intact."""
    dup_json = e2e_session.io.uploads / "dup_ids.json"
    dup_json.write_text(
        json.dumps(
            [
                {"id": "dup-1", "term": "ProjectAlpha"},
                {"id": "dup-1", "term": "ProjectBeta"},
            ]
        ),
        encoding="utf-8",
    )
    e2e_session.ui.import_rules_json(dup_json)
    drawer_txt = e2e_session.ui.get_rulebook_text()
    assert "ProjectAlpha" in drawer_txt and "ProjectBeta" in drawer_txt

    e2e_session.ui.delete_custom_rule("ProjectAlpha")
    drawer_after = e2e_session.ui.get_rulebook_text()
    assert "ProjectAlpha" not in drawer_after
    assert "ProjectBeta" in drawer_after
    e2e_session.ui.close_open_drawer()
    assert e2e_session.ui.get_rulebook_badge_count() == 1


def test_T5_10_rapid_filereader_race_and_clear_cancellation(
    e2e_session: E2ESession,
) -> None:
    """Rapid FileReader uploads ignore stale reads; Clear cancels pending FileReader onload."""
    e2e_session.page.evaluate(
        """() => {
            const NativeFR = window.FileReader;
            window.FileReader = class SlowFirstFileReader {
                readAsText(file) {
                    const reader = new NativeFR();
                    const delay = file.name.includes('stale') ? 180 : 15;
                    reader.onload = () => {
                        this.result = reader.result;
                        setTimeout(() => {
                            if (typeof this.onload === 'function') this.onload();
                        }, delay);
                    };
                    reader.onerror = () => {
                        setTimeout(() => {
                            if (typeof this.onerror === 'function') this.onerror();
                        }, delay);
                    };
                    reader.readAsText(file, 'UTF-8');
                }
            };
        }"""
    )

    f1 = e2e_session.io.uploads / "stale_1.txt"
    f1.write_text("STALE_FILE_1 stale@example.com", encoding="utf-8")
    f2 = e2e_session.io.uploads / "fresh_2.txt"
    f2.write_text("FRESH_FILE_2 fresh@example.com", encoding="utf-8")

    file_input = e2e_session.ui.get_workbench_file_input()
    file_input.set_input_files(str(f1))
    file_input.set_input_files(str(f2))
    e2e_session.page.wait_for_timeout(320)

    prompt_val = e2e_session.ui.get_prompt_input().input_value()
    assert "FRESH_FILE_2" in prompt_val
    assert "STALE_FILE_1" not in prompt_val

    # Now upload slow file and immediately click Clear before onload completes
    file_input.set_input_files(str(f1))
    e2e_session.ui.click_clear_input()
    e2e_session.page.wait_for_timeout(300)
    assert e2e_session.ui.get_prompt_input().input_value() == ""


def test_T5_11_import_rules_rejects_oversized_and_non_json_with_alert(
    e2e_session: E2ESession,
) -> None:
    """Rulebook import enforces .json extension and 2 MB cap before reading file, showing role='alert'."""
    e2e_session.ui.add_custom_rule("KeepExistingRule")
    drawer = e2e_session.ui.open_rulebook_drawer()
    file_input = drawer.locator("input[type='file']")

    non_json = e2e_session.io.uploads / "rules.txt"
    non_json.write_text('[{"term":"ShouldNotImport"}]', encoding="utf-8")
    file_input.set_input_files(str(non_json))
    e2e_session.page.wait_for_timeout(120)
    alert_sel = "[data-testid='drawer-rulebook'] [role='alert'], [data-testid='status-banner'][role='alert']"
    err_alert = _first_visible_locator(e2e_session.page, alert_sel)
    assert err_alert.is_visible()
    assert ".json" in err_alert.inner_text().lower()

    huge_json = e2e_session.io.uploads / "huge.json"
    huge_json.write_bytes(b" " * (2 * 1024 * 1024 + 64))
    file_input.set_input_files(str(huge_json))
    e2e_session.page.wait_for_timeout(120)
    err_alert_huge = _first_visible_locator(e2e_session.page, alert_sel)
    assert err_alert_huge.is_visible()
    assert re.search(r"2\s*(?:mb|мб)", err_alert_huge.inner_text(), re.I)
    assert "KeepExistingRule" in e2e_session.ui.get_rulebook_text()


def test_T5_12_live_keystroke_typing_no_phantom_vault_tokens_and_toggle_off_cancels_audit(
    e2e_session: E2ESession,
) -> None:
    """Keystroke-by-keystroke typing produces 1 vault mapping (no phantom bloat); unchecking live toggle cancels audit."""
    inp = e2e_session.ui.get_prompt_input()
    inp.click()
    inp.press_sequentially("alice@example.com", delay=25)
    e2e_session.page.wait_for_timeout(450)

    out = e2e_session.ui.get_sanitize_output_text()
    assert out.strip() == "[EMAIL_1]"
    rows = e2e_session.ui.get_vault_rows()
    assert len(rows) == 1
    assert rows[0].token == "[EMAIL_1]"

    # Clear and test unchecking Live auto-sanitize before liveAuditTimer fires
    e2e_session.ui.clear_audit_log()
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.click_clear_input()

    inp.click()
    inp.fill("sk-proj-TestSynthKey000111222333444")
    inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    e2e_session.ui.set_auto_sanitize(False)
    e2e_session.page.wait_for_timeout(450)
    assert e2e_session.ui.get_audit_hashes() == []


# ---------------------------------------------------------------------------
# 3. Accessibility & Mode 2 State Hardening
# ---------------------------------------------------------------------------


def test_T5_13_modal_focus_trap_aria_expanded_and_tablist_arrows(
    e2e_session: E2ESession,
) -> None:
    """Modal drawers trap Tab/Shift+Tab and update aria-expanded; tablist responds to ArrowLeft/ArrowRight."""
    rule_trigger = e2e_session.page.locator("[data-testid='open-rulebook-btn']").first
    audit_trigger = e2e_session.page.locator("[data-testid='open-audit-btn']").first
    assert rule_trigger.get_attribute("aria-expanded") == "false"
    assert audit_trigger.get_attribute("aria-expanded") == "false"

    # Rulebook drawer focus trap
    rule_trigger.click()
    e2e_session.page.wait_for_timeout(120)
    assert rule_trigger.get_attribute("aria-expanded") == "true"
    e2e_session.page.keyboard.press("Shift+Tab")
    assert e2e_session.page.evaluate(
        "() => Boolean(document.activeElement && document.activeElement.closest('[role=\"dialog\"]'))"
    )
    for _ in range(15):
        e2e_session.page.keyboard.press("Tab")
        assert e2e_session.page.evaluate(
            "() => Boolean(document.activeElement && document.activeElement.closest('[role=\"dialog\"]'))"
        )
    e2e_session.page.keyboard.press("Escape")
    e2e_session.page.wait_for_timeout(120)
    assert rule_trigger.get_attribute("aria-expanded") == "false"

    # Audit drawer focus trap
    audit_trigger.click()
    e2e_session.page.wait_for_timeout(120)
    assert audit_trigger.get_attribute("aria-expanded") == "true"
    e2e_session.page.keyboard.press("Shift+Tab")
    assert e2e_session.page.evaluate(
        "() => Boolean(document.activeElement && document.activeElement.closest('[role=\"dialog\"]'))"
    )
    for _ in range(10):
        e2e_session.page.keyboard.press("Tab")
        assert e2e_session.page.evaluate(
            "() => Boolean(document.activeElement && document.activeElement.closest('[role=\"dialog\"]'))"
        )
    e2e_session.page.keyboard.press("Escape")
    e2e_session.page.wait_for_timeout(120)
    assert audit_trigger.get_attribute("aria-expanded") == "false"

    # Tablist ArrowRight / ArrowLeft navigation
    san_tab = e2e_session.page.locator("[data-testid='mode-sanitize']").first
    reh_tab = e2e_session.page.locator("[data-testid='mode-rehydrate']").first
    san_tab.focus()
    e2e_session.page.keyboard.press("ArrowRight")
    assert reh_tab.get_attribute("aria-selected") == "true"
    assert e2e_session.ui.get_rehydrate_input().is_visible()
    e2e_session.page.keyboard.press("ArrowLeft")
    assert san_tab.get_attribute("aria-selected") == "true"
    assert e2e_session.ui.get_prompt_input().is_visible()


def test_T5_14_rehydrate_error_clears_on_input_and_output_clears_on_empty(
    e2e_session: E2ESession,
) -> None:
    """Mode 2 error clears when typing; clearing LLM reply clears restored output and disables export buttons."""
    e2e_session.ui.sanitize_text("bob@example.com")
    e2e_session.ui.switch_mode("rehydrate")

    rehydrate_btn = e2e_session.page.locator("[data-testid='rehydrate-now-btn']").first
    rehydrate_btn.click()
    err_banner = _first_visible_locator(
        e2e_session.page,
        "[data-testid='status-banner'][role='alert'], main [role='tabpanel']:not([hidden]) [role='alert']",
    )
    assert err_banner.is_visible()

    llm_inp = e2e_session.ui.get_rehydrate_input()
    llm_inp.fill("Hello [EMAIL_1]")
    llm_inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    assert not err_banner.is_visible()

    rehydrate_btn.click()
    assert "Hello bob@example.com" in e2e_session.ui.get_rehydrate_output_text()

    copy_restored = e2e_session.page.locator("[data-testid='copy-restored-btn']").first
    dl_restored = e2e_session.page.locator("[data-testid='download-restored-btn']").first
    assert copy_restored.is_enabled()
    assert dl_restored.is_enabled()

    llm_inp.fill("")
    llm_inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    assert e2e_session.ui.get_rehydrate_output_text() == ""
    assert copy_restored.is_disabled()
    assert dl_restored.is_disabled()


# ---------------------------------------------------------------------------
# 4. Untested UI & Cryptographic Fallback Paths
# ---------------------------------------------------------------------------


def test_T5_15_sha256_fallback_when_crypto_subtle_rejects(
    e2e_session: E2ESession,
) -> None:
    """Pure-JS FIPS 180-4 sha256FallbackHex matches hashlib.sha256 when crypto.subtle.digest rejects."""
    vectors = [
        "",
        "abc",
        "a" * 55,
        "a" * 56,
        "a" * 64,
        "Привет, PromptVeil! ООО «Вектор» — тест SHA-256",
    ]
    e2e_session.page.evaluate(
        """() => {
            if (window.crypto && window.crypto.subtle) {
                window.crypto.subtle.digest = () => Promise.reject(new Error('insecure context simulated'));
            }
        }"""
    )

    js_hashes = e2e_session.page.evaluate(
        """async (vecs) => {
            const { sha256Hex } = await import('/js/storage.js');
            const out = [];
            for (const v of vecs) {
                out.push(await sha256Hex(v));
            }
            return out;
        }""",
        vectors,
    )
    for vec, js_hex in zip(vectors, js_hashes):
        expected = hashlib.sha256(vec.encode("utf-8")).hexdigest()
        assert js_hex == expected, f"SHA-256 fallback mismatch for {vec!r}"

    # Verify UI audit receipt still records exact expected SHA-256 while crypto.subtle is rejecting
    prompt = "Fallback sha@example.com"
    e2e_session.ui.sanitize_text(prompt)
    expected_input_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    assert expected_input_hash in e2e_session.ui.get_audit_hashes()


def test_T5_16_raw_file_over_2mb_rejected_and_drag_drop_upload(
    e2e_session: E2ESession,
) -> None:
    """Raw file > 2 MB is rejected with role='alert'; dropzone drag-and-drop loads local file cleanly."""
    huge_txt = e2e_session.io.uploads / "oversized.txt"
    huge_txt.write_bytes(b"A" * (2 * 1024 * 1024 + 100))
    e2e_session.ui.upload_file(huge_txt)
    notice = e2e_session.ui.get_visible_error_notice()
    assert re.search(r"2\s*(?:mb|мб)", notice, re.I)
    assert e2e_session.ui.get_prompt_input().input_value() == ""

    # Synthetic drag-and-drop onto textarea / dropzone
    dropped = e2e_session.page.evaluate(
        """() => {
            const ta = document.querySelector('[data-testid="raw-prompt-input"]') || document.querySelector('main textarea');
            const dropzone = ta ? (ta.closest('[data-testid="input-dropzone"]') || ta) : null;
            if (!dropzone) return false;
            const file = new File(['Dropped contact drop@example.com'], 'dropped.txt', { type: 'text/plain' });
            const dt = new DataTransfer();
            dt.items.add(file);
            dropzone.dispatchEvent(new DragEvent('dragover', { bubbles: true, cancelable: true, dataTransfer: dt }));
            dropzone.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt }));
            return true;
        }"""
    )
    assert dropped is True
    e2e_session.page.wait_for_timeout(250)
    assert "[EMAIL_1]" in e2e_session.ui.get_sanitize_output_text()
    e2e_session.net.assert_zero_egress(["drop@example.com"])


def test_T5_17_manual_sanitize_toggle_reveal_apply_preset_and_downloads(
    e2e_session: E2ESession,
) -> None:
    """Exercises manual sanitize mode, Hide/Show Values toggle, Apply Preset Rules, and both Download .txt actions."""
    e2e_session.ui.set_auto_sanitize(False)

    inp = e2e_session.ui.get_prompt_input()
    inp.fill("Manual manual@example.com")
    inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    e2e_session.page.wait_for_timeout(200)
    assert e2e_session.ui.get_sanitize_output_text() == ""

    e2e_session.page.locator("[data-testid='sanitize-now-btn']").first.click()
    assert "[EMAIL_1]" in e2e_session.ui.get_sanitize_output_text()

    # Hide / Show Values toggle & aria-pressed contract
    assert e2e_session.ui.get_hide_values_pressed() == "false"
    e2e_session.ui.toggle_hide_values()
    assert e2e_session.ui.get_hide_values_pressed() == "true"
    assert "manual@example.com" not in e2e_session.ui.get_vault_rows()[0].raw_text
    e2e_session.ui.toggle_hide_values()
    assert e2e_session.ui.get_hide_values_pressed() == "false"
    assert "manual@example.com" in e2e_session.ui.get_vault_rows()[0].raw_text

    # Download sanitized .txt
    san_path = e2e_session.ui.download_sanitized(Path(e2e_session.io.downloads))
    assert "[EMAIL_1]" in san_path.read_text(encoding="utf-8")

    # Apply Preset Rules (optional [data-testid='apply-preset-rules-btn'] per PROJECT.md § Interface Contracts § 1)
    e2e_session.ui.select_preset("client_contract")
    raw_preset_text = e2e_session.ui.get_prompt_input().input_value()
    assert raw_preset_text.strip()
    apply_btn = e2e_session.page.locator("[data-testid='apply-preset-rules-btn']")
    if apply_btn.count() > 0 and apply_btn.first.is_visible():
        apply_btn.first.click()
        e2e_session.page.wait_for_timeout(120)
        assert e2e_session.ui.get_rulebook_badge_count() >= 1
        assert not apply_btn.first.is_visible()

    # Re-Hydrate + Download restored .txt
    sanitized_preset = e2e_session.ui.get_sanitize_output_text()
    assert re.search(r"\[[A-Z_]+_\d+\]", sanitized_preset)
    e2e_session.ui.rehydrate_text(sanitized_preset)
    res_path = e2e_session.ui.download_restored(Path(e2e_session.io.downloads))
    assert res_path.read_text(encoding="utf-8").strip() == raw_preset_text.strip()


def test_T5_18_clear_buttons_rule_case_sensitive_toggle_clipboard_blocked_alert(
    e2e_session: E2ESession,
) -> None:
    """Exercises Clear buttons, case-sensitive + toggleable custom rules, case-insensitive duplicate conflict, and clipboard error alert."""
    # Case-sensitive custom rule & per-rule ON/OFF switch
    drawer = e2e_session.ui.open_rulebook_drawer()
    drawer.locator("[data-testid='rule-term-input']").fill("SecretCode")
    drawer.locator("[data-testid='rule-case-input']").check()
    drawer.locator("[data-testid='add-rule-btn']").click()
    e2e_session.ui.close_open_drawer()

    out_cs = e2e_session.ui.sanitize_text("secretcode vs SecretCode")
    assert out_cs == "secretcode vs [CUSTOM_1]"

    # Toggle custom rule OFF inside Rulebook
    drawer = e2e_session.ui.open_rulebook_drawer()
    drawer.get_by_role("switch").first.click()
    e2e_session.ui.close_open_drawer()
    assert e2e_session.ui.get_sanitize_output_text() == "secretcode vs SecretCode"

    # Case-insensitive duplicate conflict
    e2e_session.ui.add_custom_rule("AcmeDup")
    e2e_session.ui.add_custom_rule("acmedup")
    dup_alert = _first_visible_locator(
        e2e_session.page,
        "[data-testid='drawer-rulebook'] [role='alert'], [data-testid='status-banner'][role='alert']",
    )
    assert dup_alert.is_visible()
    assert re.search(r"duplicate|дубликат|уже\s+(?:есть|добав|существ)", dup_alert.inner_text(), re.I)
    e2e_session.ui.close_open_drawer()

    # Clipboard blocked -> global status banner uses role='alert'
    e2e_session.ui.sanitize_text("Clip clip@example.com")
    e2e_session.page.evaluate(
        """() => {
            Object.defineProperty(navigator, 'clipboard', {
                configurable: true,
                value: { writeText: () => Promise.reject(new Error('blocked')) },
            });
            document.execCommand = () => false;
        }"""
    )
    e2e_session.ui.click_copy_output()
    alert = (
        e2e_session.page.locator("[data-testid='status-banner'][role='alert'], [role='alert']")
        .filter(has_text=re.compile(r"clipboard|буфер|скопир", re.I))
        .locator(":visible")
    )
    assert alert.count() >= 1 and alert.first.is_visible()

    # Clear buttons in Sanitize & Re-Hydrate modes
    e2e_session.ui.click_clear_input()
    assert e2e_session.ui.get_prompt_input().input_value() == ""
    assert e2e_session.ui.get_sanitize_output_text() == ""

    e2e_session.ui.rehydrate_text("Reply [EMAIL_1]")
    reh_clear = e2e_session.page.locator(
        "[data-testid='clear-rehydrate-btn'], [data-testid='panel-rehydrate'] button"
    ).filter(has_text=re.compile(r"^(?:очистить|сбросить|clear)$", re.I))
    if reh_clear.count() > 0 and reh_clear.first.is_visible():
        reh_clear.first.click()
    else:
        reh_inp = e2e_session.ui.get_rehydrate_input()
        reh_inp.fill("")
        reh_inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    assert e2e_session.ui.get_rehydrate_input().input_value() == ""
    assert e2e_session.ui.get_rehydrate_output_text() == ""


# ---------------------------------------------------------------------------
# 5. Iteration-3 Adversarial Regressions (ENV quotes, Auth Bearer, Vault JWT/ENV evolution, URL schemes, Card-dash)
# ---------------------------------------------------------------------------


def test_T5_19_env_secret_unquoted_embedded_quotes_and_auth_bearer(
    e2e_session: E2ESession,
) -> None:
    """Unquoted ENV_SECRET allows embedded quotes; Authorization: Bearer leaves Bearer unmasked and masks token."""
    env_payload = "\n".join(
        [
            'DB_PASSWORD=abc"def123',
            'API_SECRET=123456"789',
            "TOKEN_VAL=xyz'uvw123",
            'QUOTED_SECRET="mysecret" # inline comment',
            "HASH_PASSWORD=Sup3r#Secret99 # inline comment",
        ]
    )
    out = e2e_session.ui.sanitize_text(env_payload)
    for raw_secret in ('abc"def123', '123456"789', "xyz'uvw123", "mysecret", "Sup3r#Secret99", '"789'):
        assert raw_secret not in out, f"Secret fragment leaked: {raw_secret!r} -> {out!r}"
    assert out.count("[ENV_SECRET_") == 5
    assert " # inline comment" in out

    # Authorization: Bearer with HIGH_ENTROPY, API_KEY, and JWT
    e2e_session.ui.click_clear_input()
    out_ent = e2e_session.ui.sanitize_text("Authorization: Bearer K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD")
    assert out_ent.strip() == "Authorization: Bearer [SECRET_1]"
    assert "[ENV_SECRET_" not in out_ent

    e2e_session.ui.click_clear_input()
    out_api = e2e_session.ui.sanitize_text("Authorization: Bearer sk-proj-PromptVeilDemoKey9876543210abcdef")
    assert out_api.strip() == "Authorization: Bearer [API_KEY_1]"
    assert "[ENV_SECRET_" not in out_api

    e2e_session.ui.click_clear_input()
    out_jwt = e2e_session.ui.sanitize_text(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIn0.synthSig_1234567890"
    )
    assert out_jwt.strip() == "Authorization: Bearer [JWT_1]"
    assert "[ENV_SECRET_" not in out_jwt


def test_T5_20_vault_evolve_transient_jwt_live_typing_and_env_prefix(
    e2e_session: E2ESession,
) -> None:
    """Evolving HIGH_ENTROPY -> JWT (live typing across debounce) or ENV_SECRET cleans up orphaned [SECRET_1]."""
    inp = e2e_session.ui.get_prompt_input()
    inp.click()
    inp.press_sequentially("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "[SECRET_1]"

    inp.press_sequentially(".eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", delay=5)
    e2e_session.page.wait_for_timeout(450)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "[JWT_1]"
    rows = e2e_session.ui.get_vault_rows()
    assert len(rows) == 1
    assert rows[0].token == "[JWT_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"

    # Direct SessionVault test for prepending MY_SECRET= before a HIGH_ENTROPY token
    vault_res = e2e_session.page.evaluate(
        """async () => {
            const { SessionVault } = await import('/js/vault.js');
            const v = new SessionVault();
            const r1 = v.sanitize('K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD', [], { evolveTransient: true });
            const r2 = v.sanitize('MY_SECRET=K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD', [], { evolveTransient: true });
            return {
                r1Text: r1.sanitizedText,
                r2Text: r2.sanitizedText,
                tokens: Array.from(v.tokenToEntry.keys()),
                secretCounter: v.counters.get('SECRET') || 0,
            };
        }"""
    )
    assert vault_res["r1Text"] == "[SECRET_1]"
    assert vault_res["r2Text"] == "MY_SECRET=[ENV_SECRET_1]"
    assert vault_res["tokens"] == ["[ENV_SECRET_1]"]
    assert vault_res["secretCounter"] == 0


def test_T5_21_high_entropy_generalized_url_schemes_and_card_dashed_suffix(
    e2e_session: E2ESession,
) -> None:
    """Generalized :port/path URL schemes (grpcs://, amqp://) stay unmasked; spaced card + dashed suffix masks card."""
    payload = (
        "grpcs://api.internal:9443/v1/services/long_method_endpoint_name "
        "amqp://rabbit.internal:5672/production_vhost_name "
        "apikey:K7xM9pQ2vR8nL4wZ6tB1yF5hJ3cN0sD "
        "Card 4111 1111 1111 1111-99"
    )
    out = e2e_session.ui.sanitize_text(payload)
    assert "grpcs://api.internal:9443/v1/services/long_method_endpoint_name" in out
    assert "amqp://rabbit.internal:5672/production_vhost_name" in out
    assert "apikey:[SECRET_1]" in out
    assert "Card [CARD_1]-99" in out
    assert "4111 1111 1111 1111" not in out
    assert e2e_session.ui.get_category_chip_count("HIGH_ENTROPY") == 1
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 1


def test_T5_22_vault_evolve_transient_env_to_api_key_jwt_and_email_to_env(
    e2e_session: E2ESession,
) -> None:
    """Evolving ENV_SECRET -> API_KEY/JWT (live typing) or EMAIL -> ENV_SECRET cleans up orphaned transient tokens."""
    inp = e2e_session.ui.get_prompt_input()

    # 1. Live typing: OPENAI_API_KEY=sk-proj-... pauses as [ENV_SECRET_1], then upgrades to [API_KEY_1]
    inp.click()
    inp.press_sequentially("OPENAI_API_KEY=sk-proj-PromptVeil", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "OPENAI_API_KEY=[ENV_SECRET_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    assert len(e2e_session.ui.get_vault_rows()) == 1

    inp.press_sequentially("DemoKey9876543210abcdef", delay=5)
    e2e_session.page.wait_for_timeout(450)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "OPENAI_API_KEY=[API_KEY_1]"
    rows_api = e2e_session.ui.get_vault_rows()
    assert len(rows_api) == 1
    assert rows_api[0].token == "[API_KEY_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"

    # 2. Live typing: MY_TOKEN=eyJ... pauses as [ENV_SECRET_1], then upgrades to [JWT_1]
    e2e_session.ui.click_clear_input()
    inp.click()
    inp.press_sequentially("MY_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_TOKEN=[ENV_SECRET_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    assert len(e2e_session.ui.get_vault_rows()) == 1

    inp.press_sequentially(".eyJzdWIiOiJ0ZXN0MTIzIn0.synthSig_1234567890", delay=5)
    e2e_session.page.wait_for_timeout(450)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_TOKEN=[JWT_1]"
    rows_jwt = e2e_session.ui.get_vault_rows()
    assert len(rows_jwt) == 1
    assert rows_jwt[0].token == "[JWT_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"

    # 3. Direct SessionVault checks for ENV_SECRET -> API_KEY, ENV_SECRET -> JWT, and EMAIL -> ENV_SECRET
    vault_res = e2e_session.page.evaluate(
        """async () => {
            const { SessionVault } = await import('/js/vault.js');

            const vApi = new SessionVault();
            const a1 = vApi.sanitize('OPENAI_API_KEY=sk-proj-PromptVeil', [], { evolveTransient: true });
            const a2 = vApi.sanitize('OPENAI_API_KEY=sk-proj-PromptVeilDemoKey9876543210abcdef', [], { evolveTransient: true });

            const vJwt = new SessionVault();
            const j1 = vJwt.sanitize('MY_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', [], { evolveTransient: true });
            const j2 = vJwt.sanitize('MY_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIn0.synthSig_1234567890', [], { evolveTransient: true });

            const vEmail = new SessionVault();
            const e1 = vEmail.sanitize('alice@example.com', [], { evolveTransient: true });
            const e2 = vEmail.sanitize('SECRET_EMAIL=alice@example.com', [], { evolveTransient: true });

            return {
                api: {
                    r1: a1.sanitizedText,
                    r2: a2.sanitizedText,
                    size: vApi.tokenToEntry.size,
                    tokens: Array.from(vApi.tokenToEntry.keys()),
                    envCounter: vApi.counters.get('ENV_SECRET') || 0,
                    apiCounter: vApi.counters.get('API_KEY') || 0,
                },
                jwt: {
                    r1: j1.sanitizedText,
                    r2: j2.sanitizedText,
                    size: vJwt.tokenToEntry.size,
                    tokens: Array.from(vJwt.tokenToEntry.keys()),
                    envCounter: vJwt.counters.get('ENV_SECRET') || 0,
                    jwtCounter: vJwt.counters.get('JWT') || 0,
                },
                email: {
                    r1: e1.sanitizedText,
                    r2: e2.sanitizedText,
                    size: vEmail.tokenToEntry.size,
                    tokens: Array.from(vEmail.tokenToEntry.keys()),
                    emailCounter: vEmail.counters.get('EMAIL') || 0,
                    envCounter: vEmail.counters.get('ENV_SECRET') || 0,
                },
            };
        }"""
    )

    assert vault_res["api"] == {
        "r1": "OPENAI_API_KEY=[ENV_SECRET_1]",
        "r2": "OPENAI_API_KEY=[API_KEY_1]",
        "size": 1,
        "tokens": ["[API_KEY_1]"],
        "envCounter": 0,
        "apiCounter": 1,
    }
    assert vault_res["jwt"] == {
        "r1": "MY_TOKEN=[ENV_SECRET_1]",
        "r2": "MY_TOKEN=[JWT_1]",
        "size": 1,
        "tokens": ["[JWT_1]"],
        "envCounter": 0,
        "jwtCounter": 1,
    }
    assert vault_res["email"] == {
        "r1": "[EMAIL_1]",
        "r2": "SECRET_EMAIL=[ENV_SECRET_1]",
        "size": 1,
        "tokens": ["[ENV_SECRET_1]"],
        "emailCounter": 0,
        "envCounter": 1,
    }


def test_T5_23_vault_evolve_transient_symmetric_downgrade_and_multi_prefix_eviction(
    e2e_session: E2ESession,
) -> None:
    """Downward cross-category live edits (API_KEY->ENV_SECRET, ENV_SECRET->EMAIL, JWT->HIGH_ENTROPY) and multi-prefix upgrades evict inactive entries cleanly."""
    inp = e2e_session.ui.get_prompt_input()

    # 1. Live browser typing + backspacing API_KEY -> ENV_SECRET, then re-typing to API_KEY
    inp.click()
    inp.press_sequentially("OPENAI_API_KEY=sk-proj-PromptVeilDemoKey9876543210abcdef", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "OPENAI_API_KEY=[API_KEY_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    assert len(e2e_session.ui.get_vault_rows()) == 1

    for _ in range(23):
        e2e_session.page.keyboard.press("Backspace")
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "OPENAI_API_KEY=[ENV_SECRET_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_down = e2e_session.ui.get_vault_rows()
    assert len(rows_down) == 1
    assert rows_down[0].token == "[ENV_SECRET_1]"

    inp.press_sequentially("NewKey9876543210abcdef", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "OPENAI_API_KEY=[API_KEY_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_retyped = e2e_session.ui.get_vault_rows()
    assert len(rows_retyped) == 1
    assert rows_retyped[0].token == "[API_KEY_1]"

    rehydrated = e2e_session.ui.rehydrate_text("Use [API_KEY_1] and old [ENV_SECRET_1]")
    assert "Use sk-proj-PromptVeilNewKey9876543210abcdef and old [ENV_SECRET_1]" in rehydrated
    assert "DemoKey9876543210abcdef" not in rehydrated

    e2e_session.ui.switch_mode("sanitize")
    e2e_session.ui.click_clear_input()

    # 2. Live browser ENV_SECRET -> EMAIL prefix removal
    inp.fill("SECRET_EMAIL=alice@example.com")
    inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "SECRET_EMAIL=[ENV_SECRET_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    assert len(e2e_session.ui.get_vault_rows()) == 1

    inp.fill("alice@example.com")
    inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "[EMAIL_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_email = e2e_session.ui.get_vault_rows()
    assert len(rows_email) == 1
    assert rows_email[0].token == "[EMAIL_1]"

    e2e_session.ui.click_clear_input()

    # 3. Live browser JWT -> HIGH_ENTROPY backspace downgrade
    inp.click()
    inp.press_sequentially(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIn0.synthSig_1234567890",
        delay=5,
    )
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "[JWT_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    assert len(e2e_session.ui.get_vault_rows()) == 1

    for _ in range(16):
        e2e_session.page.keyboard.press("Backspace")
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "[SECRET_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_secret = e2e_session.ui.get_vault_rows()
    assert len(rows_secret) == 1
    assert rows_secret[0].token == "[SECRET_1]"

    # 4. Direct SessionVault checks for downward transitions, multi-prefix eviction, and evolveTransient: false
    vault_res = e2e_session.page.evaluate(
        """async () => {
            const { SessionVault } = await import('/js/vault.js');

            // ENV_SECRET -> EMAIL
            const vEmail = new SessionVault();
            const em1 = vEmail.sanitize('SECRET_EMAIL=alice@example.com', [], { evolveTransient: true });
            const em2 = vEmail.sanitize('alice@example.com', [], { evolveTransient: true });

            // JWT -> HIGH_ENTROPY (with excludedValues cleanup check)
            const vJwt = new SessionVault();
            const j1 = vJwt.sanitize(
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIn0.synthSig_1234567890',
                [],
                { evolveTransient: true }
            );
            vJwt.toggleToken('[JWT_1]', false);
            const j2 = vJwt.sanitize(
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIn0.syn',
                [],
                { evolveTransient: true }
            );

            // Multi-inactive-prefix eviction: [ENV_SECRET_1] + [ENV_SECRET_2] -> [API_KEY_1]
            const vMulti = new SessionVault();
            vMulti.sanitize('API_KEY_A=sk-proj-Prompt', [], { evolveTransient: true });
            vMulti.sanitize('API_KEY_A=sk-proj-Prompt\\nAPI_KEY_B=sk-proj-PromptVeil', [], { evolveTransient: true });
            const m3 = vMulti.sanitize(
                'API_KEY_A=sk-proj-PromptVeilDemoKey9876543210abcdef',
                [],
                { evolveTransient: true }
            );

            // evolveTransient: false preserves multi-turn vault entries
            const vManual = new SessionVault();
            vManual.sanitize('OPENAI_API_KEY=sk-proj-PromptVeilDemoKey9876543210abcdef', [], { evolveTransient: false });
            vManual.sanitize('OPENAI_API_KEY=sk-proj-PromptVeil', [], { evolveTransient: false });

            return {
                email: {
                    r1: em1.sanitizedText,
                    r2: em2.sanitizedText,
                    size: vEmail.tokenToEntry.size,
                    tokens: Array.from(vEmail.tokenToEntry.keys()),
                    envCounter: vEmail.counters.get('ENV_SECRET') || 0,
                    emailCounter: vEmail.counters.get('EMAIL') || 0,
                },
                jwt: {
                    r1: j1.sanitizedText,
                    r2: j2.sanitizedText,
                    size: vJwt.tokenToEntry.size,
                    tokens: Array.from(vJwt.tokenToEntry.keys()),
                    excludedSize: vJwt.excludedValues.size,
                    jwtCounter: vJwt.counters.get('JWT') || 0,
                    secretCounter: vJwt.counters.get('SECRET') || 0,
                },
                multi: {
                    r3: m3.sanitizedText,
                    size: vMulti.tokenToEntry.size,
                    tokens: Array.from(vMulti.tokenToEntry.keys()),
                    envCounter: vMulti.counters.get('ENV_SECRET') || 0,
                    apiCounter: vMulti.counters.get('API_KEY') || 0,
                },
                manualSize: vManual.tokenToEntry.size,
                manualTokens: Array.from(vManual.tokenToEntry.keys()),
            };
        }"""
    )

    assert vault_res["email"] == {
        "r1": "SECRET_EMAIL=[ENV_SECRET_1]",
        "r2": "[EMAIL_1]",
        "size": 1,
        "tokens": ["[EMAIL_1]"],
        "envCounter": 0,
        "emailCounter": 1,
    }
    assert vault_res["jwt"] == {
        "r1": "[JWT_1]",
        "r2": "[SECRET_1]",
        "size": 1,
        "tokens": ["[SECRET_1]"],
        "excludedSize": 0,
        "jwtCounter": 0,
        "secretCounter": 1,
    }
    assert vault_res["multi"] == {
        "r3": "API_KEY_A=[API_KEY_1]",
        "size": 1,
        "tokens": ["[API_KEY_1]"],
        "envCounter": 0,
        "apiCounter": 1,
    }
    assert vault_res["manualSize"] == 2
    assert vault_res["manualTokens"] == ["[API_KEY_1]", "[ENV_SECRET_1]"]


def test_T5_24_vault_evolve_transient_bounded_cross_category_eviction(
    e2e_session: E2ESession,
) -> None:
    """Cross-category transient eviction works regardless of priority-vs-length order (SSN/CARD/IBAN<->ENV_SECRET, CUSTOM->SSN)."""
    inp = e2e_session.ui.get_prompt_input()

    # 1. Live browser typing + backspacing: SSN <-> ENV_SECRET (shorter higher-priority -> longer lower-priority -> back)
    inp.click()
    inp.press_sequentially("MY_SECRET=123-45-6789", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_SECRET=[SSN_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_ssn = e2e_session.ui.get_vault_rows()
    assert len(rows_ssn) == 1
    assert rows_ssn[0].token == "[SSN_1]"

    inp.press_sequentially("0", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_SECRET=[ENV_SECRET_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_env = e2e_session.ui.get_vault_rows()
    assert len(rows_env) == 1
    assert rows_env[0].token == "[ENV_SECRET_1]"

    e2e_session.page.keyboard.press("Backspace")
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_SECRET=[SSN_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_ssn_back = e2e_session.ui.get_vault_rows()
    assert len(rows_ssn_back) == 1
    assert rows_ssn_back[0].token == "[SSN_1]"

    rehydrated_ssn = e2e_session.ui.rehydrate_text("Current [SSN_1] and stale [ENV_SECRET_1]")
    assert "Current 123-45-6789 and stale [ENV_SECRET_1]" in rehydrated_ssn
    assert "123-45-67890" not in rehydrated_ssn

    e2e_session.ui.switch_mode("sanitize")
    e2e_session.ui.click_clear_input()

    # 2. Live browser typing + backspacing: CREDIT_CARD <-> ENV_SECRET
    inp.click()
    inp.press_sequentially("MY_SECRET=4111111111111111", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_SECRET=[CARD_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_card = e2e_session.ui.get_vault_rows()
    assert len(rows_card) == 1
    assert rows_card[0].token == "[CARD_1]"

    inp.press_sequentially("5", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_SECRET=[ENV_SECRET_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_card_env = e2e_session.ui.get_vault_rows()
    assert len(rows_card_env) == 1
    assert rows_card_env[0].token == "[ENV_SECRET_1]"

    e2e_session.page.keyboard.press("Backspace")
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "MY_SECRET=[CARD_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "1"
    rows_card_back = e2e_session.ui.get_vault_rows()
    assert len(rows_card_back) == 1
    assert rows_card_back[0].token == "[CARD_1]"

    rehydrated_card = e2e_session.ui.rehydrate_text("Current [CARD_1] and stale [ENV_SECRET_1]")
    assert "Current 4111111111111111 and stale [ENV_SECRET_1]" in rehydrated_card
    assert "41111111111111115" not in rehydrated_card

    # 3. Direct SessionVault verification for IBAN -> ENV_SECRET, CUSTOM -> SSN, and SSN -> ENV_SECRET w/ toggleToken
    vault_res = e2e_session.page.evaluate(
        """async () => {
            const { SessionVault } = await import('/js/vault.js');

            // IBAN -> ENV_SECRET
            const vIban = new SessionVault();
            const ib1 = vIban.sanitize('MY_SECRET=DE89370400440532013000', [], { evolveTransient: true });
            const ib2 = vIban.sanitize('MY_SECRET=DE89370400440532013000X', [], { evolveTransient: true });

            // CUSTOM -> SSN
            const vCustom = new SessionVault();
            const customRules = [{ id: 'c1', term: '123-45-67890', enabled: true, caseSensitive: false }];
            const c1 = vCustom.sanitize('123-45-67890', customRules, { evolveTransient: true });
            const c2 = vCustom.sanitize('123-45-6789', customRules, { evolveTransient: true });

            // SSN -> ENV_SECRET with prior toggleToken('[SSN_1]', false)
            const vSsn = new SessionVault();
            const s1 = vSsn.sanitize('MY_SECRET=123-45-6789', [], { evolveTransient: true });
            vSsn.toggleToken('[SSN_1]', false);
            const s2 = vSsn.sanitize('MY_SECRET=123-45-67890', [], { evolveTransient: true });
            const sReh = vSsn.rehydrate('Old [SSN_1] and new [ENV_SECRET_1]');

            return {
                iban: {
                    r1: ib1.sanitizedText,
                    r2: ib2.sanitizedText,
                    size: vIban.tokenToEntry.size,
                    tokens: Array.from(vIban.tokenToEntry.keys()),
                    ibanCounter: vIban.counters.get('IBAN') || 0,
                    envCounter: vIban.counters.get('ENV_SECRET') || 0,
                },
                custom: {
                    r1: c1.sanitizedText,
                    r2: c2.sanitizedText,
                    size: vCustom.tokenToEntry.size,
                    tokens: Array.from(vCustom.tokenToEntry.keys()),
                    customCounter: vCustom.counters.get('CUSTOM') || 0,
                    ssnCounter: vCustom.counters.get('SSN') || 0,
                },
                ssnExcluded: {
                    r1: s1.sanitizedText,
                    r2: s2.sanitizedText,
                    r2Enabled: s2.entities[0].enabled,
                    size: vSsn.tokenToEntry.size,
                    tokens: Array.from(vSsn.tokenToEntry.keys()),
                    excludedSize: vSsn.excludedValues.size,
                    ssnCounter: vSsn.counters.get('SSN') || 0,
                    envCounter: vSsn.counters.get('ENV_SECRET') || 0,
                    rehydratedText: sReh.rehydratedText ?? sReh.restoredText,
                },
            };
        }"""
    )

    assert vault_res["iban"] == {
        "r1": "MY_SECRET=[IBAN_1]",
        "r2": "MY_SECRET=[ENV_SECRET_1]",
        "size": 1,
        "tokens": ["[ENV_SECRET_1]"],
        "ibanCounter": 0,
        "envCounter": 1,
    }
    assert vault_res["custom"] == {
        "r1": "[CUSTOM_1]",
        "r2": "[SSN_1]",
        "size": 1,
        "tokens": ["[SSN_1]"],
        "customCounter": 0,
        "ssnCounter": 1,
    }
    assert vault_res["ssnExcluded"] == {
        "r1": "MY_SECRET=[SSN_1]",
        "r2": "MY_SECRET=[ENV_SECRET_1]",
        "r2Enabled": True,
        "size": 1,
        "tokens": ["[ENV_SECRET_1]"],
        "excludedSize": 0,
        "ssnCounter": 0,
        "envCounter": 1,
        "rehydratedText": "Old [SSN_1] and new 123-45-67890",
    }


def test_T5_25_vault_evolve_transient_existing_token_collapse_and_multi_span_reuse(
    e2e_session: E2ESession,
) -> None:
    """Collapsing a transient entry onto an existingToken evicts inactive prefix entries without breaking multi-span reuse."""
    inp = e2e_session.ui.get_prompt_input()

    # 1. Live browser UI: API_KEY + ENV_SECRET prefix collapsing onto [API_KEY_1]
    inp.click()
    inp.press_sequentially(
        "A_API_KEY=sk-proj-PromptVeilDemoKey9876543210abcdef\nB_API_KEY=sk-proj-PromptVeil",
        delay=5,
    )
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == (
        "A_API_KEY=[API_KEY_1]\nB_API_KEY=[ENV_SECRET_1]"
    )
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "2"
    assert len(e2e_session.ui.get_vault_rows()) == 2

    inp.press_sequentially("DemoKey9876543210abcdef", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == (
        "A_API_KEY=[API_KEY_1]\nB_API_KEY=[API_KEY_1]"
    )
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "2"
    rows_api = e2e_session.ui.get_vault_rows()
    assert len(rows_api) == 1
    assert rows_api[0].token == "[API_KEY_1]"

    rehydrated_api = e2e_session.ui.rehydrate_text(
        "Current [API_KEY_1] and phantom [ENV_SECRET_1]"
    )
    assert (
        "Current sk-proj-PromptVeilDemoKey9876543210abcdef and phantom [ENV_SECRET_1]"
        in rehydrated_api
    )
    assert "phantom sk-proj-PromptVeil" not in rehydrated_api

    e2e_session.ui.switch_mode("sanitize")
    e2e_session.ui.click_clear_input()

    # 2. Live browser UI: Email prefix collapsing onto [EMAIL_1]
    inp.click()
    inp.press_sequentially("A=alice@example.com\nB=alice@example.co", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "A=[EMAIL_1]\nB=[EMAIL_2]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "2"
    assert len(e2e_session.ui.get_vault_rows()) == 2

    inp.press_sequentially("m", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == "A=[EMAIL_1]\nB=[EMAIL_1]"
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "2"
    rows_email = e2e_session.ui.get_vault_rows()
    assert len(rows_email) == 1
    assert rows_email[0].token == "[EMAIL_1]"

    e2e_session.ui.click_clear_input()

    # 3. Live browser UI: Backspacing ENV_SECRET onto existing [SSN_1]
    inp.click()
    inp.press_sequentially("KEEP=123-45-6789\nMY_SECRET=123-45-67890", delay=5)
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == (
        "KEEP=[SSN_1]\nMY_SECRET=[ENV_SECRET_1]"
    )
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "2"
    assert len(e2e_session.ui.get_vault_rows()) == 2

    e2e_session.page.keyboard.press("Backspace")
    e2e_session.page.wait_for_timeout(240)
    assert e2e_session.ui.get_sanitize_output_text().strip() == (
        "KEEP=[SSN_1]\nMY_SECRET=[SSN_1]"
    )
    assert str(e2e_session.ui.get_telemetry_masked_count()) == "2"
    rows_ssn = e2e_session.ui.get_vault_rows()
    assert len(rows_ssn) == 1
    assert rows_ssn[0].token == "[SSN_1]"

    # 4. Direct SessionVault checks: counters, excludedValues cleanup, multi-span reuse, and evolveTransient: false
    vault_res = e2e_session.page.evaluate(
        """async () => {
            const { SessionVault } = await import('/js/vault.js');

            // Email collapse with [EMAIL_2] excluded and [EMAIL_1] excluded/preserved
            const vEmailCollapse = new SessionVault();
            vEmailCollapse.sanitize('A=alice@example.com\\nB=alice@example.co', [], { evolveTransient: true });
            vEmailCollapse.toggleToken('[EMAIL_1]', false);
            vEmailCollapse.toggleToken('[EMAIL_2]', false);
            const ec2 = vEmailCollapse.sanitize('A=alice@example.com\\nB=alice@example.com', [], { evolveTransient: true });

            // Pre-allocation toggleToken('[EMAIL_2]', false) also clears on collapse
            const vPreExcl = new SessionVault();
            vPreExcl.toggleToken('[EMAIL_2]', false);
            vPreExcl.sanitize('A=alice@example.com\\nB=alice@example.co', [], { evolveTransient: true });
            vPreExcl.sanitize('A=alice@example.com\\nB=alice@example.com', [], { evolveTransient: true });

            // SSN backspace collapse counter check
            const vSsnCollapse = new SessionVault();
            vSsnCollapse.sanitize('KEEP=123-45-6789\\nMY_SECRET=123-45-67890', [], { evolveTransient: true });
            const sc2 = vSsnCollapse.sanitize('KEEP=123-45-6789\\nMY_SECRET=123-45-6789', [], { evolveTransient: true });

            // Multi-span same-category reuse: span1 hits [EMAIL_1], span2 reuses [EMAIL_2] without premature eviction
            const vMultiSpan = new SessionVault();
            vMultiSpan.sanitize('A=alice@example.com\\nB=alice@example.co', [], { evolveTransient: true });
            const ms2 = vMultiSpan.sanitize('A=alice@example.com\\nB=alice@example.com.uk', [], { evolveTransient: true });

            // evolveTransient: false preserves multi-turn tokens
            const vManual = new SessionVault();
            vManual.sanitize('A=alice@example.com\\nB=alice@example.co', [], { evolveTransient: false });
            const man2 = vManual.sanitize('A=alice@example.com\\nB=alice@example.com', [], { evolveTransient: false });

            return {
                emailCollapse: {
                    r2: ec2.sanitizedText,
                    size: vEmailCollapse.tokenToEntry.size,
                    tokens: Array.from(vEmailCollapse.tokenToEntry.keys()),
                    emailCounter: vEmailCollapse.counters.get('EMAIL') || 0,
                    excludedValues: Array.from(vEmailCollapse.excludedValues),
                    preExcludedSize: vPreExcl.excludedValues.size,
                },
                ssnCollapse: {
                    r2: sc2.sanitizedText,
                    size: vSsnCollapse.tokenToEntry.size,
                    tokens: Array.from(vSsnCollapse.tokenToEntry.keys()),
                    ssnCounter: vSsnCollapse.counters.get('SSN') || 0,
                    envCounter: vSsnCollapse.counters.get('ENV_SECRET') || 0,
                },
                multiSpan: {
                    r2: ms2.sanitizedText,
                    size: vMultiSpan.tokenToEntry.size,
                    tokens: Array.from(vMultiSpan.tokenToEntry.keys()),
                    emailCounter: vMultiSpan.counters.get('EMAIL') || 0,
                    rehydrated: (() => {
                        const r = vMultiSpan.rehydrate('A=[EMAIL_1] B=[EMAIL_2]');
                        return r.rehydratedText ?? r.restoredText;
                    })(),
                },
                manual: {
                    r2: man2.sanitizedText,
                    size: vManual.tokenToEntry.size,
                    tokens: Array.from(vManual.tokenToEntry.keys()),
                },
            };
        }"""
    )

    assert vault_res["emailCollapse"] == {
        "r2": "A=alice@example.com\nB=alice@example.com",
        "size": 1,
        "tokens": ["[EMAIL_1]"],
        "emailCounter": 1,
        "excludedValues": ["EMAIL\u0000alice@example.com"],
        "preExcludedSize": 0,
    }
    assert vault_res["ssnCollapse"] == {
        "r2": "KEEP=[SSN_1]\nMY_SECRET=[SSN_1]",
        "size": 1,
        "tokens": ["[SSN_1]"],
        "ssnCounter": 1,
        "envCounter": 0,
    }
    assert vault_res["multiSpan"] == {
        "r2": "A=[EMAIL_1]\nB=[EMAIL_2]",
        "size": 2,
        "tokens": ["[EMAIL_1]", "[EMAIL_2]"],
        "emailCounter": 2,
        "rehydrated": "A=alice@example.com B=alice@example.com.uk",
    }
    assert vault_res["manual"] == {
        "r2": "A=[EMAIL_1]\nB=[EMAIL_1]",
        "size": 2,
        "tokens": ["[EMAIL_1]", "[EMAIL_2]"],
    }


# ---------------------------------------------------------------------------
# 6. M3 Phase 2 Regressions (Live Banner Re-Translation, Manual Clear, WCAG AA Unmasked Row)
# ---------------------------------------------------------------------------


def test_T5_26_live_banner_and_inline_alert_retranslation_on_lang_toggle(
    e2e_session: E2ESession,
) -> None:
    """Status banner, inline alerts (Step 1 & Step 2), and audit drawer entries re-translate live on RU | EN toggle without reload."""
    # Trigger global status banner (presetLoaded with dynamic localized title) + Step 1 inline error banner simultaneously
    e2e_session.ui.select_preset("bilingual_cis_hr")
    bad_file = e2e_session.io.uploads / "unsupported.png"
    bad_file.write_bytes(b"\x89PNG\r\n\x1a\n")
    e2e_session.ui.get_workbench_file_input().set_input_files(str(bad_file))
    e2e_session.page.wait_for_timeout(120)

    status_banner = e2e_session.page.locator("[data-testid='status-banner']")
    input_err = e2e_session.page.locator("#input-error-banner")
    assert status_banner.is_visible()
    assert input_err.is_visible()
    assert "Загружен пример «Письмо и реквизиты»" in status_banner.inner_text()
    assert "Формат «.png» не поддерживается" in input_err.inner_text()

    # Toggle RU -> EN without reload: both banners must re-translate immediately
    e2e_session.ui.switch_language("en")
    assert e2e_session.ui.get_document_lang() == "en"
    assert status_banner.is_visible()
    assert input_err.is_visible()
    assert 'Loaded example "HR & Payout Brief (RU/EN)"' in status_banner.inner_text()
    assert 'Unsupported format ".png"' in input_err.inner_text()

    # Toggle EN -> RU without reload: both banners must revert to Russian
    e2e_session.ui.switch_language("ru")
    assert e2e_session.ui.get_document_lang() == "ru"
    assert status_banner.is_visible()
    assert input_err.is_visible()
    assert "Загружен пример «Письмо и реквизиты»" in status_banner.inner_text()
    assert "Формат «.png» не поддерживается" in input_err.inner_text()

    # Verify Step 2 inline alert (#rehydrate-error-banner) also re-translates live RU -> EN -> RU
    e2e_session.ui.switch_mode("rehydrate")
    e2e_session.page.locator("[data-testid='rehydrate-now-btn']").first.click()
    reh_err = e2e_session.page.locator("#rehydrate-error-banner")
    assert reh_err.is_visible()
    assert "Сначала вставьте ответ нейросети" in reh_err.inner_text()

    e2e_session.ui.switch_language("en")
    assert reh_err.is_visible()
    assert "Paste an AI reply first." in reh_err.inner_text()

    e2e_session.ui.switch_language("ru")
    assert reh_err.is_visible()
    assert "Сначала вставьте ответ нейросети" in reh_err.inner_text()

    # Verify audit drawer action labels and locale-aware timestamps update across RU <-> EN
    audit_ru = e2e_session.ui.get_audit_drawer_text()
    assert "Скрытие данных" in audit_ru
    assert re.search(r"\d{2}\.\d{2}\.\d{4}", audit_ru)
    e2e_session.ui.close_open_drawer()

    e2e_session.ui.switch_language("en")
    audit_en = e2e_session.ui.get_audit_drawer_text()
    assert "Masked" in audit_en
    assert re.search(r"\d{1,2}/\d{1,2}/\d{2}", audit_en)
    e2e_session.ui.close_open_drawer()
    e2e_session.ui.switch_language("ru")


def test_T5_27_manual_clear_with_auto_sanitize_unchecked_resets_preset_and_banners(
    e2e_session: E2ESession,
) -> None:
    """With auto-sanitize unchecked, clicking Clear resets input, output, vault, activePresetId/active pill, and inline/preset banners."""
    e2e_session.ui.set_auto_sanitize(False)
    live_toggle = e2e_session.page.locator("[data-testid='auto-sanitize-toggle']")
    assert not live_toggle.is_checked()

    # Populate input, output, vault, and activePresetId via preset, then add an inline input error banner
    e2e_session.ui.select_preset("client_contract")
    preset_btn = e2e_session.page.locator("[data-testid='preset-btn-client_contract']")
    apply_rules_btn = e2e_session.page.locator("[data-testid='apply-preset-rules-btn']")
    preset_hint = e2e_session.page.locator("#preset-rule-hint")

    assert e2e_session.ui.get_prompt_input().input_value().strip() != ""
    assert "[EMAIL_1]" in e2e_session.ui.get_sanitize_output_text()
    assert len(e2e_session.ui.get_vault_rows()) >= 1
    assert preset_btn.evaluate("el => el.classList.contains('is-active')") is True
    assert preset_btn.get_attribute("aria-pressed") == "true"
    assert apply_rules_btn.is_visible()
    assert preset_hint.is_visible()

    bad_file = e2e_session.io.uploads / "bad_clear.xyz"
    bad_file.write_text("bad", encoding="utf-8")
    e2e_session.ui.get_workbench_file_input().set_input_files(str(bad_file))
    e2e_session.page.wait_for_timeout(120)
    input_err = e2e_session.page.locator("#input-error-banner")
    assert input_err.is_visible()

    # Click Clear while auto-sanitize is still unchecked
    e2e_session.ui.click_clear_input()

    assert e2e_session.ui.get_prompt_input().input_value() == ""
    assert e2e_session.ui.get_sanitize_output_text() == ""
    assert e2e_session.ui.get_vault_rows() == []
    assert e2e_session.page.locator("#vault-empty-state").is_visible()
    assert e2e_session.ui.get_telemetry_masked_count() == 0
    assert e2e_session.page.locator("[data-testid='copy-sanitized-btn']").is_disabled()
    assert e2e_session.page.locator("[data-testid='download-sanitized-btn']").is_disabled()
    assert preset_btn.evaluate("el => el.classList.contains('is-active')") is False
    assert preset_btn.get_attribute("aria-pressed") == "false"
    assert not apply_rules_btn.is_visible()
    assert not preset_hint.is_visible()
    assert not input_err.is_visible()

    # Confirm auto-sanitize remained unchecked and manual sanitize still works cleanly after Clear
    inp = e2e_session.ui.get_prompt_input()
    inp.fill("Manual after clear test@example.com")
    inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    e2e_session.page.wait_for_timeout(200)
    assert e2e_session.ui.get_sanitize_output_text() == ""

    e2e_session.page.locator("[data-testid='sanitize-now-btn']").first.click()
    assert e2e_session.ui.get_sanitize_output_text().strip() == "Manual after clear [EMAIL_1]"


def test_T5_28_vault_unmasked_row_wcag_aa_contrast_opacity_and_strikethrough(
    e2e_session: E2ESession,
) -> None:
    """Unmasked .vault-row.is-unmasked renders with opacity 1, strikethrough value text, and >= 4.5:1 WCAG AA contrast."""
    out = e2e_session.ui.sanitize_text("Email alice@example.com and IP 192.0.2.10")
    assert "[EMAIL_1]" in out and "[IP_1]" in out

    e2e_session.ui.toggle_vault_entity("[EMAIL_1]")
    sanitized_after = e2e_session.ui.get_sanitize_output_text()
    assert "alice@example.com" in sanitized_after
    assert "[IP_1]" in sanitized_after

    def _inspect_unmasked_row() -> dict[str, object]:
        return dict(
            e2e_session.page.evaluate(
                """() => {
                    const parseColor = (str) => {
                        const m = String(str || '').match(/rgba?\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)(?:\\s*,\\s*([\\d.]+))?\\s*\\)/i);
                        if (!m) return null;
                        return {
                            r: Number(m[1]),
                            g: Number(m[2]),
                            b: Number(m[3]),
                            a: m[4] === undefined ? 1 : Number(m[4]),
                        };
                    };
                    const blend = (fg, bg) => {
                        const a = fg.a;
                        return {
                            r: fg.r * a + bg.r * (1 - a),
                            g: fg.g * a + bg.g * (1 - a),
                            b: fg.b * a + bg.b * (1 - a),
                            a: 1,
                        };
                    };
                    const effectiveBg = (el) => {
                        const layers = [];
                        let cur = el;
                        while (cur && cur.nodeType === 1) {
                            const bg = parseColor(window.getComputedStyle(cur).backgroundColor);
                            if (bg && bg.a > 0) layers.push(bg);
                            cur = cur.parentElement;
                        }
                        let acc = { r: 255, g: 255, b: 255, a: 1 };
                        for (let i = layers.length - 1; i >= 0; i -= 1) {
                            acc = blend(layers[i], acc);
                        }
                        return acc;
                    };
                    const luminance = (c) => {
                        const ch = [c.r, c.g, c.b].map((v) => {
                            const s = v / 255;
                            return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
                        });
                        return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
                    };
                    const contrastRatio = (el) => {
                        const fg = parseColor(window.getComputedStyle(el).color);
                        const bg = effectiveBg(el);
                        const fgComp = fg.a < 1 ? blend(fg, bg) : fg;
                        const l1 = luminance(fgComp);
                        const l2 = luminance(bg);
                        return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
                    };

                    const row = document.querySelector("[data-testid='entity-vault-list'] [data-testid='vault-item'][data-token='[EMAIL_1]']");
                    const valEl = row.querySelector("[data-testid='vault-value']");
                    const hitsEl = row.querySelector(".vault-hits-badge");
                    const tagEl = row.querySelector(".vault-category-tag");
                    const switchEl = row.querySelector("[data-testid='vault-item-toggle']");
                    const rowSt = window.getComputedStyle(row);
                    const valSt = window.getComputedStyle(valEl);
                    return {
                        hasUnmaskedClass: row.classList.contains("is-unmasked"),
                        dataEnabled: row.getAttribute("data-enabled"),
                        rowOpacity: Number(rowSt.opacity),
                        valTextDecorationLine: valSt.textDecorationLine || valSt.textDecoration,
                        valueContrast: contrastRatio(valEl),
                        hitsContrast: contrastRatio(hitsEl),
                        tagContrast: contrastRatio(tagEl),
                        switchContrast: contrastRatio(switchEl),
                    };
                }"""
            )
        )

    metrics_shown = _inspect_unmasked_row()
    assert metrics_shown["hasUnmaskedClass"] is True
    assert metrics_shown["dataEnabled"] == "false"
    assert metrics_shown["rowOpacity"] == 1.0
    assert "line-through" in str(metrics_shown["valTextDecorationLine"])
    for key in ("valueContrast", "hitsContrast", "tagContrast", "switchContrast"):
        assert float(metrics_shown[key]) >= 4.5, f"WCAG AA contrast failed for {key}: {metrics_shown}"

    # Also verify obfuscated unmasked state (Hide Values toggled ON) keeps opacity=1, strikethrough, and >= 4.5:1 contrast
    e2e_session.ui.toggle_hide_values()
    metrics_hidden = _inspect_unmasked_row()
    assert metrics_hidden["hasUnmaskedClass"] is True
    assert metrics_hidden["rowOpacity"] == 1.0
    assert "line-through" in str(metrics_hidden["valTextDecorationLine"])
    assert float(metrics_hidden["valueContrast"]) >= 4.5


def test_T5_29_card_suffix_and_hyphen_ssn_edge_cases(
    e2e_session: E2ESession,
) -> None:
    """Continuous/grouped cards with -NN/-NN-MM/-NNNN/-00 suffixes mask only the PAN; hyphen-joined invalid SSNs and 20-digit numbers stay unmasked."""
    # 1. Continuous cards with -NN suffixes (-99, -08)
    out_cont_suffix = e2e_session.ui.sanitize_text(
        "Visa 4111111111111111-99 Amex 378282246310005-99 Alt 4111111111111111-08"
    )
    assert out_cont_suffix.strip() == "Visa [CARD_1]-99 Amex [CARD_2]-99 Alt [CARD_1]-08"
    assert "4111111111111111" not in out_cont_suffix
    assert "378282246310005" not in out_cont_suffix
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 3
    assert len(e2e_session.ui.get_vault_rows()) == 2

    e2e_session.ui.click_clear_input()

    # 2. Spaced, hyphenated, and continuous cards followed by -12-34 or -9999
    out_multi_suffix = e2e_session.ui.sanitize_text(
        "A 4111 1111 1111 1111-12-34 | "
        "B 4111-1111-1111-1111-12-34 | "
        "C 4111111111111111-12-34 | "
        "D 4111-1111-1111-1111-9999"
    )
    assert out_multi_suffix.strip() == (
        "A [CARD_1]-12-34 | B [CARD_2]-12-34 | C [CARD_3]-12-34 | D [CARD_2]-9999"
    )
    assert "4111 1111 1111 1111" not in out_multi_suffix
    assert "4111-1111-1111-1111" not in out_multi_suffix
    assert "4111111111111111" not in out_multi_suffix
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 4
    assert len(e2e_session.ui.get_vault_rows()) == 3

    e2e_session.ui.click_clear_input()

    # 3. Luhn-collision -00 / -18 suffixes must NOT be absorbed into 18-digit card spans
    out_luhn_collision = e2e_session.ui.sanitize_text(
        "H 4111-1111-1111-1111-00 C 4111111111111111-00 S 4111-1111-1111-1111-18"
    )
    assert out_luhn_collision.strip() == "H [CARD_1]-00 C [CARD_2]-00 S [CARD_1]-18"
    assert "4111-1111-1111-1111" not in out_luhn_collision
    assert "4111111111111111" not in out_luhn_collision
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 3
    assert len(e2e_session.ui.get_vault_rows()) == 2

    e2e_session.ui.click_clear_input()

    # 4. Hyphen-joined adjacent invalid SSNs and 20-digit continuous non-cards stay unmasked;
    #    valid card + SSN still detect cleanly side by side.
    out_mixed = e2e_session.ui.sanitize_text(
        "BadSSN 900-45-6789-123-00-6789 "
        "Long20 41111111111111110000 "
        "Zeros 0000 0000 0000 0000 "
        "Dates 2026-11-19-2026-11-20 "
        "Valid 4111-1111-1111-1111 123-45-6789"
    )
    assert "900-45-6789-123-00-6789" in out_mixed
    assert "41111111111111110000" in out_mixed
    assert "0000 0000 0000 0000" in out_mixed
    assert "2026-11-19-2026-11-20" in out_mixed
    assert "Valid [CARD_1] [SSN_1]" in out_mixed
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 1
    assert e2e_session.ui.get_category_chip_count("SSN") == 1

    restored = e2e_session.ui.rehydrate_text(out_mixed)
    assert "Valid 4111-1111-1111-1111 123-45-6789" in restored
    assert "900-45-6789-123-00-6789" in restored
    assert "41111111111111110000" in restored

    e2e_session.ui.switch_mode("sanitize")
    e2e_session.ui.click_clear_input()

    # 5. Valid Luhn 17- and 18-digit PANs with -N / -NN hyphen suffixes mask only the PAN and preserve -99 / -9
    out_long_pan_suffix = e2e_session.ui.sanitize_text(
        "C17 40000000000000006-99 | "
        "H17 4000-0000-0000-00006-99 | "
        "S17 4000 0000 0000 00006-99 | "
        "C18 400000000000000002-9 | "
        "H18 4000-0000-0000-000002-9"
    )
    assert out_long_pan_suffix.strip() == (
        "C17 [CARD_1]-99 | H17 [CARD_2]-99 | S17 [CARD_3]-99 | C18 [CARD_4]-9 | H18 [CARD_5]-9"
    )
    for leaked in (
        "40000000000000006",
        "4000-0000-0000-00006",
        "4000 0000 0000 00006",
        "400000000000000002",
        "4000-0000-0000-000002",
    ):
        assert leaked not in out_long_pan_suffix
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 5
    assert len(e2e_session.ui.get_vault_rows()) == 5
    restored_long_pan = e2e_session.ui.rehydrate_text(out_long_pan_suffix)
    assert "C17 40000000000000006-99" in restored_long_pan
    assert "H17 4000-0000-0000-00006-99" in restored_long_pan
    assert "S17 4000 0000 0000 00006-99" in restored_long_pan
    assert "C18 400000000000000002-9" in restored_long_pan
    assert "H18 4000-0000-0000-000002-9" in restored_long_pan

    e2e_session.ui.switch_mode("sanitize")
    e2e_session.ui.click_clear_input()

    # 6. Genuine 19-digit 4-4-4-4-3 PAN (non-Luhn 16-digit prefix) is masked in full
    out_pan19 = e2e_session.ui.sanitize_text("PAN19 4000-0000-0000-0000-006")
    assert out_pan19.strip() == "PAN19 [CARD_1]"
    assert "4000-0000-0000-0000-006" not in out_pan19
    assert e2e_session.ui.get_category_chip_count("CREDIT_CARD") == 1
    assert e2e_session.ui.rehydrate_text(out_pan19).strip() == "PAN19 4000-0000-0000-0000-006"


def test_T5_30_stage_a_detectors_org_possible_card_uuid_city_and_audit_ram_default(
    e2e_session: E2ESession,
) -> None:
    """Stage A adversarial: RU_ORG variants, POSSIBLE_CARD vs bare/valid PAN, RU_ADDRESS city, UUID toggle, RAM-only audit."""
    ui = e2e_session.ui
    page = e2e_session.page

    payload = (
        "Организации: ООО «Вектор», АО «ТехноСфера», ПАО «ТестБанк», ЗАО \"Альфа\", НКО \"Фонд\", ИП Иванов И.И.\n"
        "Карты: карта 4276 3800 1234 5678, №карты 4111-2222-3333-4444, голый 4276 3800 1234 5678, валид 4111 1111 1111 1111.\n"
        "Адрес: живу Москва, ул. Ленина, д. 5 и г. Казань, пр. Победы, д. 10.\n"
        "UUID: 550e8400-e29b-41d4-a716-446655440000."
    )
    masked = ui.sanitize_text(payload)
    for tok in ("[ORG_1]", "[ORG_2]", "[ORG_3]", "[POSSIBLE_CARD_1]", "[POSSIBLE_CARD_2]", "[CARD_1]", "[ADDRESS_1]", "[ADDRESS_2]"):
        assert tok in masked, f"Expected {tok} in {masked!r}"
    assert "голый 4276 3800 1234 5678" in masked
    assert "Москва" not in masked and "г. Казань" not in masked
    assert "550e8400-e29b-41d4-a716-446655440000" in masked

    ui.set_detect_uuid(True)
    masked_uuid = ui.get_sanitize_output_text()
    assert "[UUID_1]" in masked_uuid
    assert "550e8400-e29b-41d4-a716-446655440000" not in masked_uuid
    assert ui.rehydrate_text(masked_uuid).strip() == payload.strip()

    # RAM-only audit default vs opt-in persistence + uncheck cleanup + Proof unknownKeys == 0
    assert page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None
    assert len(ui.get_audit_hashes()) >= 1
    ui.set_audit_persistence(True)
    assert page.evaluate("() => Boolean(localStorage.getItem('promptveil_audit_v1'))")
    ui.close_open_drawer()

    modal = ui.open_privacy_proof_modal("header")
    assert "неизвестные ключи: 0" in modal.inner_text()
    ui.close_active_modal()

    ui.set_audit_persistence(False)
    assert page.evaluate("() => localStorage.getItem('promptveil_audit_v1')") is None
    ui.close_open_drawer()


def test_T5_31_stage_b_counter_sync_rulebook_validation_and_copy_timer_clear(
    e2e_session: E2ESession,
) -> None:
    """Stage B adversarial: metric/chip/badge counter lockstep, novalidate Rulebook alert clearing, copy-timer cancellation."""
    page = e2e_session.page
    ui = e2e_session.ui

    ui.add_custom_rule("СекретноеСлово")
    ui.close_open_drawer()
    ui.sanitize_text("a@example.com a@example.com 192.0.2.1 СекретноеСлово")

    def _counters() -> tuple[int, int, int]:
        m = ui.get_telemetry_masked_count()
        a = int(page.locator("[data-testid='category-chips'] [data-category='ALL']").get_attribute("data-count") or "0")
        b_txt = page.locator("#rehydrate-ready-badge").inner_text()
        b = int(re.findall(r"\d+", b_txt)[0])
        return m, a, b

    assert _counters() == (4, 4, 4)
    ui.toggle_category_chip("EMAIL")
    assert _counters() == (2, 2, 2)
    ui.toggle_vault_entity("СекретноеСлово")
    assert _counters() == (1, 1, 1)
    ui.toggle_category_chip("EMAIL")
    assert _counters() == (3, 3, 3)

    # Copy timer cancellation on Clear & Reset to 0
    copy_btn = page.locator("[data-testid='copy-sanitized-btn']").first
    ui.click_copy_output()
    assert copy_btn.get_attribute("data-copied") == "true"
    ui.click_clear_input()
    assert copy_btn.get_attribute("data-copied") is None
    assert copy_btn.is_disabled()

    ui.sanitize_text("b@example.com")
    ui.click_copy_output()
    assert copy_btn.get_attribute("data-copied") == "true"
    ui.click_reset_session_to_zero("workbench")
    assert copy_btn.get_attribute("data-copied") is None
    assert copy_btn.is_disabled()

    # Rulebook novalidate + focus + clearing stale duplicate alert
    drawer = ui.open_rulebook_drawer()
    assert drawer.locator("#add-rule-form").get_attribute("novalidate") is not None
    drawer.locator("[data-testid='add-rule-btn']").click()
    assert drawer.locator("#rulebook-alert").is_visible()
    assert page.evaluate(
        "() => document.activeElement === document.querySelector(\"[data-testid='rule-term-input']\")"
    ) is True
    ui.add_custom_rule("СекретноеСлово")
    assert drawer.locator("#rulebook-alert").is_visible()
    drawer.locator("[data-testid='rule-term-input']").fill("НовоеСлово")
    drawer.locator("[data-testid='rule-term-input']").evaluate(
        "el => el.dispatchEvent(new Event('input', { bubbles: true }))"
    )
    assert not drawer.locator("#rulebook-alert").is_visible()


def test_T5_32_stage_d_headers_template_modals_and_sw_update_banner(
    raw_session: E2ESession,
    playwright_browser: Browser,
) -> None:
    """Stage D adversarial: COOP/CORP headers, /dist/* assets, <template> modal hydration, and SW update banner."""
    base_url = raw_session.base_url
    page = raw_session.page
    ui = raw_session.ui

    for route in ("/", "/en/"):
        verify_csp_and_security_headers(f"{base_url}{route}")
        st, hdrs, _ = fetch_http_response(f"{base_url}{route}")
        assert st == 200
        assert hdrs.get("cross-origin-opener-policy", "").lower() == "same-origin"
        assert hdrs.get("cross-origin-resource-policy", "").lower() == "same-origin"

    page.goto(f"{base_url}/", wait_until="networkidle")
    raw_session.net.assert_clean_load()

    # Verify /dist/* bundles loaded with 200 (and immutable cache on static-only)
    dist_hrefs = page.evaluate(
        """() => Array.from(document.querySelectorAll('link[href*="/dist/"], script[src*="/dist/"]'))
            .map(el => el.getAttribute('href') || el.getAttribute('src'))
            .filter(Boolean)"""
    )
    assert len(dist_hrefs) >= 1, "Expected /dist/* bundled assets referenced in index.html"
    for href in dist_hrefs:
        st, _, _ = fetch_http_response(f"{base_url}{href}")
        assert st == 200, f"Bundled asset {href} returned {st}"

    # Verify <template> modal hydration, reopen, and RU/EN translation
    assert page.locator("template").count() >= 4
    for opener in (
        lambda: ui.open_privacy_proof_modal("header"),
        lambda: ui.open_plan_request_modal("pro"),
        ui.open_privacy_policy_modal,
        ui.open_terms_modal,
    ):
        modal = opener()
        assert modal.is_visible()
        ui.close_active_modal()
        assert not modal.is_visible()

    ui.switch_language("en")
    en_modal = ui.open_privacy_proof_modal("header")
    assert "CSP violations in app document: 0" in en_modal.inner_text()
    ui.close_active_modal()
    ui.switch_language("ru")

    # Service Worker registration + update banner
    sw_ready = page.evaluate(
        """async () => {
            if (!('serviceWorker' in navigator)) return false;
            const reg = await navigator.serviceWorker.ready;
            return Boolean(reg && reg.active);
        }"""
    )
    assert sw_ready is True

    # Part B: Simulate an incoming updated Service Worker script on an isolated static origin
    # (Chromium's ServiceWorkerRegistration.update() bypasses page.context.route("**/sw.js"))
    orig_sw = (STATIC_APP_DIR / "sw.js").read_text(encoding="utf-8")
    updated_sw = (
        orig_sw.replace('const CACHE_NAME = "promptveil-build-', 'const CACHE_NAME = "promptveil-build-e2e-v2-', 1)
        + "\n// e2e-sw-update-probe\n"
    )
    sw_state: dict[str, str] = {"body": orig_sw}

    with start_static_dir_server(
        STATIC_APP_DIR,
        sw_body_provider=lambda: sw_state["body"],
    ) as sw_url:
        sw_ctx = playwright_browser.new_context(viewport={"width": 1440, "height": 900})
        sw_page = sw_ctx.new_page()
        sw_net = NetworkMonitor(page=sw_page)
        sw_console = ConsoleErrorMonitor(page=sw_page)
        sw_net.attach()
        sw_console.attach()
        sw_ui = PromptVeilUI(sw_page)
        try:
            sw_page.goto(f"{sw_url}/", wait_until="networkidle")
            sw_net.assert_clean_load()
            sw_console.assert_no_errors()

            v1_activated = sw_page.evaluate(
                """async () => {
                    const reg = await navigator.serviceWorker.ready;
                    if (!reg || !reg.active) return false;
                    if (reg.active.state === 'activated') return true;
                    await new Promise((resolve) => {
                        const sw = reg.active;
                        if (sw.state === 'activated') return resolve();
                        sw.addEventListener('statechange', () => {
                            if (sw.state === 'activated') resolve();
                        });
                    });
                    return reg.active.state === 'activated';
                }"""
            )
            assert v1_activated is True

            sw_state["body"] = updated_sw
            sw_status, sw_hdrs, sw_body = fetch_http_response(f"{sw_url}/sw.js")
            assert sw_status == 200
            assert sw_hdrs.get("cache-control", "").lower() == "no-cache"
            assert "// e2e-sw-update-probe" in sw_body

            sw_page.evaluate(
                "async () => { const r = await navigator.serviceWorker.getRegistration(); if (r) await r.update(); }"
            )
            sw_page.locator("[data-testid='sw-update-banner'], #sw-update-banner").first.wait_for(
                state="visible", timeout=5000
            )
            banner = sw_ui.get_sw_update_banner()
            assert banner.is_visible()
            verify_russian_purity(sw_page)

            sw_page.evaluate("() => { window.__pvBeforeSwReload = true; }")
            sw_ui.click_sw_update()
            sw_page.wait_for_function("() => window.__pvBeforeSwReload === undefined", timeout=5000)
            sw_page.wait_for_load_state("networkidle")

            assert not sw_page.locator("[data-testid='sw-update-banner'], #sw-update-banner").first.is_visible()
            sw_after = sw_page.evaluate(
                """async () => {
                    const r = await navigator.serviceWorker.getRegistration();
                    return Boolean(r && r.active && !r.waiting && navigator.serviceWorker.controller);
                }"""
            )
            assert sw_after is True
            sw_net.assert_clean_load()
            sw_console.assert_no_errors()
        finally:
            sw_net.detach()
            sw_console.detach()
            sw_ctx.close()

    raw_session.console.assert_no_errors()


def test_T5_33_r1_launchers_whitespace_keyboard_enter_and_en_clipboard_error(
    e2e_session: E2ESession,
) -> None:
    """R1 adversarial: whitespace-only input stays unready without copying; keyboard Enter on Gemini flushes on Step 2; EN clipboard alert."""
    page = e2e_session.page
    ui = e2e_session.ui

    ui.get_prompt_input().fill("   \n\t  ")
    ui.get_prompt_input().evaluate(
        "el => el.dispatchEvent(new Event('input', { bubbles: true }))"
    )
    page.wait_for_timeout(180)
    assert ui.is_ai_launchers_ready() is False

    page.evaluate("async () => navigator.clipboard.writeText('SENTINEL_WS')")
    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            ui.click_ai_launcher("gemini")
        pop_info.value.close()
        assert ui.read_clipboard_text() == "SENTINEL_WS"
        assert not page.locator("[data-testid='status-banner']").is_visible()
    finally:
        page.context.unroute("https://gemini.google.com/**")

    # Custom rule + debounced input + Step 2 + keyboard Enter on Gemini pill
    ui.add_custom_rule("ProjectOrion")
    ui.close_open_drawer()
    ui.get_prompt_input().fill("Secret ProjectOrion lead r1.adv@example.com")
    ui.switch_mode("rehydrate")
    assert ui.is_ai_launchers_ready() is True

    gemini_pill = ui.get_ai_launcher("gemini")
    page.context.route("https://gemini.google.com/**", lambda r: r.abort())
    try:
        with page.expect_popup(timeout=3000) as pop_info:
            gemini_pill.focus()
            page.keyboard.press("Enter")
        pop_info.value.close()
        copied = ui.read_clipboard_text() or ""
        assert copied == "Secret [CUSTOM_1] lead [EMAIL_1]"
        assert "ProjectOrion" not in copied and "r1.adv@example.com" not in copied
    finally:
        page.context.unroute("https://gemini.google.com/**")

    # EN mode clipboard denied -> English role='alert' banner
    ui.switch_language("en")
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
        alert_el = page.locator("[data-testid='status-banner'][role='alert']")
        alert_el.wait_for(state="visible", timeout=3000)
        assert "Clipboard access restricted" in alert_el.inner_text()
    finally:
        page.context.unroute("https://gemini.google.com/**")

    e2e_session.net.assert_zero_egress(["ProjectOrion", "r1.adv@example.com"])
    e2e_session.console.assert_no_errors()


def test_T5_34_r2_pro_license_schema_padding_identity_purejs_and_modal_a11y(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R2 adversarial: expired storage purge, pure-JS identity/small-subgroup key rejection, invalid-schema/padded PV1 tokens, wrapped key, and Pro modal focus trap."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    page.goto(f"{pro_raw_session.base_url}/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()

    # 1. Expired validly-signed token pre-seeded in localStorage must purge on reload
    expired_tok = ephemeral_pro_keys.issue_token(
        tier="pro", key_id="PV-T5-EXP", exp="2020-01-01T00:00:00.000Z"
    )
    page.evaluate("t => localStorage.setItem('promptveil_pro_license_v1', t)", expired_tok)
    page.reload(wait_until="networkidle")
    assert ui.get_pro_badge_text() == "Free"
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    # 2. Pure-JS Ed25519 parity (pre-interactive): identity, order-2, and order-4 public keys with (R=identity, S=0) must be rejected
    pure_check = page.evaluate(
        """async () => {
            const { verifyEd25519PureJs } = await import('/js/pro-license.js');
            const idPub = new Uint8Array(32);
            idPub[0] = 0x01;
            const order2Pub = new Uint8Array(32).fill(0xff);
            order2Pub[0] = 0xec;
            order2Pub[31] = 0x7f;
            const order4Pub = new Uint8Array(32);
            const forgedSig = new Uint8Array(64);
            forgedSig[0] = 0x01;
            const msg = new TextEncoder().encode('m4-3');
            return {
                idAccepted: verifyEd25519PureJs(msg, forgedSig, idPub),
                order2Accepted: verifyEd25519PureJs(msg, forgedSig, order2Pub),
                order4Accepted: verifyEd25519PureJs(msg, forgedSig, order4Pub),
            };
        }"""
    )
    assert pure_check == {
        "idAccepted": False,
        "order2Accepted": False,
        "order4Accepted": False,
    }

    pro_raw_session.net.start_interactive_phase()

    # 3. Signed-but-invalid-schema tokens + padded base64url rejected cleanly
    bad_schema_tokens = [
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 1, "tier": "admin", "keyId": "PV-ADM", "label": "Admin", "issuedAt": "2026-11-21T00:00:00Z"}
        ),
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 2, "tier": "pro", "keyId": "PV-V2", "label": "V2", "issuedAt": "2026-11-21T00:00:00Z"}
        ),
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 1, "tier": "pro", "keyId": "PV-EXP0", "label": "Exp0", "issuedAt": "2026-11-21T00:00:00Z", "exp": 0}
        ),
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 1, "tier": "pro", "keyId": "   ", "label": "BlankId", "issuedAt": "2026-11-21T00:00:00Z"}
        ),
        ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-PAD") + "=",
    ]
    ui.open_pro_license_modal("header")
    for tok in bad_schema_tokens:
        ui.activate_pro_key(tok)
        assert page.locator("#pro-license-alert").is_visible()
        assert ui.get_pro_badge_text() == "Free"
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    # 4. Whitespace/newline-wrapped valid key succeeds + modal focus trap & Escape restoration
    wrapped_tok = "  \n  " + ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-WRAP") + "\r\n  "
    ui.activate_pro_key(wrapped_tok)
    assert ui.get_pro_badge_text() == "Pro Активен"

    pro_btn = page.locator("[data-testid='open-pro-license-btn']").first
    assert pro_btn.get_attribute("aria-expanded") == "true"
    page.keyboard.press("Shift+Tab")
    assert page.evaluate("() => Boolean(document.activeElement?.closest('#modal-pro-license'))")
    for _ in range(10):
        page.keyboard.press("Tab")
        assert page.evaluate("() => Boolean(document.activeElement?.closest('#modal-pro-license'))")
    page.keyboard.press("Escape")
    page.wait_for_timeout(120)
    assert pro_btn.get_attribute("aria-expanded") == "false"
    assert page.evaluate("() => document.activeElement?.id") == "open-pro-license-btn"

    # 5. "Get a key" button transitions cleanly to #modal-plan-request and Escape closes backdrop
    ui.open_pro_license_modal("header")
    page.locator("[data-testid='pro-license-get-key-btn']").click()
    page.wait_for_timeout(120)
    assert not page.locator("#modal-pro-license").is_visible()
    assert page.locator("#modal-plan-request").is_visible()
    page.keyboard.press("Escape")
    page.wait_for_timeout(120)
    assert not page.locator("#drawer-backdrop").is_visible()

    pro_raw_session.net.assert_zero_egress([wrapped_tok.strip()])
    pro_raw_session.console.assert_no_errors()


def test_T5_35_r3_pro_deactivation_batch_isolation_xlsx_rels_pdf_cmap_zip_bomb_and_dtd_xml(
    pro_e2e_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R3 adversarial: Pro deactivation clears residual batchItems, 1-byte ToUnicode without codespacerange, ../xl/ XLSX rels, Billion Laughs XML, and corrupt FlateDecode."""
    page = pro_e2e_session.page
    ui = pro_e2e_session.ui

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-R3"))
    ui.close_active_modal()

    # 1. Pro deactivation mid-batch must clear batchItems so keyboard clear resets vault & re-activation does not resurrect
    batch_docx = make_synthetic_docx(
        pro_e2e_session.io.uploads / "deact_secret.docx",
        paragraphs=["Confidential deact.secret@example.com"],
    )
    ui.upload_files([batch_docx])
    assert len(ui.get_batch_queue_items()) == 1

    ui.open_pro_license_modal("header")
    ui.remove_pro_key()
    ui.close_active_modal()

    inp = ui.get_prompt_input()
    inp.fill("")
    inp.evaluate("el => el.dispatchEvent(new Event('input', { bubbles: true }))")
    page.wait_for_timeout(200)
    out_after = ui.sanitize_text("Fresh free.only@example.org")
    assert out_after.strip() == "Fresh [EMAIL_1]"
    assert ui.rehydrate_text("[EMAIL_1]").strip() == "free.only@example.org"

    ui.switch_mode("sanitize")
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-R3-RE"))
    ui.close_active_modal()
    assert not page.locator("#batch-queue-panel").is_visible()
    assert ui.get_batch_queue_items() == []

    # 2. PDF with 1-byte ToUnicode CMap omitting begincodespacerange + indirect /Length + ' operator
    cmap_1b = (
        "/CIDInit /ProcSet findresource begin\n"
        "begincmap\n"
        "2 beginbfchar\n"
        "<01> <0061>\n"
        "<02> <0040>\n"
        "endbfchar\n"
        "1 beginbfrange\n"
        "<10> <12> <0078>\n"
        "endbfrange\n"
        "endcmap\n"
    ).encode("ascii")
    cmap_comp = zlib.compress(cmap_1b)
    stream_comp = zlib.compress(
        b"BT\n/F1 12 Tf\n<0102101112> Tj\n(extra.pdf@example.com)'\nET\n"
    )
    pdf_1b = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 6 0 R >>\nendobj\n"
        b"5 0 obj\n<< /Filter /FlateDecode /Length 7 0 R >>\nstream\n" + stream_comp + b"\nendstream\nendobj\n"
        b"6 0 obj\n<< /Filter /FlateDecode /Length " + str(len(cmap_comp)).encode("ascii") + b" >>\nstream\n" + cmap_comp + b"\nendstream\nendobj\n"
        b"7 0 obj\n" + str(len(stream_comp)).encode("ascii") + b"\nendobj\n%%EOF\n"
    )
    pdf_1b_path = pro_e2e_session.io.uploads / "cmap_1byte.pdf"
    pdf_1b_path.write_bytes(pdf_1b)
    ui.upload_files([pdf_1b_path])
    raw_pdf = ui.get_prompt_input().input_value()
    assert "a@xyz" in raw_pdf
    assert "extra.pdf@example.com" in raw_pdf
    assert "[EMAIL_1]" in ui.get_sanitize_output_text()

    # 3. XLSX with custom worksheet filename, Target="../xl/worksheets/custom.xml", and missing sharedStrings.xml
    xlsx_custom = pro_e2e_session.io.uploads / "custom_rels.xlsx"
    with zipfile.ZipFile(xlsx_custom, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "xl/workbook.xml",
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Custom" sheetId="1" r:id="rId1"/></sheets></workbook>',
        )
        zf.writestr(
            "xl/_rels/workbook.xml.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Target="../xl/worksheets/custom.xml"/></Relationships>',
        )
        zf.writestr(
            "xl/worksheets/custom.xml",
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>rels.ok@example.com</t></is></c></row></sheetData></worksheet>',
        )
    ui.upload_files([xlsx_custom])
    assert "rels.ok@example.com" in ui.get_prompt_input().input_value()
    assert "[EMAIL_1]" in ui.get_sanitize_output_text()

    # 4. Billion Laughs XML inside .docx is rejected safely by browser DOMParser with zero hang/crash
    bl_docx = pro_e2e_session.io.uploads / "billion_laughs.docx"
    bl_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE lolz ['
        ' <!ENTITY lol "lol">'
        ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        ' <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
        ' <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        ' <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
        ' <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'
        ']>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>&lol5;</w:t></w:r></w:p></w:body></w:document>'
    )
    with zipfile.ZipFile(bl_docx, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", bl_xml)
    ui.upload_files([bl_docx])
    assert ui.get_visible_error_notice()

    # 5. Corrupted FlateDecode PDF is rejected cleanly
    corrupt_flate_pdf = pro_e2e_session.io.uploads / "bad_flate.pdf"
    corrupt_flate_pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Filter /FlateDecode /Length 8 >>\nstream\nBADFLATE\nendstream\nendobj\n%%EOF\n"
    )
    ui.upload_files([corrupt_flate_pdf])
    assert ui.get_visible_error_notice()

    pro_e2e_session.net.assert_zero_egress(
        ["deact.secret@example.com", "extra.pdf@example.com", "rels.ok@example.com"]
    )
    pro_e2e_session.console.assert_no_errors()


def test_T5_36_token_shape_with_digits_ipv4_rehydrate_env_and_strict_entropy(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """Candidate #1 (F-01): Digit-bearing prefixes ([IPV4_1], [SHA256_1]) and long bracketed tokens in normal/strict mode."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui

    page.goto(f"{pro_raw_session.base_url}/en/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    # 1. Digit-bearing token [IPV4_1] in ENV assignment must NOT be double-masked as [ENV_SECRET_1],
    # and long bracketed tokens [POSSIBLE_CARD_1234567] / [IPV4_ADDRESS_0123456789] must NOT re-mask as [SECRET_1].
    probe_text = (
        "AUTH_HOST=[IPV4_1]\n"
        "KEEP_LONG=[POSSIBLE_CARD_1234567]\n"
        "STRICT_TOK=[IPV4_ADDRESS_0123456789]"
    )
    ui.sanitize_text(probe_text)
    normal_out = ui.get_sanitize_output_text()
    assert "[IPV4_1]" in normal_out
    assert "[ENV_SECRET_" not in normal_out
    assert "[POSSIBLE_CARD_1234567]" in normal_out
    assert "[SECRET_" not in normal_out

    ui.set_sensitivity_mode("strict")
    strict_out = ui.get_sanitize_output_text()
    assert "[IPV4_ADDRESS_0123456789]" in strict_out
    assert "[SECRET_" not in strict_out

    # 2. Rehydrating a reply containing unresolved [IPV4_1] and [SHA256_1] must surface unresolved warning instead of silent no-op.
    ui.switch_mode("rehydrate")
    ui.rehydrate_text("Host [IPV4_1] digest [SHA256_1] unreachable")
    unresolved = ui.get_unresolved_tokens()
    assert "[IPV4_1]" in unresolved
    assert "[SHA256_1]" in unresolved

    # 3. Verify Pro code_security_review template uses canonical [IP_1] and surfaces unresolved tokens on rehydrate.
    ui.switch_mode("sanitize")
    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-36", label="T5 36"))
    ui.close_active_modal()
    ui.click_prompt_template("code_security_review")
    tpl_out = ui.get_sanitize_output_text()
    assert "[IP_1]" in tpl_out
    ui.switch_mode("rehydrate")
    ui.rehydrate_text(tpl_out)
    assert "[IP_1]" in ui.get_unresolved_tokens()

    pro_raw_session.net.assert_zero_egress()
    pro_raw_session.console.assert_no_errors()


def test_T5_37_rulebook_pro_pack_alert_and_banner_retranslate_on_lang_toggle(
    e2e_session: E2ESession,
) -> None:
    """F-02: Rulebook Pro pack upgrade banner and inline alert must retranslate pack title on RU <-> EN toggle."""
    page = e2e_session.page
    ui = e2e_session.ui
    e2e_session.net.start_interactive_phase()

    ui.apply_industry_word_pack("banking_fintech")
    drawer = page.locator("#drawer-rulebook")
    banner = drawer.locator("#rulebook-pro-upgrade-banner, [data-testid='rulebook-pro-upgrade-banner']").first
    alert = drawer.locator("#rulebook-alert, [data-testid='rulebook-alert']").first
    assert banner.is_visible()
    assert alert.is_visible()
    assert "Банки и финтех" in banner.inner_text()
    assert "Банки и финтех" in alert.inner_text()

    page.evaluate("() => document.getElementById('lang-en-btn')?.click()")
    page.wait_for_function("() => document.documentElement.lang === 'en'", timeout=3000)
    en_banner_text = banner.inner_text()
    en_alert_text = alert.inner_text()
    assert "Banking & FinTech" in en_banner_text
    assert "Banking & FinTech" in en_alert_text
    assert "Банки и финтех" not in en_banner_text
    assert "Банки и финтех" not in en_alert_text
    ui.close_open_drawer()

    e2e_session.net.assert_zero_egress()
    e2e_session.console.assert_no_errors()


def test_T5_38_profiles_json_prototype_pollution_xss_and_tampered_free_storage(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R5 Adversarial: Prototype pollution & XSS payloads in rule JSON import / profile names + Free storage tamper."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    page.goto(f"{pro_raw_session.base_url}/en/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-38", label="T5 38"))
    ui.close_active_modal()

    xss_name = "<img src=x onerror=alert(1)>"
    ui.create_rulebook_profile(xss_name)
    assert xss_name in ui.get_rulebook_profile_options()

    evil_json_path = pro_raw_session.io.uploads / "evil_rules.json"
    evil_json_path.write_text(
        json.dumps(
            {
                "__proto__": {"pvPolluted": True},
                "rules": [
                    {
                        "term": "AlphaSecretTerm",
                        "category": "<script>alert(1)</script>",
                        "caseSensitive": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    drawer = ui.open_rulebook_drawer()
    assert drawer.locator("input[type='file']").count() == 1
    drawer.locator("#import-rules-input").set_input_files(str(evil_json_path))
    page.wait_for_timeout(150)

    assert page.evaluate("() => ({}).pvPolluted === undefined") is True
    assert dialogs == []
    ui.close_open_drawer()

    ui.sanitize_text("Contact AlphaSecretTerm now")
    assert "AlphaSecretTerm" not in ui.get_sanitize_output_text()
    pro_raw_session.net.assert_zero_egress(["AlphaSecretTerm"])

    # Remove Pro key + tamper localStorage with forged token; reload must enforce Free default.
    ui.open_pro_license_modal("header")
    ui.remove_pro_key()
    ui.close_active_modal()
    page.evaluate("() => localStorage.setItem('promptveil_pro_license_v1', 'PV1.forged.sig')")
    page.reload(wait_until="networkidle")
    assert ui.get_pro_badge_text().lower() in ("free", "бесплатно")
    drawer = ui.open_rulebook_drawer()
    opts = ui.get_rulebook_profile_options()
    assert len(opts) == 1
    assert xss_name not in opts
    assert drawer.locator("#profiles-tier-badge").is_visible()
    drawer.locator("#profile-name-input").fill("FreeBlocked")
    drawer.locator("#profile-create-btn").click()
    page.wait_for_timeout(120)
    assert drawer.locator("#rulebook-pro-upgrade-banner").is_visible()
    assert len(ui.get_rulebook_profile_options()) == 1
    assert dialogs == []
    pro_raw_session.console.assert_no_errors()


def test_T5_39_extension_zip_headers_download_isolation_and_privacy_proof_after_pro(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
    request: pytest.FixtureRequest,
) -> None:
    """R4 + R6: Extension .zip MIME/Cache-Control/CORP headers, Free gating, CRC32 integrity, and Privacy Proof allowlist."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    is_static_only = bool(request.config.getoption("--static-only"))

    status, headers, _ = fetch_http_response(
        f"{pro_raw_session.base_url}/downloads/promptveil-pro-extension.zip"
    )
    assert status == 200
    assert headers.get("content-type", "").split(";")[0].strip().lower() == "application/zip"
    if not is_static_only:
        assert "max-age=300" in headers.get("cache-control", "").lower()
        assert headers.get("x-content-type-options", "").lower() == "nosniff"
        assert headers.get("cross-origin-resource-policy", "").lower() == "same-origin"

    page.goto(f"{pro_raw_session.base_url}/en/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    # Free mode must hide #open-pro-downloads-btn
    assert not page.locator("#open-pro-downloads-btn").is_visible()

    ui.activate_pro_key(ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-39", label="T5 39"))
    ui.close_active_modal()
    zip_path = ui.download_extension_zip(pro_raw_session.io.downloads)
    assert zip_path.exists() and zip_path.stat().st_size > 1000
    with zipfile.ZipFile(zip_path, "r") as zf:
        assert zf.testzip() is None
        names = zf.namelist()
        assert names == sorted(names)
        assert not any(n.startswith(("src/", "tests/")) for n in names)

    ui.create_rulebook_profile("ProofCheckProfile")
    ui.close_open_drawer()
    proof_modal = ui.open_privacy_proof_modal("header")
    proof_text = proof_modal.inner_text()
    assert "CSP violations in app document: 0" in proof_text
    assert "unknown keys: 0" in proof_text
    assert "0 bytes" in proof_text
    assert "Verified: 0 retention and 0 text egress" in proof_text

    pro_raw_session.net.assert_zero_egress()
    pro_raw_session.console.assert_no_errors()


