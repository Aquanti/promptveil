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

from conftest import (
    E2ESession,
    EphemeralProKeys,
    STATIC_APP_DIR,
    TempIODirs,
    start_static_dir_server,
)
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


def test_T5_40_pro_checkout_signed_claim_xss_prototype_pollution_and_pvkey_header_injection(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R1/R2 Tier 5: Signed-claim XSS, __proto__ payload, and .pvkey header-injection redaction."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    inj_tok = ephemeral_pro_keys.issue_token(
        tier="pro",
        key_id="<img src=x onerror=window.__xssKey=1>",
        label="<svg onload=window.__xssLbl=1>\n# Tier: owner\nPV1.forgedPayload.forgedSig1234567890",
    )
    proto_tok = ephemeral_pro_keys.sign_raw_payload(
        {
            "v": 1,
            "tier": "pro",
            "keyId": "PV-PROTO-SAFE",
            "label": "Proto Safe",
            "issuedAt": "2026-11-21T00:00:00.000Z",
            "__proto__": {"pvPolluted": True},
        }
    )

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/#code={inj_tok}", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    ui.activate_checkout_token()
    assert ui.get_checkout_unlocked_panel().is_visible()
    assert page.evaluate("() => window.__xssKey === undefined && window.__xssLbl === undefined") is True
    assert page.locator("img[src='x'], svg[onload]").count() == 0

    exported_pvkey = pro_raw_session.io.downloads / "injected_roundtrip.pvkey"
    saved_path = ui.download_checkout_pvkey(pro_raw_session.io.downloads)
    pvkey_text = saved_path.read_text(encoding="utf-8")
    assert "[REDACTED]" in pvkey_text
    assert "PV1.forgedPayload.forgedSig1234567890" not in pvkey_text
    assert pvkey_text.strip().splitlines()[-1] == inj_tok
    exported_pvkey.write_text(pvkey_text, encoding="utf-8")

    ui.upload_checkout_pvkey(exported_pvkey)
    assert page.locator("#checkout-token-input").input_value() == inj_tok

    ui.activate_checkout_token(proto_tok)
    assert page.evaluate("() => ({}).pvPolluted === undefined") is True

    ui.fill_checkout_buyer(
        name="__proto__",
        email="proto.safe@example.com",
        company="constructor",
        accept_terms=True,
    )
    ui.submit_checkout_order()
    assert ui.get_checkout_order_panel().is_visible()
    assert page.evaluate("() => ({}).pvPolluted === undefined") is True

    pro_raw_session.net.assert_zero_egress([inj_tok, proto_tok, "proto.safe@example.com"])
    pro_raw_session.console.assert_no_errors()


def test_T5_41_pro_checkout_purejs_ed25519_fallback_and_exp_boundary_matrix(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R1/R2 Tier 5: Pure-JS Ed25519 fallback on /pro/, exp/schema boundaries, diagnostics coercion (B3), and %2E fragment."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()

    # Exact exp == nowMs boundary check via direct verifyProLicenseToken import (loaded during load phase)
    eq_now_tok = ephemeral_pro_keys.sign_raw_payload(
        {
            "v": 1,
            "tier": "pro",
            "keyId": "PV-EQNOW",
            "label": "EqNow",
            "issuedAt": "2026-11-21T00:00:00Z",
            "exp": 1795435200000,
        }
    )
    eq_res = page.evaluate(
        """async (tok) => {
            const { verifyProLicenseToken } = await import('/js/pro-license.js');
            const atBoundary = await verifyProLicenseToken(tok, { nowMs: 1795435200000 });
            const beforeBoundary = await verifyProLicenseToken(tok, { nowMs: 1795435199999 });
            return { atValid: atBoundary.valid, atReason: atBoundary.reason, beforeValid: beforeBoundary.valid };
        }""",
        eq_now_tok,
    )
    assert eq_res == {"atValid": False, "atReason": "expired", "beforeValid": True}
    pro_raw_session.net.assert_clean_load()

    pro_raw_session.net.start_interactive_phase()

    page.evaluate(
        """() => {
            if (window.crypto && window.crypto.subtle) {
                window.crypto.subtle.verify = () => Promise.reject(new Error('Ed25519 unsupported'));
            }
        }"""
    )

    valid_tok = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-PJS", label="PureJS Test")
    ui.activate_checkout_token(valid_tok)
    assert ui.get_checkout_unlocked_panel().is_visible()
    assert "pure-js" in ui.get_checkout_token_diagnostics().lower()

    page.locator("#checkout-deactivate-btn").click()
    page.wait_for_timeout(100)

    prefix, payload_b64, sig_b64 = valid_tok.split(".")
    flipped = "A" if sig_b64[0] != "A" else "B"
    exp_empty_tok = ephemeral_pro_keys.sign_raw_payload(
        {"v": 1, "tier": "pro", "keyId": "PV-EXPE", "label": "ExpEmpty", "issuedAt": "0", "exp": ""}
    )
    bad_tier_tok = ephemeral_pro_keys.sign_raw_payload(
        {"v": 1, "tier": 123, "keyId": "PV-T123", "label": "BadTier", "issuedAt": "2026-11-21T00:00:00Z"}
    )
    bad_vectors = [
        f"{prefix}.{payload_b64}.{flipped}{sig_b64[1:]}",
        f"{valid_tok}=",
        f"{valid_tok}.extra",
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 1, "tier": "pro", "keyId": "PV-EXP0", "label": "Exp0", "issuedAt": "2026-11-21T00:00:00Z", "exp": 0}
        ),
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 1, "tier": "pro", "keyId": "PV-EXPN", "label": "ExpNeg", "issuedAt": "2026-11-21T00:00:00Z", "exp": -100}
        ),
        exp_empty_tok,
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 1, "tier": "pro", "keyId": "PV-EXPB", "label": "ExpBool", "issuedAt": "2026-11-21T00:00:00Z", "exp": False}
        ),
        bad_tier_tok,
        ephemeral_pro_keys.sign_raw_payload(
            {"v": 1, "tier": "pro", "keyId": 456, "label": "BadId", "issuedAt": "2026-11-21T00:00:00Z"}
        ),
    ]
    for vec in bad_vectors:
        ui.activate_checkout_token(vec)
        assert not page.locator("#checkout-pro-unlocked").is_visible()
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    # B3 checks: empty exp must not render "бессрочный"/"never", and non-string tier must not coerce to "pro"
    ui.activate_checkout_token(exp_empty_tok)
    diag_exp_empty = ui.get_checkout_token_diagnostics().lower()
    assert "бессроч" not in diag_exp_empty and "never" not in diag_exp_empty
    assert "1970" not in diag_exp_empty

    ui.activate_checkout_token(bad_tier_tok)
    diag_bad_tier = ui.get_checkout_token_diagnostics().lower()
    assert "уровень: pro" not in diag_bad_tier and "tier: pro" not in diag_bad_tier

    # Percent-encoded fragment with literal 100% (malformed percent elsewhere)
    encoded_tok = valid_tok.replace(".", "%2E")
    page.evaluate("(h) => { window.location.hash = h; }", f"#code={encoded_tok}&note=100%")
    page.wait_for_timeout(200)
    assert page.locator("#checkout-token-input").input_value() == valid_tok

    pro_raw_session.net.assert_zero_egress([valid_tok])
    pro_raw_session.console.assert_no_errors()


def test_T5_42_pro_checkout_pvkey_256kb_boundary_nul_tail_utf8_and_bom(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R1 Tier 5: .pvkey upload enforces 256 KB exact cap, UTF-8 BOM support, NUL-byte & invalid UTF-8 rejection."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    tok = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-256K", label="Boundary File")
    tok_bytes = (tok + "\n").encode("utf-8")

    exact_file = pro_raw_session.io.uploads / "exact_256k.pvkey"
    exact_file.write_bytes(tok_bytes + b" " * (262144 - len(tok_bytes)))

    bom_file = pro_raw_session.io.uploads / "utf8_bom.pvkey"
    bom_file.write_bytes(b"\xef\xbb\xbf" + tok_bytes)

    over_file = pro_raw_session.io.uploads / "over_256k.pvkey"
    over_file.write_bytes(tok_bytes + b" " * (262145 - len(tok_bytes)))

    nul_tail_file = pro_raw_session.io.uploads / "nul_tail.pvkey"
    nul_tail_file.write_bytes(tok.encode("utf-8") + b"\x00")

    bad_utf8_file = pro_raw_session.io.uploads / "bad_utf8.pvkey"
    bad_utf8_file.write_bytes(tok.encode("utf-8") + b"\n\xc3\x28")

    utf16_file = pro_raw_session.io.uploads / "utf16.pvkey"
    utf16_file.write_bytes(b"\xff\xfe" + tok.encode("utf-16-le"))

    for ok_file in (exact_file, bom_file):
        ui.upload_checkout_pvkey(ok_file)
        assert page.locator("#checkout-token-input").input_value() == tok
        assert "PV-T5-256K" in ui.get_checkout_token_diagnostics()

    for bad_file in (over_file, nul_tail_file, bad_utf8_file, utf16_file):
        ui.upload_checkout_pvkey(bad_file)
        assert page.locator("#checkout-token-diagnostics").is_visible()
        assert not page.locator("#checkout-pro-unlocked").is_visible()
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None

    pro_raw_session.net.assert_zero_egress([tok])
    pro_raw_session.console.assert_no_errors()


def test_T5_43_pro_checkout_localstorage_tamper_whitespace_json_and_active_license_preservation(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R1/R2 Tier 5: Tampered localStorage payloads purge cleanly; failed re-activation preserves active Pro license; QuotaExceededError warns cleanly (B2)."""
    from monitors import verify_allowed_local_storage_keys

    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    for route in ("/pro/", "/en/pro/", "/"):
        for tampered in ('{"valid":true,"isPro":true,"tier":"owner"}', "[null]", "   "):
            pro_raw_session.net.phase = "load"
            page.goto(f"{base}{route}", wait_until="networkidle")
            page.evaluate("(v) => localStorage.setItem('promptveil_pro_license_v1', v)", tampered)
            page.reload(wait_until="networkidle")
            pro_raw_session.net.assert_clean_load()
            assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None
            if route == "/":
                assert ui.get_pro_badge_text().lower() in ("free", "бесплатно")
            else:
                assert page.locator("#checkout-pro-status-badge").get_attribute("data-pro-state") == "free"
                assert not page.locator("#checkout-pro-unlocked").is_visible()

    valid_tok = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-KEEP", label="Keep Valid")
    expired_tok = ephemeral_pro_keys.issue_token(
        tier="pro", key_id="PV-T5-EXPP", label="Expired", exp="2020-01-01T00:00:00.000Z"
    )
    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    ui.activate_checkout_token(valid_tok)
    assert ui.get_checkout_unlocked_panel().is_visible()

    # Failed activation of an expired token must NOT destroy existing active license
    ui.activate_checkout_token(expired_tok)
    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") == valid_tok
    assert ui.get_checkout_unlocked_panel().is_visible()
    assert page.locator("#checkout-pro-status-badge").get_attribute("data-pro-state") == "pro"
    verify_allowed_local_storage_keys(page)

    # B2: QuotaExceededError during activation surfaces storageWarning alert banner cleanly
    page.locator("#checkout-deactivate-btn").click()
    page.wait_for_timeout(100)
    page.evaluate(
        """() => {
            window.__origSetItem = Storage.prototype.setItem;
            Storage.prototype.setItem = () => {
                throw new DOMException('Quota exceeded', 'QuotaExceededError');
            };
        }"""
    )
    try:
        ui.activate_checkout_token(valid_tok)
        banner = page.locator("#global-status-banner")
        assert banner.is_visible()
        assert banner.get_attribute("role") == "alert"
        assert "заполнено" in banner.inner_text().lower() or "storage" in banner.inner_text().lower()
        assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None
    finally:
        page.evaluate(
            """() => {
                if (window.__origSetItem) {
                    Storage.prototype.setItem = window.__origSetItem;
                    delete window.__origSetItem;
                }
            }"""
        )

    pro_raw_session.net.assert_zero_egress([valid_tok, expired_tok])
    pro_raw_session.console.assert_no_errors()


def test_T5_44_pro_checkout_sw_offline_routes_and_lang_switch_resilience(
    playwright_browser: Browser,
) -> None:
    """R1 Tier 5: Service Worker precaches /pro/ & /en/pro/ + dynamic i18n chunks and syncs footer links (B4) offline."""
    with start_static_dir_server(STATIC_APP_DIR) as static_url:
        ctx = playwright_browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        console = ConsoleErrorMonitor(page=page)
        console.attach()
        try:
            page.goto(f"{static_url}/pro/", wait_until="networkidle")
            ready = page.evaluate(
                """async () => {
                    const reg = await navigator.serviceWorker.ready;
                    if (!reg || !reg.active) return false;
                    if (reg.active.state === 'activated') return true;
                    await new Promise((resolve) => {
                        reg.active.addEventListener('statechange', () => {
                            if (reg.active.state === 'activated') resolve();
                        });
                    });
                    return true;
                }"""
            )
            assert ready is True
            page.reload(wait_until="networkidle")
            assert page.evaluate("() => Boolean(navigator.serviceWorker.controller)") is True

            ctx.set_offline(True)
            page.reload(wait_until="domcontentloaded")
            page.wait_for_timeout(200)
            assert page.locator("#checkout-hero-title").is_visible()

            page.locator("#lang-en-btn").click()
            page.wait_for_timeout(200)
            assert page.evaluate("() => document.documentElement.lang") == "en"
            # B4: Footer links stay synced with RU/EN toggle
            footer_hrefs = page.evaluate(
                "() => Array.from(document.querySelectorAll('.footer-links-row a')).map(a => a.getAttribute('href'))"
            )
            assert "/en/" in footer_hrefs and "/en/#pricing-section" in footer_hrefs

            page.goto(f"{static_url}/en/pro/", wait_until="domcontentloaded")
            page.wait_for_timeout(200)
            assert "Checkout" in page.locator("#checkout-hero-title").inner_text()

            page.goto(f"{static_url}/pro", wait_until="domcontentloaded")
            page.wait_for_timeout(200)
            assert page.locator("#checkout-hero-title").is_visible()

            page.goto(f"{static_url}/pro/#code=PV1.bad.sig", wait_until="domcontentloaded")
            page.wait_for_timeout(200)
            assert page.locator("#checkout-token-input").input_value() == "PV1.bad.sig"
            assert page.locator("#checkout-token-diagnostics").is_visible()

            console.assert_no_errors()
        finally:
            ctx.set_offline(False)
            console.detach()
            ctx.close()


def test_T5_45_pro_checkout_active_csp_all_egress_sinks_and_allowlist_hygiene(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R1 Tier 5: Active CSP enforcement across fetch/XHR/sendBeacon/WebSocket/script/img on /pro/ & /en/pro/ + storage allowlist."""
    from monitors import verify_allowed_local_storage_keys

    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    for route in ("/pro/", "/en/pro/"):
        pro_raw_session.net.phase = "load"
        page.goto(f"{base}{route}", wait_until="networkidle")
        pro_raw_session.net.assert_clean_load()

        with pro_raw_session.console.allow_expected_csp_errors():
            probe = page.evaluate(
                """async () => {
                    const violated = [];
                    const onV = (e) => violated.push(e.effectiveDirective || e.violatedDirective || '');
                    document.addEventListener('securitypolicyviolation', onV);
                    try {
                        let fetchErr = false;
                        try { await fetch('https://example.com/t5-csp'); } catch { fetchErr = true; }
                        let beaconOk = true;
                        try { beaconOk = navigator.sendBeacon('https://example.com/t5-beacon', 'x'); } catch { beaconOk = false; }
                        let wsErr = false;
                        try { new WebSocket('wss://example.com/t5-ws'); } catch { wsErr = true; }
                        const img = document.createElement('img');
                        img.src = 'https://example.com/t5-pixel.png';
                        document.body.appendChild(img);
                        await new Promise((r) => setTimeout(r, 150));
                        img.remove();
                        return { fetchErr, beaconOk, wsErr, violated };
                    } finally {
                        document.removeEventListener('securitypolicyviolation', onV);
                    }
                }"""
            )
        assert probe["fetchErr"] is True
        assert probe["beaconOk"] is False or any("connect-src" in d for d in probe["violated"])
        assert len(probe["violated"]) >= 2
        assert ("https://example.com/t5-pixel.png", "csp") in pro_raw_session.net.failed_requests
        pro_raw_session.net.failed_requests = [
            f for f in pro_raw_session.net.failed_requests if f[0] != "https://example.com/t5-pixel.png"
        ]

    pro_raw_session.net.start_interactive_phase()
    tok = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-T5-CSP", label="CSP Clean")
    ui.activate_checkout_token(tok)
    verify_allowed_local_storage_keys(page)
    pro_raw_session.net.assert_zero_egress([tok])
    pro_raw_session.console.assert_no_errors()


def test_T5_46_pro_checkout_async_verify_activate_deactivate_race_regression(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """R1 Tier 5 Regression (B1 fix in pro-checkout.js): Async activate vs deactivate & verify races."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    pro_raw_session.net.phase = "load"
    page.goto(f"{base}/pro/", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()

    tok_a = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-RACE-A", label="Race A")
    tok_b = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-RACE-B", label="Race B")
    ui.activate_checkout_token(tok_a)
    assert ui.get_checkout_unlocked_panel().is_visible()

    # Slow down first subtle.verify call, trigger activate(tok_b), then deactivate before resolve
    page.evaluate(
        """() => {
            const orig = crypto.subtle.verify.bind(crypto.subtle);
            let delayOnce = true;
            crypto.subtle.verify = async (...args) => {
                if (delayOnce) {
                    delayOnce = false;
                    await new Promise((r) => setTimeout(r, 250));
                }
                return orig(...args);
            };
        }"""
    )
    ui.enter_checkout_token(tok_b)
    page.locator("#checkout-activate-btn").click()
    page.wait_for_timeout(30)
    page.locator("#checkout-deactivate-btn").click()
    page.wait_for_timeout(350)

    assert page.evaluate("() => localStorage.getItem('promptveil_pro_license_v1')") is None
    assert not page.locator("#checkout-pro-unlocked").is_visible()
    assert page.locator("#checkout-pro-status-badge").get_attribute("data-pro-state") == "free"

    # Slow verify(tok_a) overtaken by fast verify('PV1.bad.sig') must not overwrite diagnostics
    page.evaluate(
        """() => {
            const orig = crypto.subtle.verify.bind(crypto.subtle);
            let call = 0;
            crypto.subtle.verify = async (...args) => {
                call += 1;
                if (call === 1) await new Promise((r) => setTimeout(r, 250));
                return orig(...args);
            };
        }"""
    )
    ui.enter_checkout_token(tok_a)
    page.locator("#checkout-verify-only-btn").click()
    page.wait_for_timeout(30)
    ui.enter_checkout_token("PV1.bad.sig")
    page.locator("#checkout-verify-only-btn").click()
    page.wait_for_timeout(350)

    assert "PV-RACE-A" not in ui.get_checkout_token_diagnostics()
    pro_raw_session.net.assert_zero_egress([tok_a, tok_b])
    pro_raw_session.console.assert_no_errors()


def test_T5_47_owner_cli_adversarial_verify_redact_bundle_and_bounds(
    temp_io_dir: TempIODirs,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """Owner CLI: --verify tampering/--now, --verify-bundle mismatch/empty/non-array, --redact leak check, batch/days bounds, and --key-id traversal."""
    import subprocess
    from conftest import WORKSPACE_ROOT, _resolve_node_exe

    node_exe = str(_resolve_node_exe())
    issue_script = str(WORKSPACE_ROOT / "scripts" / "issue-pro-key.mjs")
    bundle_path = temp_io_dir.root / "ephem_bundle.json"
    pv_dir = temp_io_dir.root / "pvkeys"

    def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [node_exe, issue_script, *args],
            cwd=str(WORKSPACE_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=15,
        )

    gen = _run_cli("--generate-bundle", "--out", str(bundle_path), "--json")
    assert gen.returncode == 0, gen.stderr
    ephem_pub = json.loads(gen.stdout)["publicKeyB64U"]

    # 1. --verify-bundle rejects wrong --pub, tampered bundle entries, non-array clientKeys, and empty bundle
    wrong_pub = ephemeral_pro_keys.public_key_b64u
    assert _run_cli("--verify-bundle", "--bundle", str(bundle_path), "--pub", wrong_pub, "--json").returncode != 0

    tampered_bundle = temp_io_dir.root / "tampered_bundle.json"
    b_obj = json.loads(bundle_path.read_text(encoding="utf-8"))
    b_obj["clientKeys"][0]["keyId"] = "PV-MISMATCH-99"
    tampered_bundle.write_text(json.dumps(b_obj), encoding="utf-8")
    tb_res = _run_cli("--verify-bundle", "--bundle", str(tampered_bundle), "--pub", ephem_pub, "--json")
    assert tb_res.returncode != 0
    assert any(f["reason"] == "keyId_mismatch" for f in json.loads(tb_res.stdout)["failures"])

    non_arr_bundle = temp_io_dir.root / "non_arr_bundle.json"
    b_non_arr = json.loads(bundle_path.read_text(encoding="utf-8"))
    b_non_arr["clientKeys"] = "not-an-array"
    non_arr_bundle.write_text(json.dumps(b_non_arr), encoding="utf-8")
    na_res = _run_cli("--verify-bundle", "--bundle", str(non_arr_bundle), "--pub", ephem_pub, "--json")
    assert na_res.returncode != 0
    assert json.loads(na_res.stdout)["ok"] is False

    empty_bundle = temp_io_dir.root / "empty_bundle.json"
    empty_bundle.write_text(
        json.dumps(
            {
                "publicKeyB64U": b_non_arr["publicKeyB64U"],
                "privateKeyPkcs8Pem": b_non_arr["privateKeyPkcs8Pem"],
            }
        ),
        encoding="utf-8",
    )
    emp_res = _run_cli("--verify-bundle", "--bundle", str(empty_bundle), "--pub", ephem_pub, "--json")
    assert emp_res.returncode != 0
    assert json.loads(emp_res.stdout)["ok"] is False

    # 2. --issue + --redact never leaks raw PV1. tokens or private keys across JSON, MD, CSV, --verify, or --inspect-bundle
    now_iso = "2026-11-23T00:00:00.000Z"
    md_table = temp_io_dir.root / "redacted.md"
    csv_table = temp_io_dir.root / "redacted.csv"
    iss = _run_cli(
        "--issue", "--bundle", str(bundle_path), "--pub", ephem_pub,
        "--plan", "pro-monthly", "--count", "2", "--prefix", "PV-T547",
        "--now", now_iso, "--out-pvkey", str(pv_dir),
        "--out-table", str(md_table), "--redact", "--json",
    )
    assert iss.returncode == 0, iss.stderr
    assert "BEGIN PRIVATE KEY" not in iss.stdout
    for item in json.loads(iss.stdout)["items"]:
        assert "..." in item["token"]

    iss_csv = _run_cli(
        "--issue", "--bundle", str(bundle_path), "--pub", ephem_pub,
        "--key-id", "../../evil", "--out-pvkey", str(pv_dir) + "/",
        "--out-table", str(csv_table), "--redact", "--json",
    )
    assert iss_csv.returncode == 0, iss_csv.stderr
    assert (pv_dir / ".._.._evil.pvkey").is_file()
    assert not (temp_io_dir.root / "evil.pvkey").exists()
    assert re.search(r"PV1\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", md_table.read_text(encoding="utf-8")) is None
    assert re.search(r"PV1\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", csv_table.read_text(encoding="utf-8")) is None

    # 3. --verify tampered sig, padded token, wrong pub, and --now boundary (1ms before vs exact exp)
    pv_file = pv_dir / "PV-T547-01.pvkey"
    raw_tok = [ln.strip() for ln in pv_file.read_text(encoding="utf-8").splitlines() if ln.startswith("PV1.")][0]
    exp_iso = json.loads(iss.stdout)["items"][0]["exp"]

    tampered_tok = raw_tok[:-2] + ("AA" if not raw_tok.endswith("AA") else "BB")
    assert _run_cli("--verify", tampered_tok, "--pub", ephem_pub, "--json").returncode == 1
    assert _run_cli("--verify", raw_tok + "=", "--pub", ephem_pub, "--json").returncode == 1
    assert _run_cli("--verify", raw_tok, "--pub", wrong_pub, "--json").returncode == 1

    ver_ok = _run_cli("--verify", raw_tok, "--pub", ephem_pub, "--now", "2026-12-22T23:59:59.999Z", "--redact", "--json")
    assert ver_ok.returncode == 0
    assert raw_tok not in ver_ok.stdout
    ver_exp = _run_cli("--verify", raw_tok, "--pub", ephem_pub, "--now", exp_iso, "--json")
    assert ver_exp.returncode == 1
    assert json.loads(ver_exp.stdout)["reason"] == "expired"

    # 4. Invalid batch / days boundaries
    for bad_args in (
        ("--count", "0"),
        ("--count", "-1"),
        ("--count", "1.5"),
        ("--count", "1001"),
        ("--days", "0"),
        ("--days", "-2"),
        ("--days", "1e-10"),
        ("--days", "10", "--exp", "2028-01-01T00:00:00Z"),
    ):
        fail = _run_cli("--issue", "--bundle", str(bundle_path), "--pub", ephem_pub, *bad_args, "--json")
        assert fail.returncode != 0, f"Expected failure for {bad_args}"


def test_T5_48_owner_console_http_security_boundaries_and_csrf(
    temp_io_dir: TempIODirs,
) -> None:
    """Owner Console HTTP server: non-loopback rejection, Host DNS-rebinding, Origin/Referer CSRF, // URL, corrupt ledger, favicon 204, 413 >64KB, 400 JSON."""
    import http.client
    import subprocess
    import urllib.parse
    from conftest import WORKSPACE_ROOT, _resolve_node_exe

    node_exe = str(_resolve_node_exe())
    issue_script = str(WORKSPACE_ROOT / "scripts" / "issue-pro-key.mjs")
    console_script = str(WORKSPACE_ROOT / "scripts" / "owner-console.mjs")
    bundle_path = temp_io_dir.root / "bundle.json"
    ledger_path = temp_io_dir.root / "ledger.json"

    gen = subprocess.run(
        [node_exe, issue_script, "--generate-bundle", "--out", str(bundle_path), "--json"],
        cwd=str(WORKSPACE_ROOT), capture_output=True, text=True, encoding="utf-8", check=True, timeout=15,
    )
    pub = json.loads(gen.stdout)["publicKeyB64U"]

    # Non-loopback bind refusal
    non_loopback = subprocess.run(
        [node_exe, console_script, "--host", "0.0.0.0", "--port", "0", "--bundle", str(bundle_path)],
        cwd=str(WORKSPACE_ROOT), capture_output=True, text=True, encoding="utf-8", check=False, timeout=10,
    )
    assert non_loopback.returncode != 0

    proc = subprocess.Popen(
        [
            node_exe, console_script, "--host", "127.0.0.1", "--port", "0",
            "--bundle", str(bundle_path), "--ledger", str(ledger_path), "--pub", pub,
        ],
        cwd=str(WORKSPACE_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().strip()
        base_url = line.split("listening at ", 1)[1].strip().rstrip("/")
        parsed = urllib.parse.urlparse(base_url)
        host_port = f"{parsed.hostname}:{parsed.port}"

        def _raw_http(method: str, req_path: str, headers: dict[str, str], body: bytes = b"") -> tuple[int, str]:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
            try:
                conn.request(method, req_path, body=body, headers=headers)
                resp = conn.getresponse()
                return resp.status, resp.read().decode("utf-8", errors="replace")
            finally:
                conn.close()

        # DNS-rebinding Host headers -> 403
        for bad_host in ("evil.com", "127.0.0.1.evil.com:80", "127.0.0.1:80@evil.com"):
            st, _ = _raw_http("GET", "/api/health", {"Host": bad_host})
            assert st == 403, f"Expected 403 for Host={bad_host}, got {st}"

        # Sec-Fetch-Site: cross-site -> 403
        st_sfs, _ = _raw_http("GET", "/api/status", {"Host": host_port, "Sec-Fetch-Site": "cross-site"})
        assert st_sfs == 403

        # Protocol-relative req.url //evil.com -> 400
        st_proto, _ = _raw_http("GET", "//evil.com/api/health", {"Host": host_port})
        assert st_proto == 400

        # GET /favicon.ico -> 204
        st_fav, fav_body = _raw_http("GET", "/favicon.ico", {"Host": host_port})
        assert st_fav == 204 and fav_body == ""

        # Cross-origin / cross-host loopback / null / https / wrong-port Origin on POST -> 403
        for bad_origin in (
            "https://evil.example",
            "null",
            f"https://127.0.0.1:{parsed.port}",
            "http://127.0.0.1:1",
            f"http://localhost:{parsed.port}",
        ):
            st_csrf, _ = _raw_http(
                "POST", "/api/issue",
                {"Host": host_port, "Origin": bad_origin, "Content-Type": "application/json"},
                b'{"plan":"pro-monthly"}',
            )
            assert st_csrf == 403, f"Expected 403 for Origin={bad_origin}, got {st_csrf}"

        # Omitted Origin + cross-origin Referer -> 403; matching Referer -> 200
        st_ref_bad, _ = _raw_http(
            "POST", "/api/issue",
            {"Host": host_port, "Referer": "https://evil.com/attack.html", "Content-Type": "application/json"},
            b'{"plan":"pro-monthly"}',
        )
        assert st_ref_bad == 403

        st_ref_ok, _ = _raw_http(
            "POST", "/api/verify",
            {"Host": host_port, "Referer": f"http://{host_port}/", "Content-Type": "application/json"},
            b'{"rawText":"PV2.bad.sig"}',
        )
        assert st_ref_ok == 200

        # Corrupt JSON & invalid schema in ledger_path -> 400/409 (no 500, no OS ledgerPath leak)
        for bad_ledger in ("{corrupt json", json.dumps({"format": "PV1-LEDGER", "entries": "not-an-array"})):
            ledger_path.write_text(bad_ledger, encoding="utf-8")
            st_led, led_body = _raw_http(
                "POST", "/api/issue",
                {"Host": host_port, "Content-Type": "application/json"},
                b'{"plan":"pro-monthly","appendLedger":true}',
            )
            assert st_led in (400, 409), f"Expected 400/409 for corrupt ledger, got {st_led}: {led_body}"
            assert str(ledger_path) not in led_body
            assert str(temp_io_dir.root) not in led_body

        # Oversized POST (> 64 KB) -> 413
        big_body = json.dumps({"rawText": "A" * (70 * 1024)}).encode("utf-8")
        st_big, _ = _raw_http(
            "POST", "/api/verify",
            {"Host": host_port, "Content-Type": "application/json"},
            big_body,
        )
        assert st_big == 413

        # Malformed & non-object JSON -> 400
        for bad_json in (b"{bad", b"null", b"[]", b"123", b'"str"'):
            st_bad, _ = _raw_http(
                "POST", "/api/issue",
                {"Host": host_port, "Content-Type": "application/json"},
                bad_json,
            )
            assert st_bad == 400

        # /api/status default redacts & never exposes private key
        st_stat, stat_body = _raw_http("GET", "/api/status", {"Host": host_port})
        assert st_stat == 200
        assert "BEGIN PRIVATE KEY" not in stat_body
        assert "privateKeyPkcs8Pem" not in stat_body
        assert "..." in json.loads(stat_body)["ownerKey"]["token"]
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_T5_49_owner_console_browser_ui_csp_and_xss_inertness(
    temp_io_dir: TempIODirs,
    playwright_browser: Browser,
) -> None:
    """Owner Console UI in Chromium: strict CSP, real /favicon.ico 204, zero console errors/violations, and inert XSS rendering in keyId/label/orderId."""
    import subprocess
    from conftest import WORKSPACE_ROOT, _resolve_node_exe

    node_exe = str(_resolve_node_exe())
    issue_script = str(WORKSPACE_ROOT / "scripts" / "issue-pro-key.mjs")
    console_script = str(WORKSPACE_ROOT / "scripts" / "owner-console.mjs")
    bundle_path = temp_io_dir.root / "bundle.json"
    ledger_path = temp_io_dir.root / "ledger.json"

    gen = subprocess.run(
        [node_exe, issue_script, "--generate-bundle", "--out", str(bundle_path), "--json"],
        cwd=str(WORKSPACE_ROOT), capture_output=True, text=True, encoding="utf-8", check=True, timeout=15,
    )
    pub = json.loads(gen.stdout)["publicKeyB64U"]

    proc = subprocess.Popen(
        [
            node_exe, console_script, "--host", "127.0.0.1", "--port", "0",
            "--bundle", str(bundle_path), "--ledger", str(ledger_path), "--pub", pub,
        ],
        cwd=str(WORKSPACE_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
    )
    ctx = playwright_browser.new_context(viewport={"width": 1280, "height": 800})
    try:
        assert proc.stdout is not None
        url = proc.stdout.readline().strip().split("listening at ", 1)[1].strip()
        page = ctx.new_page()
        console = ConsoleErrorMonitor(page=page)
        console.attach()
        dialogs: list[str] = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.add_init_script(
            "window.__cspViolations = []; document.addEventListener('securitypolicyviolation', e => window.__cspViolations.push(e.violatedDirective));"
        )

        page.goto(url, wait_until="networkidle")
        assert page.locator("#health-pill").inner_text() == "Loopback Active"
        assert "Matches PRO_PUBLIC_KEY_B64U" in page.locator("#status-match").inner_text()

        xss_payload = "<img src=x onerror=alert(1)>"
        page.fill("#issue-key-id", f"PV-XSS-{xss_payload}")
        page.fill("#issue-label", f"Buyer {xss_payload}")
        page.fill("#issue-order", f"PV-ORD-{xss_payload}")
        page.click("#issue-submit-btn")
        page.locator(".issued-item").first.wait_for(state="visible", timeout=5000)
        assert xss_payload in page.locator("#issued-results").inner_text()

        page.locator(".issued-item button", has_text="Send to Validator").click()
        page.locator("#verify-output pre").wait_for(state="visible", timeout=5000)
        verify_txt = page.locator("#verify-output").inner_text()
        assert "VALID (pro)" in verify_txt
        assert xss_payload in verify_txt

        assert dialogs == []
        assert page.evaluate("() => window.__cspViolations") == []
        console.assert_no_errors()
        console.detach()
    finally:
        ctx.close()
        proc.terminate()
        proc.wait(timeout=5)


def _serve_extension_dir(ext_dir: Path):
    """Context manager serving extension/ on 127.0.0.1:0 with MV3 CSP header."""
    import contextlib
    import functools
    import http.server
    import socketserver
    import threading

    class _ExtHandler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self) -> None:
            self.send_header("Content-Security-Policy", "script-src 'self'; object-src 'none'")
            super().end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            _ = (format, args)

    class _Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    @contextlib.contextmanager
    def _ctx():
        srv = _Srv(("127.0.0.1", 0), functools.partial(_ExtHandler, directory=str(ext_dir)))
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            yield f"http://127.0.0.1:{srv.server_address[1]}"
        finally:
            srv.shutdown()
            srv.server_close()

    return _ctx()


def test_T5_50_extension_popup_bundle_csp_pvkey_bounds_and_xss(
    temp_io_dir: TempIODirs,
    ephemeral_pro_keys: EphemeralProKeys,
    playwright_browser: Browser,
) -> None:
    """Bundled extension/popup.html + dist/popup.bundle.js in Chromium under MV3 CSP: .pvkey bounds, XSS inertness, and external storage tamper clearing diagnostics."""
    from conftest import WORKSPACE_ROOT

    ext_dir = WORKSPACE_ROOT / "extension"
    prod_pub = "Fsb_LKEZCuhkazGVQd18WiV34EQmpUUkxR9-Rc20YCY"
    ephem_pub = ephemeral_pro_keys.public_key_b64u

    with _serve_extension_dir(ext_dir) as ext_url:
        ctx = playwright_browser.new_context(viewport={"width": 420, "height": 720})
        page = ctx.new_page()
        dialogs: list[str] = []
        page_errors: list[str] = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.on("pageerror", lambda e: page_errors.append(str(e)))
        page.add_init_script(
            """(() => {
                window.__cspV = [];
                document.addEventListener('securitypolicyviolation', e => window.__cspV.push(e.violatedDirective));
                const store = new Map();
                const listeners = new Set();
                window.chrome = window.chrome || {};
                window.chrome.runtime = { id: 'pv-e2e-ext' };
                window.chrome.tabs = {
                    query: (_q, cb) => {
                        const r = [{ url: 'https://chatgpt.com/c/1' }];
                        if (cb) cb(r);
                        return Promise.resolve(r);
                    },
                };
                window.chrome.storage = {
                    local: {
                        get(keys, cb) {
                            const list = Array.isArray(keys) ? keys : [keys];
                            const out = {};
                            for (const k of list) if (store.has(k)) out[k] = structuredClone(store.get(k));
                            if (cb) cb(out);
                            return Promise.resolve(out);
                        },
                        set(items, cb) {
                            const changes = {};
                            for (const [k, v] of Object.entries(items)) {
                                const oldValue = store.has(k) ? structuredClone(store.get(k)) : undefined;
                                store.set(k, structuredClone(v));
                                changes[k] = { oldValue, newValue: structuredClone(v) };
                            }
                            if (cb) cb();
                            for (const fn of listeners) fn(changes, 'local');
                            return Promise.resolve();
                        },
                        remove(key, cb) {
                            const oldValue = store.has(key) ? structuredClone(store.get(key)) : undefined;
                            store.delete(key);
                            if (cb) cb();
                            for (const fn of listeners) fn({ [key]: { oldValue, newValue: undefined } }, 'local');
                            return Promise.resolve();
                        },
                    },
                    onChanged: {
                        addListener: fn => listeners.add(fn),
                        removeListener: fn => listeners.delete(fn),
                    },
                };
            })();"""
        )

        def _patch_ext_bundle(route: object) -> None:
            resp = route.fetch()  # type: ignore[attr-defined]
            body = resp.body().decode("utf-8", errors="replace").replace(prod_pub, ephem_pub)
            hdrs = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-length", "content-encoding")}
            route.fulfill(status=resp.status, headers=hdrs, body=body.encode("utf-8"))  # type: ignore[attr-defined]

        page.route("**/dist/*.bundle.js", _patch_ext_bundle)
        page.route("**/favicon.ico", lambda r: r.fulfill(status=204, body=b""))
        try:
            page.goto(f"{ext_url}/popup.html", wait_until="networkidle")
            page.wait_for_timeout(120)
            assert "ChatGPT" in page.locator("#popup-site-status").inner_text()
            assert page.locator("#popup-pro-badge").inner_text() == "Free"

            xss = "<img src=x onerror=alert(1)>"
            xss_tok = ephemeral_pro_keys.issue_token(tier="pro", key_id=f"PV-EXT-{xss}", label=f"Ext {xss}")

            # 1. Exact 256 KB .pvkey succeeds
            exact_file = temp_io_dir.uploads / "exact_256k.pvkey"
            pad_len = 256 * 1024 - len(xss_tok.encode("utf-8")) - 1
            exact_file.write_bytes(b"#" * pad_len + b"\n" + xss_tok.encode("utf-8"))
            page.set_input_files("#popup-pro-file-input", str(exact_file))
            page.wait_for_timeout(150)
            assert page.locator("#popup-pro-badge").inner_text() == "Pro Активен"
            assert xss in page.locator("#popup-pro-meta-list").inner_text()

            # 2. 256 KB + 1 byte rejected; NUL binary rejected; invalid UTF-8 rejected; UTF-8 BOM accepted
            over_file = temp_io_dir.uploads / "over_256k.pvkey"
            over_file.write_bytes(b"#" * (256 * 1024 + 1))
            page.set_input_files("#popup-pro-file-input", str(over_file))
            page.wait_for_timeout(120)
            assert "256" in page.locator("#popup-pro-alert").inner_text()

            nul_file = temp_io_dir.uploads / "nul.pvkey"
            nul_file.write_bytes(b"PV1\x00" + xss_tok.encode("utf-8"))
            page.set_input_files("#popup-pro-file-input", str(nul_file))
            page.wait_for_timeout(120)
            assert page.locator("#popup-pro-diagnostics.is-error").is_visible()

            bad_utf8 = temp_io_dir.uploads / "bad_utf8.pvkey"
            bad_utf8.write_bytes(b"\xff\xfe\xfd" + xss_tok.encode("utf-8"))
            page.set_input_files("#popup-pro-file-input", str(bad_utf8))
            page.wait_for_timeout(120)
            assert page.locator("#popup-pro-diagnostics.is-error").is_visible()

            bom_file = temp_io_dir.uploads / "bom.pvkey"
            bom_file.write_bytes(b"\xef\xbb\xbf# BOM\n" + xss_tok.encode("utf-8"))
            page.set_input_files("#popup-pro-file-input", str(bom_file))
            page.wait_for_timeout(150)
            assert page.locator("#popup-pro-diagnostics.is-valid").is_visible()
            assert page.locator("#popup-pro-alert").is_visible()

            # 3. External chrome.storage.onChanged downgrade clears stale diagnostics & alert
            page.evaluate("() => window.chrome.storage.local.set({ promptveil_pro_license_v1: 'PV1.forged.sig' })")
            page.wait_for_timeout(150)
            assert page.locator("#popup-pro-badge").inner_text() == "Free"
            assert not page.locator("#popup-pro-diagnostics").is_visible()
            assert not page.locator("#popup-pro-alert").is_visible()

            # Zero localStorage usage in extension popup
            assert page.evaluate("() => localStorage.length") == 0
            assert dialogs == []
            assert page_errors == []
            assert page.evaluate("() => window.__cspV") == []
        finally:
            page.close()
            ctx.close()


def test_T5_51_extension_storage_tamper_downgrade_and_shadow_dom_sync(
    ephemeral_pro_keys: EphemeralProKeys,
    playwright_browser: Browser,
) -> None:
    """Bundled extension content.bundle.js Shadow DOM in Chromium: XSS inertness, zero <style>, and live storage tamper downgrade to Free."""
    from conftest import WORKSPACE_ROOT

    ext_dir = WORKSPACE_ROOT / "extension"
    prod_pub = "Fsb_LKEZCuhkazGVQd18WiV34EQmpUUkxR9-Rc20YCY"
    ephem_pub = ephemeral_pro_keys.public_key_b64u

    xss = "<img src=x onerror=alert(1)>"
    pro_tok = ephemeral_pro_keys.issue_token(tier="pro", key_id=f"PV-SHD-{xss}", label=f"Shadow {xss}")
    exp_tok = ephemeral_pro_keys.issue_token(tier="pro", key_id="PV-SHD-EXP", exp="2020-01-01T00:00:00.000Z")

    with _serve_extension_dir(ext_dir) as ext_url:
        ctx = playwright_browser.new_context(viewport={"width": 1280, "height": 800})
        page = ctx.new_page()
        dialogs: list[str] = []
        page_errors: list[str] = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.on("pageerror", lambda e: page_errors.append(str(e)))
        page.add_init_script(
            f"""(() => {{
                window.__cspV = [];
                document.addEventListener('securitypolicyviolation', e => window.__cspV.push(e.violatedDirective));
                const store = new Map([
                    ['promptveil_pro_license_v1', {json.dumps(pro_tok)}],
                    ['promptveil_ext_settings_v1', {{
                        lang: 'en',
                        theme: 'light',
                        overlayVisible: true,
                        sensitivity: 'normal',
                        disabledCategories: ['EMAIL'],
                        customRules: Array.from({{ length: 7 }}, (_, i) => ({{ id: 'r' + i, term: 'CustTerm' + i, category: 'CUSTOM', enabled: true }})),
                    }}],
                ]);
                const listeners = new Set();
                window.chrome = window.chrome || {{}};
                window.chrome.runtime = {{ id: 'pv-e2e-content' }};
                window.chrome.storage = {{
                    local: {{
                        get(keys, cb) {{
                            const list = Array.isArray(keys) ? keys : [keys];
                            const out = {{}};
                            for (const k of list) if (store.has(k)) out[k] = structuredClone(store.get(k));
                            if (cb) cb(out);
                            return Promise.resolve(out);
                        }},
                        set(items, cb) {{
                            const changes = {{}};
                            for (const [k, v] of Object.entries(items)) {{
                                const oldValue = store.has(k) ? structuredClone(store.get(k)) : undefined;
                                store.set(k, structuredClone(v));
                                changes[k] = {{ oldValue, newValue: structuredClone(v) }};
                            }}
                            if (cb) cb();
                            for (const fn of listeners) fn(changes, 'local');
                            return Promise.resolve();
                        }},
                    }},
                    onChanged: {{
                        addListener: fn => listeners.add(fn),
                        removeListener: fn => listeners.delete(fn),
                    }},
                }};
            }})();"""
        )

        def _patch_content_bundle(route: object) -> None:
            resp = route.fetch()  # type: ignore[attr-defined]
            body = resp.body().decode("utf-8", errors="replace").replace(prod_pub, ephem_pub)
            hdrs = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-length", "content-encoding")}
            route.fulfill(status=resp.status, headers=hdrs, body=body.encode("utf-8"))  # type: ignore[attr-defined]

        page.route("**/dist/content.bundle.js", _patch_content_bundle)
        page.route(
            "**/chat_sandbox.html",
            lambda r: r.fulfill(
                status=200,
                headers={
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'",
                },
                body="<!doctype html><html><head><meta charset='utf-8'></head><body><textarea id='chat-input'></textarea><script src='/dist/content.bundle.js'></script></body></html>",
            ),
        )
        page.route("**/favicon.ico", lambda r: r.fulfill(status=204, body=b""))
        try:
            page.goto(f"{ext_url}/chat_sandbox.html", wait_until="networkidle")
            page.wait_for_timeout(150)

            # 1. Valid Pro: disabledCategories=['EMAIL'] honored, all 7 custom rules active, zero <style> in Shadow DOM
            assert page.evaluate("() => document.getElementById('promptveil-ext-host').shadowRoot.querySelectorAll('style').length") == 0
            assert page.evaluate("() => document.getElementById('promptveil-ext-host').shadowRoot.querySelector('.pv-tier-chip').textContent") == "Pro Active"
            page.evaluate("() => document.getElementById('promptveil-ext-host').shadowRoot.querySelector('.pv-tier-chip').click()")
            toast_txt = page.evaluate("() => document.getElementById('promptveil-ext-host').shadowRoot.querySelector('.pv-toast').textContent")
            assert xss in toast_txt

            page.fill("#chat-input", "alice@example.com CustTerm6")
            page.evaluate("() => document.getElementById('promptveil-ext-host').shadowRoot.querySelector('[data-pv-action=\"sanitize\"]').click()")
            page.wait_for_timeout(100)
            san_pro = page.input_value("#chat-input")
            assert "alice@example.com" in san_pro and "[CUSTOM_1]" in san_pro

            # 2. Tamper storage -> forged, expired, and non-string downgrade to Free immediately
            for bad_val in ("PV1.forged.sig", exp_tok, {"isPro": True}):
                page.evaluate("v => window.chrome.storage.local.set({ promptveil_pro_license_v1: v })", bad_val)
                page.wait_for_timeout(120)
                assert page.evaluate("() => document.getElementById('promptveil-ext-host').shadowRoot.querySelector('.pv-tier-chip').textContent") == "Free"
                page.fill("#chat-input", "alice@example.com CustTerm6")
                page.evaluate("() => document.getElementById('promptveil-ext-host').shadowRoot.querySelector('[data-pv-action=\"sanitize\"]').click()")
                page.wait_for_timeout(100)
                san_free = page.input_value("#chat-input")
                assert "[EMAIL_" in san_free and "CustTerm6" in san_free

            assert page.evaluate("() => localStorage.length") == 0
            assert dialogs == []
            assert page_errors == []
            assert page.evaluate("() => window.__cspV") == []
        finally:
            page.close()
            ctx.close()


def test_T5_52_build_zip_exact_9_file_parity_and_dist_sw_integrity() -> None:
    """Build integrity: exact 9-file .zip byte-for-byte parity with extension/, zero unsafe/egress patterns in dist/, and sw.js/HTML precache parity."""
    from conftest import WORKSPACE_ROOT

    ext_dir = WORKSPACE_ROOT / "extension"
    zip_path = STATIC_APP_DIR / "downloads" / "promptveil-pro-extension.zip"
    assert zip_path.is_file()

    expected_runtime_files = sorted(
        [
            "manifest.json",
            "popup.html",
            "popup.css",
            "content.css",
            "dist/content.bundle.js",
            "dist/popup.bundle.js",
            "icons/icon-16.png",
            "icons/icon-48.png",
            "icons/icon-128.png",
        ]
    )

    with zipfile.ZipFile(zip_path, "r") as zf:
        assert zf.testzip() is None
        assert zf.namelist() == expected_runtime_files
        for info in zf.infolist():
            assert info.date_time == (2026, 1, 1, 0, 0, 0), f"Non-deterministic ZIP timestamp for {info.filename}: {info.date_time}"
            disk_bytes = (ext_dir / info.filename).read_bytes()
            zip_bytes = zf.read(info.filename)
            assert hashlib.sha256(zip_bytes).hexdigest() == hashlib.sha256(disk_bytes).hexdigest(), (
                f"Stale ZIP entry {info.filename}: run npm run build"
            )

    forbidden_js = (
        re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b"),
        re.compile(r"\beval\s*\("),
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(r"\bfetch\s*\("),
        re.compile(r"\bXMLHttpRequest\b"),
        re.compile(r"\bsendBeacon\b"),
        re.compile(r"\bnew\s+WebSocket\s*\("),
        re.compile(r"\bEventSource\b"),
        re.compile(r"BEGIN PRIVATE KEY"),
        re.compile(r"PV-CLIENT-"),
        re.compile(r"PV1\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}"),
    )
    for bundle_name in ("dist/content.bundle.js", "dist/popup.bundle.js"):
        src = (ext_dir / bundle_name).read_text(encoding="utf-8")
        assert re.search(r"\blocalStorage\b", src) is None, f"localStorage leaked into {bundle_name}"
        for pat in forbidden_js:
            assert pat.search(src) is None, f"{bundle_name} matched forbidden pattern {pat.pattern}"

    dist_dir = STATIC_APP_DIR / "dist"
    dist_files = sorted(p.name for p in dist_dir.iterdir() if p.is_file())
    for fname in dist_files:
        if fname.endswith(".js"):
            src = (dist_dir / fname).read_text(encoding="utf-8")
            for pat in forbidden_js:
                assert pat.search(src) is None, f"dist/{fname} matched forbidden pattern {pat.pattern}"

    sw_src = (STATIC_APP_DIR / "sw.js").read_text(encoding="utf-8")
    m = re.search(r"const PRECACHE_URLS = (\[[\s\S]*?\]);", sw_src)
    assert m is not None
    precache_urls = json.loads(m.group(1))
    assert "/pro/" in precache_urls and "/en/pro/" in precache_urls
    assert "/downloads/promptveil-pro-extension.zip" not in precache_urls
    sw_dist = sorted(u[len("/dist/"):] for u in precache_urls if u.startswith("/dist/"))
    assert sw_dist == dist_files

    for html_rel in ("index.html", "en/index.html", "pro/index.html", "en/pro/index.html", "404.html"):
        html = (STATIC_APP_DIR / html_rel).read_text(encoding="utf-8")
        refs = re.findall(r"/dist/([A-Za-z0-9_.-]+)", html)
        assert refs, f"Missing /dist/ reference in {html_rel}"
        for ref in refs:
            assert ref in dist_files, f"Stale /dist/{ref} in {html_rel}"


def test_T5_53_pro_checkout_xss_pvkey_boundaries_and_zip_download_parity(
    pro_raw_session: E2ESession,
    ephemeral_pro_keys: EphemeralProKeys,
) -> None:
    """/pro/ checkout adversarial: XSS inertness in buyer/token claims, .pvkey size/NUL/UTF-8 boundaries, #code= non-egress, and downloaded .zip SHA-256 parity."""
    page = pro_raw_session.page
    ui = pro_raw_session.ui
    base = pro_raw_session.base_url.rstrip("/")

    dialogs: list[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    xss = "<img src=x onerror=alert(1)>"
    tok = ephemeral_pro_keys.issue_token(tier="pro", key_id=f"PV-CHK-{xss}", label=f"Chk {xss}")

    page.goto(f"{base}/pro/#code={tok}", wait_until="networkidle")
    pro_raw_session.net.assert_clean_load()
    pro_raw_session.net.start_interactive_phase()
    page.wait_for_timeout(150)

    # Buyer order receipt XSS inertness
    ui.fill_checkout_buyer(name=f"Иван {xss}", email="ivan.t553@example.ru", company=f"ООО {xss}", accept_terms=True)
    ui.submit_checkout_order()
    assert xss in page.locator("#checkout-order-panel").inner_text()

    # .pvkey boundary uploads in checkout terminal
    over_file = pro_raw_session.io.uploads / "chk_over.pvkey"
    over_file.write_bytes(b"#" * (256 * 1024 + 1))
    page.set_input_files("#checkout-pvkey-file-input", str(over_file))
    page.wait_for_timeout(120)
    assert page.locator("#checkout-token-diagnostics.is-error").is_visible()

    bad_utf8 = pro_raw_session.io.uploads / "chk_bad_utf8.pvkey"
    bad_utf8.write_bytes(b"\xff\xfe\xfd" + tok.encode("utf-8"))
    page.set_input_files("#checkout-pvkey-file-input", str(bad_utf8))
    page.wait_for_timeout(120)
    assert page.locator("#checkout-token-diagnostics.is-error").is_visible()

    bom_file = pro_raw_session.io.uploads / "chk_bom.pvkey"
    bom_file.write_bytes(b"\xef\xbb\xbf# BOM\n" + tok.encode("utf-8"))
    page.set_input_files("#checkout-pvkey-file-input", str(bom_file))
    page.wait_for_timeout(120)
    assert page.locator("#checkout-token-diagnostics.is-valid").is_visible()

    ui.activate_checkout_token()
    assert ui.get_checkout_unlocked_panel().is_visible()

    dl_zip = ui.download_checkout_extension_zip(pro_raw_session.io.downloads)
    disk_zip = STATIC_APP_DIR / "downloads" / "promptveil-pro-extension.zip"
    assert hashlib.sha256(dl_zip.read_bytes()).hexdigest() == hashlib.sha256(disk_zip.read_bytes()).hexdigest()

    assert dialogs == []
    for req in pro_raw_session.net.requests:
        assert "#code=" not in req.url
    pro_raw_session.net.assert_zero_egress([tok, "ivan.t553@example.ru"])
    pro_raw_session.console.assert_no_errors()



