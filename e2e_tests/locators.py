"""Opaque-box contract-first UI locator adapter for PromptVeil E2E tests.

Resolves controls via:
1. Stable `data-testid` hooks from PROJECT.md § Interface Contracts § 1
2. Bilingual (RU | EN) ARIA role / accessible name / label / placeholder
3. Structural HTML fallback

Strictly scoped by active mode (Sanitize / Re-Hydrate) and open drawer
(Rulebook / «Свои слова» and Audit / «Журнал проверок»).
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from playwright.sync_api import Download, Locator, Page


ModeType = Literal["sanitize", "rehydrate"]
LangType = Literal["ru", "en"]


class LocatorLookupError(AssertionError):
    """Raised when a UI control cannot be resolved, with DOM diagnostics."""


@dataclass(frozen=True)
class VaultRowInfo:
    """Observed row in the Entity Vault / Replacement List («Что скрыто»)."""

    token: str
    category: str
    raw_text: str
    enabled: bool
    row_locator: Locator


_CATEGORY_ALIASES: dict[str, list[str]] = {
    "API_KEY": ["API_KEY", "API KEY", "API KEYS", "КЛЮЧИ API", "API-КЛЮЧИ"],
    "JWT": ["JWT", "JWTS", "ТОКЕНЫ ВХОДА", "JWT-ТОКЕНЫ"],
    "CREDIT_CARD": ["CREDIT_CARD", "CREDIT CARD", "CARD", "CARDS", "БАНК. КАРТЫ", "КАРТЫ"],
    "IBAN": ["IBAN", "IBANS", "СЧЕТА (IBAN)", "СЧЕТА IBAN"],
    "SSN": ["SSN", "SSNS", "SSN (США)"],
    "ENV_SECRET": ["ENV_SECRET", "ENV SECRET", "ENV", ".ENV", "ПАРОЛИ (.ENV)", "СЕКРЕТЫ .ENV"],
    "CUSTOM": ["CUSTOM", "CUSTOM RULE", "CUSTOM RULES", "СВОИ СЛОВА"],
    "EMAIL": ["EMAIL", "EMAILS", "ПОЧТА", "E-MAIL"],
    "PHONE": ["PHONE", "PHONES", "ТЕЛЕФОНЫ", "ТЕЛЕФОН"],
    "IPV4": ["IPV4", "IP", "IP ADDRESS", "IP-АДРЕСА"],
    "HIGH_ENTROPY": [
        "HIGH_ENTROPY",
        "HIGH ENTROPY",
        "HIGH-ENTROPY",
        "SECRET",
        "SECRETS",
        "ENTROPY",
        "СЕКРЕТНЫЕ СТРОКИ",
        "СЛУЧАЙНЫЕ КЛЮЧИ",
    ],
}

_PRESET_ALIASES: dict[str, list[str]] = {
    "client_contract": [
        "client_contract",
        "client nda",
        "service agreement",
        "contract",
        "договор",
        "контракт",
    ],
    "prod_env_trace": [
        "prod_env_trace",
        "production .env",
        "stacktrace",
        "prod env",
        "лог",
        "ошибка",
    ],
    "bilingual_cis_hr": [
        "bilingual_cis_hr",
        "bilingual",
        "ru/cis",
        "ru-cis",
        "cis hr",
        "резюме",
        "кандидат",
    ],
}


class PromptVeilUI:
    """Opaque-box Page Object adapter for PromptVeil."""

    def __init__(self, page: Page, timeout_ms: int = 5000) -> None:
        self.page = page
        self.timeout_ms = timeout_ms
        self._active_mode: ModeType = "sanitize"

    def dump_diagnostics(self, reason: str) -> str:
        """Capture structured visible interactive DOM elements (including data-testid and lang)."""
        try:
            snapshot: dict[str, Any] = self.page.evaluate(
                """() => {
                    const els = Array.from(document.querySelectorAll(
                        '[data-testid], button, [role="button"], [role="tab"], [role="switch"], ' +
                        'a, input, textarea, select, [role="dialog"], dialog, aside, ' +
                        'table, [role="table"], [aria-live], pre, code, h1, h2, h3'
                    ));
                    const seen = new Set();
                    const unique = [];
                    for (const el of els) {
                        if (!seen.has(el)) {
                            seen.add(el);
                            unique.push(el);
                        }
                    }
                    const items = unique.slice(0, 100).map((el) => {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        const visible = rect.width > 0 && rect.height > 0 &&
                            style.visibility !== 'hidden' && style.display !== 'none';
                        return {
                            tag: el.tagName.toLowerCase(),
                            testid: el.getAttribute('data-testid') || '',
                            role: el.getAttribute('role') || '',
                            type: el.getAttribute('type') || '',
                            text: (el.textContent || '').trim().slice(0, 60),
                            placeholder: el.getAttribute('placeholder') || '',
                            ariaLabel: el.getAttribute('aria-label') || '',
                            title: el.getAttribute('title') || '',
                            disabled: Boolean(el.disabled || el.getAttribute('aria-disabled') === 'true'),
                            visible: visible
                        };
                    });
                    return {
                        url: window.location.href,
                        lang: document.documentElement.lang || '',
                        title: document.title,
                        innerWidth: window.innerWidth,
                        scrollWidth: document.documentElement.scrollWidth,
                        elements: items
                    };
                }"""
            )
        except Exception as exc:  # noqa: BLE001
            snapshot = {"diagnostic_error": str(exc)}
        return f"{reason}\nDOM Snapshot:\n{json.dumps(snapshot, ensure_ascii=False, indent=2)}"

    def _first_visible(self, candidates: list[Locator], description: str) -> Locator:
        """Return the first candidate locator resolving to a visible element."""
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible():
                        return item
                except Exception:  # noqa: BLE001
                    continue
        raise LocatorLookupError(self.dump_diagnostics(f"Could not find visible element: {description}"))

    def _first_attached(self, candidates: list[Locator], description: str) -> Locator:
        """Return the first candidate locator attached in DOM (for hidden file inputs)."""
        for loc in candidates:
            try:
                if loc.count() > 0:
                    return loc.first
            except Exception:  # noqa: BLE001
                continue
        raise LocatorLookupError(self.dump_diagnostics(f"Could not find attached element: {description}"))

    @staticmethod
    def _read_element_text(loc: Locator) -> str:
        """Read value from textarea/input or textContent from non-form containers."""
        tag = loc.evaluate("el => el.tagName.toLowerCase()")
        if tag in ("textarea", "input"):
            return str(loc.input_value())
        return str(
            loc.evaluate(
                """el => {
                    const emptySel = '.empty-placeholder, .empty-state, [data-empty-placeholder], [data-empty]';
                    const placeholders = el.querySelectorAll(emptySel);
                    if (!placeholders.length) {
                        return el.textContent || '';
                    }
                    const clone = el.cloneNode(true);
                    clone.querySelectorAll(emptySel).forEach(p => p.remove());
                    const remaining = clone.textContent || '';
                    return remaining.trim() === '' ? '' : remaining;
                }"""
            )
        )

    @staticmethod
    def _set_textarea_with_events(loc: Locator, text: str) -> None:
        """Fill textarea/input and explicitly dispatch input + change events."""
        loc.fill(text)
        loc.evaluate(
            """el => {
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            }"""
        )

    # -----------------------------------------------------------------------
    # Header, Language, Value Prop & Mode Switching
    # -----------------------------------------------------------------------

    def get_zero_egress_pill(self) -> Locator:
        """Locate the top-rail Zero-Retention privacy badge / trigger."""
        pattern = re.compile(
            r"(гарантия\s*0\s*хранения|zero[- ]retention|только\s+в\s+браузере|100%\s*BROWSER[- ]LOCAL|ZERO[- ]EGRESS|CLIENT[- ]SIDE)",
            re.I,
        )
        candidates = [
            self.page.locator("[data-testid='brand-badge']"),
            self.page.locator("[data-testid='zero-egress-badge']"),
            self.page.locator("header, [role='banner']").get_by_text(pattern),
            self.page.get_by_text(pattern),
        ]
        return self._first_visible(candidates, "Zero-Retention badge ([data-testid='brand-badge'])")

    def switch_language(self, lang: LangType) -> None:
        """Switch UI language via [data-testid='lang-ru'] or [data-testid='lang-en']."""
        testid = f"lang-{lang}"
        label_pat = re.compile(r"^\s*RU\s*$|рус", re.I) if lang == "ru" else re.compile(r"^\s*EN\s*$|eng", re.I)
        candidates = [
            self.page.locator(f"[data-testid='{testid}']"),
            self.page.locator("[data-testid='lang-switch']").get_by_role("button", name=label_pat),
            self.page.locator("header, nav").get_by_role("button", name=label_pat),
        ]
        btn = self._first_visible(candidates, f"Language toggle '{lang}'")
        btn.click()
        self.page.wait_for_timeout(120)

    def get_document_lang(self) -> str:
        """Return document.documentElement.lang."""
        return str(self.page.evaluate("() => document.documentElement.lang || ''"))

    def get_stored_language(self) -> str | None:
        """Return localStorage['promptveil_lang_v1'] value if set."""
        val = self.page.evaluate("() => localStorage.getItem('promptveil_lang_v1')")
        return None if val is None else str(val)

    def get_hero_summary_text(self) -> str:
        """Return visible text from [data-testid='hero-summary']."""
        loc = self._first_visible(
            [
                self.page.locator("[data-testid='hero-summary']"),
                self.page.locator("main h1, [role='region'] h1").locator(".."),
            ],
            "Hero summary ([data-testid='hero-summary'])",
        )
        return (loc.inner_text() or "").strip()

    def switch_mode(self, mode: ModeType) -> None:
        """Switch between 'sanitize' and 'rehydrate' workbench modes."""
        if mode == "sanitize":
            testid = "mode-sanitize"
            pattern = re.compile(
                r"^(?:1[.)\s-]*)?(?:скрыть(?:\s+данные)?|sanitize(?:\s+prompt)?)(?:\s*\([^)]*\))?$",
                re.I,
            )
            fallback_attr = "[data-mode='sanitize'], [aria-controls*='sanitize' i]"
        else:
            testid = "mode-rehydrate"
            pattern = re.compile(
                r"^(?:2[.)\s-]*)?(?:вернуть(?:\s+в\s+ответ(?:\s+ии)?)?|восстановить|re-?hydrate(?:\s+reply)?)(?:\s*\([^)]*\))?$",
                re.I,
            )
            fallback_attr = "[data-mode='rehydrate'], [aria-controls*='rehydrate' i]"

        scope = self.page.locator("header, nav, [role='tablist'], [role='banner']")
        candidates = [
            self.page.locator(f"[data-testid='{testid}']"),
            scope.get_by_role("tab", name=pattern),
            scope.get_by_role("button", name=pattern),
            self.page.get_by_role("tab", name=pattern),
            scope.locator("button, [role='tab'], label").filter(has_text=pattern),
            self.page.locator(fallback_attr),
        ]
        btn = self._first_visible(candidates, f"Mode switch '{mode}'")
        btn.click()
        self._active_mode = mode
        self.page.wait_for_timeout(120)

    def click_go_rehydrate(self) -> None:
        """Click the Step 1 -> Step 2 CTA button ([data-testid='go-rehydrate-btn'])."""
        btn = self._first_visible(
            [
                self.page.locator("[data-testid='go-rehydrate-btn']"),
                self.page.locator("main").get_by_role(
                    "button",
                    name=re.compile(r"вернуть\s+в\s+ответ|шаг\s*2|re-?hydrate", re.I),
                ),
            ],
            "Go to Step 2 button ([data-testid='go-rehydrate-btn'])",
        )
        btn.click()
        self._active_mode = "rehydrate"
        self.page.wait_for_timeout(120)

    def click_back_sanitize(self) -> None:
        """Click the Step 2 -> Step 1 back button ([data-testid='back-sanitize-btn'])."""
        btn = self._first_visible(
            [
                self.page.locator("[data-testid='back-sanitize-btn']"),
                self.page.locator("main").get_by_role(
                    "button",
                    name=re.compile(r"назад|шаг\s*1|скрыть\s+данные|back", re.I),
                ),
            ],
            "Back to Step 1 button ([data-testid='back-sanitize-btn'])",
        )
        btn.click()
        self._active_mode = "sanitize"
        self.page.wait_for_timeout(120)

    # -----------------------------------------------------------------------
    # Step 1 (Sanitize) & Step 2 (Re-Hydrate) Inputs / Outputs / Actions
    # -----------------------------------------------------------------------

    @staticmethod
    def _is_editable_workbench_control(item: Locator) -> bool:
        """Return True iff item is an enabled editable input outside any dialog/drawer."""
        return bool(
            item.evaluate(
                """el => {
                    const tag = el.tagName.toLowerCase();
                    const type = (el.getAttribute('type') || '').toLowerCase();
                    const ce = (el.getAttribute('contenteditable') || '').toLowerCase();
                    const isCtrl = (
                        tag === 'textarea' ||
                        (tag === 'input' && !['file', 'checkbox', 'radio', 'hidden', 'button', 'submit', 'reset'].includes(type)) ||
                        ce === 'true' || ce === 'plaintext-only'
                    );
                    if (!isCtrl) return false;
                    if (el.readOnly || el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
                    return !Boolean(el.closest('[role="dialog"], dialog'));
                }"""
            )
        )

    def get_prompt_input(self) -> Locator:
        """Locate editable Step 1 prompt textarea."""
        label_pat = re.compile(
            r"исходн|текст|вставьте|prompt|source|raw|input|paste",
            re.I,
        )
        editable_fallback = (
            "textarea:not([readonly]):not([disabled]), "
            "input:not([type='file']):not([type='checkbox']):not([type='radio']):not([readonly]):not([disabled]), "
            "[contenteditable='true']"
        )
        candidates = [
            self.page.locator("[data-testid='raw-prompt-input']"),
            self.page.locator("main").get_by_role("textbox", name=label_pat),
            self.page.locator("main").get_by_label(label_pat),
            self.page.locator("main").get_by_placeholder(label_pat),
            self.page.locator("main").locator(editable_fallback),
            self.page.locator(editable_fallback),
        ]
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible() and self._is_editable_workbench_control(item):
                        return item
                except Exception:  # noqa: BLE001
                    continue
        raise LocatorLookupError(self.dump_diagnostics("Sanitize prompt textarea not found"))

    def _find_output_container(
        self,
        candidates: list[Locator],
        input_loc: Locator,
        description: str,
    ) -> Locator:
        """Resolve an output container, drilling down inside landmark/section wrappers."""
        input_handle = input_loc.element_handle()
        inner_tiers = [
            "textarea[readonly], [data-output]",
            "[aria-live]:not([role='status']):not([role='alert'])",
            "pre, code",
        ]
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if not item.is_visible():
                        continue
                    is_invalid = item.evaluate(
                        """(el, inp) => {
                            const tag = el.tagName.toLowerCase();
                            const role = (el.getAttribute('role') || '').toLowerCase();
                            if (tag === 'button' || tag === 'a' || role === 'button' || role === 'status' || role === 'alert') {
                                return true;
                            }
                            if (el.closest('[role="dialog"], dialog, [role="status"], [role="alert"]')) return true;
                            if (el === inp) return true;
                            return false;
                        }""",
                        input_handle,
                    )
                    if is_invalid:
                        continue
                    is_wrapper = item.evaluate(
                        """el => {
                            if (el.hasAttribute('data-testid') && (
                                el.getAttribute('data-testid') === 'sanitized-output' ||
                                el.getAttribute('data-testid') === 'restored-output'
                            )) {
                                return false;
                            }
                            const tag = el.tagName.toLowerCase();
                            if (['section', 'article', 'aside', 'main', 'form', 'fieldset'].includes(tag)) {
                                return true;
                            }
                            return Boolean(el.querySelector(
                                "h1, h2, h3, h4, h5, h6, button, [role='button'], textarea, [aria-live]"
                            ));
                        }"""
                    )
                    if is_wrapper:
                        for inner_sel in inner_tiers:
                            inner_loc = item.locator(inner_sel)
                            inner_count = inner_loc.count()
                            for j in range(inner_count):
                                inner = inner_loc.nth(j)
                                try:
                                    if not inner.is_visible():
                                        continue
                                    inner_invalid = inner.evaluate(
                                        """(el, inp) => {
                                            const tag = el.tagName.toLowerCase();
                                            const role = (el.getAttribute('role') || '').toLowerCase();
                                            if (tag === 'button' || tag === 'a' || role === 'button' || role === 'status' || role === 'alert') {
                                                return true;
                                            }
                                            if (el.closest('[role="dialog"], dialog, [role="status"], [role="alert"]')) return true;
                                            if (el === inp) return true;
                                            return false;
                                        }""",
                                        input_handle,
                                    )
                                    if not inner_invalid:
                                        return inner
                                except Exception:  # noqa: BLE001
                                    continue
                        continue
                    return item
                except Exception:  # noqa: BLE001
                    continue
        raise LocatorLookupError(self.dump_diagnostics(description))

    def get_sanitize_output(self) -> Locator:
        """Locate Step 1 masked output container."""
        direct = self.page.locator("[data-testid='sanitized-output']")
        try:
            if direct.count() > 0 and direct.first.is_visible():
                return direct.first
        except Exception:  # noqa: BLE001
            pass

        input_loc = self.get_prompt_input()
        label_pat = re.compile(r"безопасн|скрыт|результат|sanitized|masked|output|redacted|result", re.I)
        candidates = [
            self.page.locator("main").get_by_label(label_pat),
            self.page.locator("main [aria-label*='sanitiz' i]:not(button):not([role='button'])"),
            self.page.locator("main [aria-label*='masked' i]:not(button):not([role='button'])"),
            self.page.locator("main [aria-label*='output' i]:not(button):not([role='button'])"),
            self.page.locator("main textarea[readonly]"),
            self.page.locator("main [data-output]"),
            self.page.locator("main [aria-live]:not([role='status']):not([role='alert'])"),
            self.page.locator("main pre"),
            self.page.locator("main code"),
            self.page.locator("textarea[readonly]"),
            self.page.locator("[data-output]"),
            self.page.locator("[aria-live]:not([role='status']):not([role='alert'])"),
        ]
        return self._find_output_container(
            candidates, input_loc, "Sanitize output container not found"
        )

    def get_sanitize_output_text(self) -> str:
        """Return masked text from Step 1 output pane."""
        return self._read_element_text(self.get_sanitize_output())

    def get_sanitized_token_pills(self) -> list[str]:
        """Return text of <mark data-token='...'> pills in sanitized output."""
        out = self.get_sanitize_output()
        marks = out.locator("mark[data-token], mark")
        pills: list[str] = []
        for idx in range(marks.count()):
            item = marks.nth(idx)
            tok = item.get_attribute("data-token") or (item.inner_text() or "").strip()
            if tok:
                pills.append(tok)
        return pills

    def _find_action_button(
        self,
        pattern: re.Pattern[str],
        testid: str | None = None,
    ) -> Locator | None:
        """Find an explicit action button inside <main> by data-testid or text pattern."""
        candidates: list[Locator] = []
        if testid:
            candidates.append(self.page.locator(f"[data-testid='{testid}']"))
        candidates.extend(
            [
                self.page.locator("main").get_by_role("button", name=pattern),
                self.page.locator("main button").filter(has_text=pattern),
            ]
        )
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible() and item.is_enabled():
                        in_dialog = item.evaluate("el => Boolean(el.closest('[role=\"dialog\"], dialog'))")
                        if not in_dialog:
                            return item
                except Exception:  # noqa: BLE001
                    continue
        return None

    def _wait_for_output_or_click(
        self,
        read_fn: Any,
        previous_text: str,
        button_pattern: re.Pattern[str],
        expect_non_empty: bool,
        wait_ms: int,
        force_click: bool = False,
        button_testid: str | None = None,
    ) -> str:
        """Support both debounced auto-scan and explicit action button."""
        btn = self._find_action_button(button_pattern, testid=button_testid)
        if force_click and btn is not None:
            btn.click()
            self.page.wait_for_timeout(160)
            return str(read_fn())

        deadline = time.monotonic() + (wait_ms / 1000.0)
        current = read_fn()
        while time.monotonic() < deadline:
            current = read_fn()
            if expect_non_empty:
                if current.strip() and current != previous_text:
                    break
            elif not current.strip():
                break
            self.page.wait_for_timeout(40)

        btn = self._find_action_button(button_pattern, testid=button_testid)
        if btn is not None:
            if expect_non_empty and (not current.strip() or current == previous_text):
                btn.click()
                self.page.wait_for_timeout(160)
                current = read_fn()
            elif not expect_non_empty and current.strip():
                btn.click()
                self.page.wait_for_timeout(160)
                current = read_fn()
        elif expect_non_empty and not current.strip():
            self.page.wait_for_timeout(200)
            current = read_fn()
        return str(current)

    def sanitize_text(self, text: str, wait_ms: int = 450) -> str:
        """Switch to Step 1 if needed, enter text, trigger scan, return output."""
        if self._active_mode != "sanitize":
            self.switch_mode("sanitize")
        inp = self.get_prompt_input()
        prev_out = self.get_sanitize_output_text()
        self._set_textarea_with_events(inp, text)
        out = self._wait_for_output_or_click(
            self.get_sanitize_output_text,
            prev_out,
            re.compile(r"проверить|скрыть|маскир|sanitize|scan|mask|redact", re.I),
            expect_non_empty=bool(text.strip()),
            wait_ms=wait_ms,
            force_click=bool(text.strip()),
            button_testid="sanitize-now-btn",
        )
        # Allow async Web Crypto SHA-256 audit receipt write to settle.
        self.page.wait_for_timeout(120)
        return out

    def set_auto_sanitize(self, enabled: bool) -> None:
        """Check or uncheck [data-testid='auto-sanitize-toggle']."""
        cb = self._first_visible(
            [
                self.page.locator("[data-testid='auto-sanitize-toggle']"),
                self.page.locator("main").get_by_label(
                    re.compile(r"автоматическ|live\s+auto-?sanitize|auto-?sanitize", re.I)
                ),
            ],
            "Auto-sanitize toggle ([data-testid='auto-sanitize-toggle'])",
        )
        if enabled:
            cb.check()
        else:
            cb.uncheck()
        self.page.wait_for_timeout(80)

    def click_clear_input(self) -> None:
        """Click [data-testid='clear-input-btn'] in Step 1 (or fallback clear button)."""
        btn = self._first_visible(
            [
                self.page.locator("[data-testid='clear-input-btn']"),
                self.page.locator("main").get_by_role(
                    "button",
                    name=re.compile(r"^(?:очистить|сбросить|clear)$", re.I),
                ),
            ],
            "Clear input button ([data-testid='clear-input-btn'])",
        )
        if btn.is_disabled() and self.get_prompt_input().input_value() == "":
            return
        btn.click()
        self.page.wait_for_timeout(120)

    def get_rehydrate_input(self) -> Locator:
        """Locate editable Step 2 LLM reply textarea."""
        label_pat = re.compile(
            r"ответ\s+ии|вставьте\s+ответ|reply|re-?hydrate|\bmasked\b|llm|paste",
            re.I,
        )
        editable_fallback = (
            "textarea:not([readonly]):not([disabled]), "
            "input:not([type='file']):not([type='checkbox']):not([type='radio']):not([readonly]):not([disabled]), "
            "[contenteditable='true']"
        )
        candidates = [
            self.page.locator("[data-testid='llm-reply-input']"),
            self.page.locator("main").get_by_role("textbox", name=label_pat),
            self.page.locator("main").get_by_label(label_pat),
            self.page.locator("main").get_by_placeholder(label_pat),
            self.page.locator("main").locator(editable_fallback),
            self.page.locator(editable_fallback),
        ]
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible() and self._is_editable_workbench_control(item):
                        return item
                except Exception:  # noqa: BLE001
                    continue
        raise LocatorLookupError(self.dump_diagnostics("Re-Hydrate input textarea not found"))

    def get_rehydrate_output(self) -> Locator:
        """Locate Step 2 restored output container."""
        direct = self.page.locator("[data-testid='restored-output']")
        try:
            if direct.count() > 0 and direct.first.is_visible():
                return direct.first
        except Exception:  # noqa: BLE001
            pass

        input_loc = self.get_rehydrate_input()
        label_pat = re.compile(r"восстанов|готов|результат|restored|re-?hydrated|output|plain|result", re.I)
        candidates = [
            self.page.locator("main").get_by_label(label_pat),
            self.page.locator("main [aria-label*='restor' i]:not(button):not([role='button'])"),
            self.page.locator("main [aria-label*='rehydrat' i]:not(button):not([role='button'])"),
            self.page.locator("main [aria-label*='output' i]:not(button):not([role='button'])"),
            self.page.locator("main textarea[readonly]"),
            self.page.locator("main [data-output]"),
            self.page.locator("main [aria-live]:not([role='status']):not([role='alert'])"),
            self.page.locator("main pre"),
            self.page.locator("main code"),
            self.page.locator("textarea[readonly]"),
            self.page.locator("[data-output]"),
            self.page.locator("[aria-live]:not([role='status']):not([role='alert'])"),
        ]
        return self._find_output_container(
            candidates, input_loc, "Re-Hydrate output container not found"
        )

    def get_rehydrate_output_text(self) -> str:
        """Return restored text from Step 2 output pane."""
        return self._read_element_text(self.get_rehydrate_output())

    def get_restored_token_pills(self) -> list[str]:
        """Return text of <mark class='restored-token'> pills in restored output."""
        out = self.get_rehydrate_output()
        marks = out.locator("mark.restored-token, mark")
        pills: list[str] = []
        for idx in range(marks.count()):
            txt = (marks.nth(idx).inner_text() or "").strip()
            if txt:
                pills.append(txt)
        return pills

    def rehydrate_text(self, reply_text: str, wait_ms: int = 450) -> str:
        """Switch to Step 2, enter reply, trigger restore, return restored text."""
        if self._active_mode != "rehydrate":
            self.switch_mode("rehydrate")
        inp = self.get_rehydrate_input()
        prev_out = self.get_rehydrate_output_text()
        self._set_textarea_with_events(inp, reply_text)
        out = self._wait_for_output_or_click(
            self.get_rehydrate_output_text,
            prev_out,
            re.compile(r"вернуть|восстанов|подстав|re-?hydrate|restore|unmask", re.I),
            expect_non_empty=bool(reply_text.strip()),
            wait_ms=wait_ms,
            button_testid="rehydrate-now-btn",
        )
        self.page.wait_for_timeout(120)
        return out

    def get_unresolved_tokens(self) -> list[str]:
        """Inspect Step 2 unresolved token banner ([data-testid='unresolved-warning']) and extract tokens."""
        direct = self.page.locator("[data-testid='unresolved-warning'], [data-testid='unresolved-tokens-banner']")
        found: list[str] = []
        for idx in range(direct.count()):
            item = direct.nth(idx)
            try:
                if item.is_visible():
                    text = str(item.evaluate("el => el.textContent || ''"))
                    for tok in re.findall(r"\[[A-Z_]+_\d+\]", text):
                        if tok not in found:
                            found.append(tok)
            except Exception:  # noqa: BLE001
                continue
        if found:
            return found

        banner_candidates = [
            self.page.locator("main").get_by_text(re.compile(r"не\s+найден|нераспознан|unresolved", re.I)),
            self.page.locator("[data-unresolved], [aria-label*='unresolved' i]"),
        ]
        for loc in banner_candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible():
                        text = str(item.evaluate("el => el.textContent || ''"))
                        if not re.search(r"\[[A-Z_]+_\d+\]", text):
                            text = str(
                                item.evaluate(
                                    "el => (el.parentElement ? el.parentElement.textContent : el.textContent) || ''"
                                )
                            )
                        for tok in re.findall(r"\[[A-Z_]+_\d+\]", text):
                            if tok not in found:
                                found.append(tok)
                except Exception:  # noqa: BLE001
                    continue
        return found

    # -----------------------------------------------------------------------
    # Presets
    # -----------------------------------------------------------------------

    def select_preset(self, preset_key: str) -> None:
        """Select a built-in preset by key ([data-testid='preset-btn-{key}']) or <select> fallback."""
        if self._active_mode != "sanitize":
            self.switch_mode("sanitize")

        # Tier 1: Contract preset pill button
        btn_candidates = [
            self.page.locator(f"[data-testid='preset-bar'] [data-testid='preset-btn-{preset_key}']"),
            self.page.locator(f"[data-testid='preset-btn-{preset_key}']"),
        ]
        clicked = False
        for loc in btn_candidates:
            try:
                if loc.count() > 0 and loc.first.is_visible():
                    loc.first.click()
                    clicked = True
                    break
            except Exception:  # noqa: BLE001
                continue

        if not clicked:
            aliases = _PRESET_ALIASES.get(preset_key, [preset_key])
            select_candidates = [
                self.page.get_by_role("combobox", name=re.compile(r"пример|сценари|preset|scenario|sample", re.I)),
                self.page.get_by_label(re.compile(r"пример|сценари|preset|scenario|sample", re.I)),
                self.page.locator("select"),
            ]

            select_loc: Locator | None = None
            for loc in select_candidates:
                try:
                    count = loc.count()
                except Exception:  # noqa: BLE001
                    continue
                for idx in range(count):
                    item = loc.nth(idx)
                    try:
                        if item.is_visible() and item.evaluate("el => el.tagName.toLowerCase() === 'select'"):
                            select_loc = item
                            break
                    except Exception:  # noqa: BLE001
                        continue
                if select_loc is not None:
                    break

            if select_loc is not None:
                options: list[dict[str, str]] = select_loc.evaluate(
                    """sel => Array.from(sel.options).map(o => ({
                        value: o.value,
                        text: (o.textContent || '').trim()
                    }))"""
                )
                chosen_value: str | None = None
                for opt in options:
                    val_low = opt["value"].lower()
                    txt_low = opt["text"].lower()
                    for alias in aliases:
                        a_low = alias.lower()
                        if val_low == a_low or a_low in val_low or a_low in txt_low:
                            chosen_value = opt["value"]
                            break
                    if chosen_value is not None:
                        break
                if chosen_value is None:
                    raise LocatorLookupError(
                        self.dump_diagnostics(f"Preset option '{preset_key}' not found in <select> options={options}")
                    )
                current_val = select_loc.input_value()
                if current_val == chosen_value:
                    empty_opts = [o["value"] for o in options if not o["value"]]
                    if empty_opts:
                        select_loc.select_option(empty_opts[0])
                        self.page.wait_for_timeout(50)
                select_loc.select_option(chosen_value)
                select_loc.evaluate(
                    "el => el.dispatchEvent(new Event('change', { bubbles: true }))"
                )
            else:
                btn_pat = re.compile("|".join(re.escape(a) for a in aliases), re.I)
                btn = self._first_visible(
                    [
                        self.page.locator("[data-testid='preset-bar'] button").filter(has_text=btn_pat),
                        self.page.get_by_role("button", name=btn_pat),
                        self.page.locator("button").filter(has_text=btn_pat),
                    ],
                    f"Preset button '{preset_key}'",
                )
                btn.click()

        self.page.wait_for_timeout(150)
        load_btn = self._find_action_button(re.compile(r"загрузить\s*пример|load\s*preset|apply\s*preset", re.I))
        if load_btn is not None and not self.get_prompt_input().input_value().strip():
            load_btn.click()
            self.page.wait_for_timeout(150)

        # Ensure sanitize output updates if explicit button exists
        if not self.get_sanitize_output_text().strip():
            san_btn = self._find_action_button(
                re.compile(r"проверить|скрыть|sanitize|scan|mask", re.I),
                testid="sanitize-now-btn",
            )
            if san_btn is not None:
                san_btn.click()
                self.page.wait_for_timeout(150)

    def apply_preset_suggested_rules(self) -> bool:
        """Click [data-testid='apply-preset-rules-btn'] if visible; return True if clicked."""
        btn = self._find_action_button(
            re.compile(r"скрыть\s+(?:имена|слова|компани)|добавить\s+в\s+свои|apply\s+preset\s+rules", re.I),
            testid="apply-preset-rules-btn",
        )
        if btn is None:
            return False
        btn.click()
        self.page.wait_for_timeout(150)
        return True

    # -----------------------------------------------------------------------
    # Category Filter Chips & Entity Vault / Replacement List («Что скрыто»)
    # -----------------------------------------------------------------------

    def _expand_all_categories_if_needed(self, cat_upper: str) -> None:
        """If [data-category='CAT'] is hidden/collapsed, click [data-testid='toggle-all-categories-btn']."""
        has_chips_container = self.page.locator("[data-testid='category-chips']").count() > 0
        chip_sel = (
            f"[data-testid='category-chips'] [data-category='{cat_upper}' i]"
            if has_chips_container
            else f"[data-category='{cat_upper}' i]"
        )
        loc = self.page.locator(chip_sel)
        for idx in range(loc.count()):
            item = loc.nth(idx)
            try:
                if item.is_visible():
                    in_excluded = item.evaluate(
                        "el => Boolean(el.closest('[data-testid=\"entity-vault-list\"], [role=\"dialog\"], dialog'))"
                    )
                    if not in_excluded:
                        return
            except Exception:  # noqa: BLE001
                continue
        toggle_btn = self.page.locator("[data-testid='toggle-all-categories-btn']")
        if toggle_btn.count() > 0:
            try:
                btn = toggle_btn.first
                if btn.is_visible():
                    already_expanded = bool(
                        btn.evaluate(
                            "el => el.getAttribute('aria-expanded') === 'true' || el.getAttribute('aria-pressed') === 'true' || el.getAttribute('data-expanded') === 'true'"
                        )
                    )
                    if not already_expanded:
                        btn.click()
                        self.page.wait_for_timeout(100)
            except Exception:  # noqa: BLE001
                pass

    def get_category_chip(self, category: str, *, expand: bool = True) -> Locator:
        """Locate a visible category filter chip by data-category or bilingual alias."""
        cat_upper = category.upper()
        if expand:
            self._expand_all_categories_if_needed(cat_upper)

        aliases = _CATEGORY_ALIASES.get(cat_upper, [category])
        pattern = re.compile(
            r"(?<![A-Za-zА-Яа-яЁё0-9_])(?:"
            + "|".join(re.escape(a) for a in aliases)
            + r")(?![A-Za-zА-Яа-яЁё0-9_])",
            re.I,
        )
        has_chips_container = self.page.locator("[data-testid='category-chips']").count() > 0
        if has_chips_container:
            chips_root = self.page.locator("[data-testid='category-chips']").first
            candidates = [
                chips_root.locator(f"[data-category='{cat_upper}' i]"),
                chips_root.locator("button, [role='switch'], [role='checkbox'], label").filter(has_text=pattern),
                chips_root.get_by_role("button", name=pattern),
                chips_root.get_by_role("checkbox", name=pattern),
            ]
        else:
            candidates = [
                self.page.locator(f"[data-category='{cat_upper}' i]"),
                self.page.locator("main, section, aside").locator("button, [role='switch'], label").filter(has_text=pattern),
                self.page.get_by_role("button", name=pattern),
                self.page.locator("main, section, aside").get_by_role("checkbox", name=pattern),
                self.page.get_by_role("checkbox", name=pattern),
            ]
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if not item.is_visible():
                        continue
                    in_excluded = item.evaluate(
                        "el => Boolean(el.closest('header, nav, [role=\"dialog\"], dialog, table, [role=\"table\"], [data-testid=\"entity-vault-list\"], [data-testid=\"open-rulebook-btn\"]'))"
                    )
                    if not in_excluded:
                        return item
                except Exception:  # noqa: BLE001
                    continue
        raise LocatorLookupError(self.dump_diagnostics(f"Category chip '{category}' not found"))

    def _find_attached_category_chip(self, cat_upper: str) -> Locator | None:
        """Return attached [data-category='CAT'] locator (even if hidden) outside excluded areas."""
        has_chips_container = self.page.locator("[data-testid='category-chips']").count() > 0
        loc = (
            self.page.locator("[data-testid='category-chips']")
            .first.locator(f"[data-category='{cat_upper}' i]")
            if has_chips_container
            else self.page.locator(f"[data-category='{cat_upper}' i]")
        )
        try:
            count = loc.count()
        except Exception:  # noqa: BLE001
            return None
        for idx in range(count):
            item = loc.nth(idx)
            try:
                in_excluded = item.evaluate(
                    "el => Boolean(el.closest('header, nav, [role=\"dialog\"], dialog, table, [role=\"table\"], [data-testid=\"entity-vault-list\"], [data-testid=\"open-rulebook-btn\"]'))"
                )
                if not in_excluded:
                    return item
            except Exception:  # noqa: BLE001
                continue
        return None

    def get_category_chip_count(self, category: str) -> int:
        """Read numeric count for category chip without mutating collapsed UI state."""
        cat_upper = category.upper()
        attached = self._find_attached_category_chip(cat_upper)
        if attached is not None:
            raw_count = attached.get_attribute("data-count")
            if raw_count is not None:
                stripped = raw_count.strip()
                return int(stripped) if stripped.isdigit() else 0
            text = attached.evaluate(
                """el => {
                    const aria = el.getAttribute('aria-label') || '';
                    if (/\\d+/.test(aria)) return aria;
                    return el.textContent || aria || '';
                }"""
            )
            matches = re.findall(r"\d+", str(text))
            return int(matches[-1]) if matches else 0

        if self.page.locator("[data-testid='category-chips'], [data-testid='panel-sanitize']").count() > 0:
            return 0

        chip = self.get_category_chip(category, expand=False)
        data_count = chip.get_attribute("data-count")
        if data_count is not None and data_count.strip().isdigit():
            return int(data_count.strip())

        text = (chip.inner_text() or "").strip()
        if not re.search(r"\d+", text):
            text = chip.evaluate(
                """el => {
                    const aria = el.getAttribute('aria-label') || '';
                    if (/\\d+/.test(aria)) return aria;
                    if (el.id) {
                        const lbl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
                        if (lbl && /\\d+/.test(lbl.textContent || '')) return lbl.textContent || '';
                    }
                    const wrap = el.closest('label');
                    if (wrap && /\\d+/.test(wrap.textContent || '')) return wrap.textContent || '';
                    return el.textContent || aria || '';
                }"""
            )
        matches = re.findall(r"\d+", str(text))
        if not matches:
            return 0
        return int(matches[-1])

    def toggle_category_chip(self, category: str) -> None:
        """Click category filter chip to disable/enable its masking."""
        chip = self.get_category_chip(category)
        chip.click()
        self.page.wait_for_timeout(120)

    def get_vault_rows(self) -> list[VaultRowInfo]:
        """Read all visible rows in [data-testid='entity-vault-list'] (with <table> fallback)."""
        rows: list[VaultRowInfo] = []

        vault_list = self.page.locator("[data-testid='entity-vault-list']")
        if vault_list.count() > 0:
            items = vault_list.first.locator("[data-testid='vault-item']")
            for idx in range(items.count()):
                item = items.nth(idx)
                try:
                    if not item.is_visible():
                        continue
                    txt = (item.inner_text() or "").strip()
                    tok_attr = item.get_attribute("data-token")
                    tok_match = re.search(r"\[[A-Z_]+_\d+\]", txt)
                    if tok_attr and re.fullmatch(r"\[[A-Z_]+_\d+\]", tok_attr.strip()):
                        token = tok_attr.strip()
                    elif tok_match:
                        token = tok_match.group(0)
                    else:
                        continue
                    cat_attr = (item.get_attribute("data-category") or "").strip().upper()
                    cat = cat_attr or token.strip("[]").rsplit("_", 1)[0]
                    enabled = item.evaluate(
                        """row => {
                            const explicit = row.querySelector('[data-testid="vault-item-toggle"]');
                            let ctrl = explicit || row.querySelector('input[type="checkbox"], [role="switch"], button[aria-pressed]');
                            if (ctrl && ctrl.tagName.toLowerCase() !== 'input') {
                                const nested = ctrl.querySelector('input[type="checkbox"]');
                                if (nested) ctrl = nested;
                            }
                            if (ctrl) {
                                if (ctrl.tagName.toLowerCase() === 'input') return Boolean(ctrl.checked);
                                const ap = ctrl.getAttribute('aria-pressed');
                                const ac = ctrl.getAttribute('aria-checked');
                                const de = ctrl.getAttribute('data-enabled');
                                if (ap !== null) return ap === 'true';
                                if (ac !== null) return ac === 'true';
                                if (de !== null) return de !== 'false' && de !== '0';
                            }
                            if (row.getAttribute('data-enabled') === 'false') return false;
                            if (row.getAttribute('aria-disabled') === 'true') return false;
                            return !/disabled|off|unmasked/i.test(row.className || '');
                        }"""
                    )
                    rows.append(
                        VaultRowInfo(
                            token=token,
                            category=cat,
                            raw_text=txt,
                            enabled=bool(enabled),
                            row_locator=item,
                        )
                    )
                except Exception:  # noqa: BLE001
                    continue
            return rows

        table_candidates = [
            self.page.locator("main table"),
            self.page.locator("main [role='table']"),
            self.page.locator("table"),
        ]
        for table_loc in table_candidates:
            try:
                if table_loc.count() == 0:
                    continue
            except Exception:  # noqa: BLE001
                continue
            row_loc = table_loc.first.locator("tbody tr, [role='row']")
            count = row_loc.count()
            for idx in range(count):
                item = row_loc.nth(idx)
                try:
                    if not item.is_visible():
                        continue
                    txt = (item.inner_text() or "").strip()
                    tok_match = re.search(r"\[[A-Z_]+_\d+\]", txt)
                    if not tok_match:
                        continue
                    token = tok_match.group(0)
                    cat = token.strip("[]").rsplit("_", 1)[0]
                    enabled = item.evaluate(
                        """row => {
                            const cb = row.querySelector('input[type="checkbox"]');
                            if (cb) return Boolean(cb.checked);
                            const sw = row.querySelector('[role="switch"], button[aria-pressed]');
                            if (sw) {
                                const ap = sw.getAttribute('aria-pressed');
                                const ac = sw.getAttribute('aria-checked');
                                if (ap !== null) return ap === 'true';
                                if (ac !== null) return ac === 'true';
                            }
                            if (row.getAttribute('data-enabled') === 'false') return false;
                            if (row.getAttribute('aria-disabled') === 'true') return false;
                            return !/disabled|off|unmasked/i.test(row.className || '');
                        }"""
                    )
                    rows.append(
                        VaultRowInfo(
                            token=token,
                            category=cat,
                            raw_text=txt,
                            enabled=bool(enabled),
                            row_locator=item,
                        )
                    )
                except Exception:  # noqa: BLE001
                    continue
            if rows:
                return rows
        return rows

    def toggle_vault_entity(self, identifier: str) -> None:
        """Toggle an entity row off/on by token ([EMAIL_1]), exact data-value/text, or substring fallback."""
        rows = self.get_vault_rows()
        target_row: Locator | None = None
        id_lower = identifier.strip().lower()

        row_data_values: list[list[str]] = []
        for row in rows:
            vals: list[str] = []
            try:
                rv = (row.row_locator.get_attribute("data-value") or "").strip().lower()
                if rv:
                    vals.append(rv)
                child_vals = row.row_locator.evaluate(
                    "el => Array.from(el.querySelectorAll('[data-value]')).map(n => (n.getAttribute('data-value') || '').trim())"
                )
                for cv in child_vals:
                    if cv and cv.lower() not in vals:
                        vals.append(cv.lower())
            except Exception:  # noqa: BLE001
                pass
            row_data_values.append(vals)

        # Pass 1: exact match on token, data-value, exact raw_text line, or token-bounded match in raw_text
        exact_boundary_pat = re.compile(
            rf"(?<![A-Za-zА-Яа-яЁё0-9._%+-]){re.escape(id_lower)}(?![A-Za-zА-Яа-яЁё0-9._%+-])"
        )
        for row, vals in zip(rows, row_data_values):
            raw_low = row.raw_text.strip().lower()
            raw_lines = [ln.strip().lower() for ln in raw_low.splitlines() if ln.strip()]
            if (
                id_lower == row.token.strip().lower()
                or id_lower in vals
                or id_lower == raw_low
                or id_lower in raw_lines
                or exact_boundary_pat.search(raw_low)
            ):
                target_row = row.row_locator
                break

        # Pass 2: substring fallback only if Pass 1 found no match
        if target_row is None:
            for row, vals in zip(rows, row_data_values):
                if id_lower in row.raw_text.lower() or any(id_lower in v for v in vals):
                    target_row = row.row_locator
                    break

        if target_row is None:
            raise LocatorLookupError(
                self.dump_diagnostics(f"Vault row matching '{identifier}' not found among {len(rows)} rows")
            )
        toggle_candidates = [
            target_row.locator("[data-testid='vault-item-toggle']"),
            target_row.locator("input[type='checkbox']"),
            target_row.locator("[role='switch']"),
            target_row.locator("button[aria-pressed], button[aria-checked]"),
            target_row.locator("button"),
        ]
        toggle_loc = self._first_visible(toggle_candidates, f"Vault row toggle '{identifier}'")
        toggle_loc.click()
        self.page.wait_for_timeout(120)

    def toggle_hide_values(self) -> None:
        """Click [data-testid='toggle-hide-values-btn'] to mask/reveal raw values in vault list."""
        btn = self._first_visible(
            [
                self.page.locator("[data-testid='toggle-hide-values-btn']"),
                self.page.locator("main").get_by_role(
                    "button",
                    name=re.compile(r"скрыть\s+значен|показать\s+значен|hide\s+values|show\s+values", re.I),
                ),
            ],
            "Hide/Show values button ([data-testid='toggle-hide-values-btn'])",
        )
        btn.click()
        self.page.wait_for_timeout(100)

    def get_telemetry_masked_count(self) -> int:
        """Read integer masked count from [data-testid='telemetry-masked-count'] (or #stat-vault fallback)."""
        loc = self._first_visible(
            [
                self.page.locator("[data-testid='telemetry-masked-count']"),
                self.page.locator("#stat-vault"),
            ],
            "Masked telemetry count ([data-testid='telemetry-masked-count'])",
        )
        data_count = loc.get_attribute("data-count")
        if data_count is not None and data_count.strip().isdigit():
            return int(data_count.strip())
        txt = (loc.inner_text() or "").strip()
        matches = re.findall(r"\d+", txt)
        if not matches:
            raise LocatorLookupError(
                self.dump_diagnostics(f"Telemetry masked count has no digits: {txt!r}")
            )
        return int(matches[0])

    # -----------------------------------------------------------------------
    # FileReader Upload
    # -----------------------------------------------------------------------

    def get_workbench_file_input(self) -> Locator:
        """Locate the FileReader <input type='file'> outside any open drawer/dialog/aside."""
        direct = self.page.locator("[data-testid='file-upload-input']")
        if direct.count() > 0:
            return direct.first

        for scope_sel in ("main input[type='file']", "input[type='file']"):
            all_inputs = self.page.locator(scope_sel)
            try:
                count = all_inputs.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = all_inputs.nth(idx)
                in_drawer = item.evaluate(
                    "el => Boolean(el.closest('[role=\"dialog\"], dialog, aside, [data-drawer]'))"
                )
                if not in_drawer:
                    return item
        raise LocatorLookupError(self.dump_diagnostics("Workbench file input not found outside drawers"))

    def upload_file(self, file_path: Path) -> None:
        """Upload a local file via FileReader <input type='file'> without HTTP upload."""
        if self._active_mode != "sanitize":
            self.switch_mode("sanitize")
        file_input = self.get_workbench_file_input()
        file_input.set_input_files(str(file_path))
        self.page.wait_for_timeout(300)
        if self.get_prompt_input().input_value().strip() and not self.get_sanitize_output_text().strip():
            btn = self._find_action_button(
                re.compile(r"проверить|скрыть|sanitize|scan|mask", re.I),
                testid="sanitize-now-btn",
            )
            if btn is not None:
                btn.click()
                self.page.wait_for_timeout(150)

    # -----------------------------------------------------------------------
    # Drawers: Custom Words («Свои слова» / Rulebook) & Audit («Журнал проверок»)
    # -----------------------------------------------------------------------

    def _get_open_drawer(
        self,
        heading_pattern: re.Pattern[str],
        testid: str | None = None,
    ) -> Locator | None:
        """Return currently open drawer/dialog matching data-testid or heading pattern."""
        if testid:
            loc = self.page.locator(f"[data-testid='{testid}']")
            for idx in range(loc.count()):
                item = loc.nth(idx)
                try:
                    if item.is_visible():
                        return item
                except Exception:  # noqa: BLE001
                    continue

        containers = self.page.locator("[role='dialog'], dialog[open], aside, [data-drawer]")
        count = containers.count()
        for idx in range(count):
            item = containers.nth(idx)
            try:
                if item.is_visible():
                    txt = item.inner_text()
                    if heading_pattern.search(txt):
                        return item
            except Exception:  # noqa: BLE001
                continue
        return None

    def open_rulebook_drawer(self) -> Locator:
        """Open Custom Words / Rulebook drawer and return its scoped Locator."""
        pat = re.compile(r"свои\s+слова|мои\s+правила|правила|rulebook|custom\s*rules", re.I)
        existing = self._get_open_drawer(pat, testid="drawer-rulebook")
        if existing is not None:
            return existing
        trigger = self._first_visible(
            [
                self.page.locator("[data-testid='open-rulebook-btn']"),
                self.page.get_by_role("button", name=pat),
                self.page.locator("header button, nav button, button").filter(has_text=pat),
            ],
            "Rulebook drawer trigger ([data-testid='open-rulebook-btn'])",
        )
        trigger.click()
        self.page.wait_for_timeout(150)
        drawer = self._get_open_drawer(pat, testid="drawer-rulebook")
        if drawer is None:
            raise LocatorLookupError(self.dump_diagnostics("Rulebook drawer did not open"))
        return drawer

    def close_open_drawer(self) -> None:
        """Close any currently open Rulebook or Audit drawer."""
        drawer = self._get_open_drawer(
            re.compile(r"свои\s+слова|мои\s+правила|журнал|rulebook|custom\s*rules|audit", re.I),
            testid="drawer-rulebook",
        )
        if drawer is None:
            drawer = self._get_open_drawer(
                re.compile(r"журнал|audit", re.I),
                testid="drawer-audit",
            )
        if drawer is None:
            return
        close_candidates = [
            drawer.locator("[data-testid='close-rulebook-btn'], [data-testid='close-audit-btn']"),
            drawer.get_by_role("button", name=re.compile(r"закрыть|готово|close|×|dismiss|done", re.I)),
            drawer.locator("button[aria-label*='закрыть' i], button[aria-label*='close' i], button[data-close]"),
        ]
        for loc in close_candidates:
            try:
                if loc.count() > 0 and loc.first.is_visible():
                    loc.first.click()
                    self.page.wait_for_timeout(120)
                    return
            except Exception:  # noqa: BLE001
                continue
        self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(120)

    @staticmethod
    def _is_editable_text_input(item: Locator) -> bool:
        """Return True iff item is an enabled editable text input or textarea."""
        return bool(
            item.evaluate(
                """el => {
                    const tag = el.tagName.toLowerCase();
                    const type = (el.getAttribute('type') || '').toLowerCase();
                    const isCtrl = (
                        tag === 'textarea' ||
                        (tag === 'input' && !['file', 'checkbox', 'radio', 'hidden', 'button', 'submit', 'reset'].includes(type))
                    );
                    if (!isCtrl) return false;
                    return !el.readOnly && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
                }"""
            )
        )

    def _first_visible_editable_input(self, candidates: list[Locator], description: str) -> Locator:
        """Return the first candidate resolving to a visible editable text input."""
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible() and self._is_editable_text_input(item):
                        return item
                except Exception:  # noqa: BLE001
                    continue
        raise LocatorLookupError(self.dump_diagnostics(f"Could not find visible editable input: {description}"))

    def add_custom_rule(self, term: str, label: str | None = None) -> None:
        """Open Rulebook drawer and add a custom rule term (handling <select> or <input> category)."""
        drawer = self.open_rulebook_drawer()
        term_input = self._first_visible_editable_input(
            [
                drawer.locator("[data-testid='rule-term-input']"),
                drawer.get_by_role("textbox", name=re.compile(r"слово|фраз|термин|term|pattern|phrase|rule|text|keyword", re.I)),
                drawer.get_by_label(re.compile(r"слово|фраз|термин|term|pattern|phrase|rule|text|keyword", re.I)),
                drawer.get_by_placeholder(re.compile(r"слово|фраз|термин|пример|term|pattern|phrase|rule|entity|name", re.I)),
                drawer.locator("input[type='text']:not([readonly])"),
                drawer.locator("textarea:not([readonly])"),
                drawer.locator("input:not([type='file']):not([type='checkbox']):not([type='radio']):not([type='hidden'])"),
            ],
            "Rulebook term input ([data-testid='rule-term-input'])",
        )
        self._set_textarea_with_events(term_input, term)

        if label is not None:
            cat_candidates = [
                drawer.locator("[data-testid='rule-category-input']"),
                drawer.get_by_label(re.compile(r"категор|метка|тип|label|category|note", re.I)),
            ]
            for loc in cat_candidates:
                if loc.count() > 0 and loc.first.is_visible():
                    cat_el = loc.first
                    tag = str(cat_el.evaluate("el => el.tagName.toLowerCase()"))
                    if tag == "select":
                        options: list[dict[str, str]] = cat_el.evaluate(
                            """sel => Array.from(sel.options).map(o => ({
                                value: o.value,
                                text: (o.textContent || '').trim()
                            }))"""
                        )
                        lbl_low = label.strip().lower()
                        chosen_val: str | None = None
                        for opt in options:
                            if opt["value"].strip().lower() == lbl_low or opt["text"].lower() == lbl_low:
                                chosen_val = opt["value"]
                                break
                        if chosen_val is None:
                            cat_aliases = [
                                a.lower() for a in _CATEGORY_ALIASES.get(label.strip().upper(), [label])
                            ]
                            for opt in options:
                                v_low = opt["value"].strip().lower()
                                t_low = opt["text"].lower()
                                if any(a == v_low or a == t_low or a in t_low for a in cat_aliases):
                                    chosen_val = opt["value"]
                                    break
                        if chosen_val is not None:
                            cat_el.select_option(value=chosen_val, timeout=1000)
                        else:
                            try:
                                cat_el.select_option(value=label, timeout=1000)
                            except Exception:  # noqa: BLE001
                                cat_el.select_option(label=label, timeout=1000)
                        cat_el.evaluate("el => el.dispatchEvent(new Event('change', { bubbles: true }))")
                    else:
                        self._set_textarea_with_events(cat_el, label)
                    break

        add_btn = self._first_visible(
            [
                drawer.locator("[data-testid='add-rule-btn']"),
                drawer.get_by_role("button", name=re.compile(r"добавить|сохранить|add|save|create|\+", re.I)),
                drawer.locator("button[type='submit']"),
            ],
            "Rulebook Add button ([data-testid='add-rule-btn'])",
        )
        if not term.strip() and add_btn.is_disabled():
            return
        add_btn.click()
        self.page.wait_for_timeout(150)

    def delete_custom_rule(self, term: str) -> None:
        """Delete a custom rule row matching term inside Rulebook drawer."""
        drawer = self.open_rulebook_drawer()
        rows_loc = drawer.locator("[data-testid='rules-list'] > *, li, tr, [role='row'], [data-rule-item]")
        count = rows_loc.count()
        for idx in range(count):
            row = rows_loc.nth(idx)
            try:
                if row.is_visible() and term in row.inner_text():
                    del_btn = row.locator("button").filter(
                        has_text=re.compile(r"удалить|убрать|delete|remove|×|trash", re.I)
                    )
                    if del_btn.count() == 0:
                        del_btn = row.locator(
                            "button[aria-label*='удал' i], button[aria-label*='delete' i], button[aria-label*='remove' i], button"
                        )
                    del_btn.first.click()
                    self.page.wait_for_timeout(120)
                    return
            except Exception:  # noqa: BLE001
                continue
        raise LocatorLookupError(self.dump_diagnostics(f"Custom rule '{term}' not found for deletion"))

    def get_rulebook_text(self) -> str:
        """Return visible text inside open Rulebook drawer."""
        drawer = self.open_rulebook_drawer()
        return drawer.inner_text()

    def export_rules_json(self, target_dir: Path) -> Path:
        """Click Export Rules inside Rulebook drawer and save downloaded JSON."""
        drawer = self.open_rulebook_drawer()
        export_btn = self._first_visible(
            [
                drawer.locator("[data-testid='export-rules-btn']"),
                drawer.get_by_role("button", name=re.compile(r"экспорт|скачать|сохранить|export", re.I)),
                drawer.locator("a, button").filter(has_text=re.compile(r"экспорт|скачать|сохранить|export", re.I)),
            ],
            "Rulebook Export button ([data-testid='export-rules-btn'])",
        )
        with self.page.expect_download(timeout=self.timeout_ms) as dl_info:
            export_btn.click()
        download: Download = dl_info.value
        dest = target_dir / (download.suggested_filename or "promptveil_rules.json")
        download.save_as(str(dest))
        return dest

    def import_rules_json(self, json_path: Path) -> None:
        """Import rules JSON file strictly inside the open Rulebook drawer."""
        drawer = self.open_rulebook_drawer()
        file_input = self._first_attached(
            [
                drawer.locator("[data-testid='import-rules-input']"),
                drawer.locator("input[type='file']"),
            ],
            "Rulebook Import file input ([data-testid='import-rules-input'])",
        )
        file_input.set_input_files(str(json_path))
        self.page.wait_for_timeout(200)

    def open_audit_drawer(self) -> Locator:
        """Open Audit drawer («Журнал проверок») and return its scoped Locator."""
        pat = re.compile(r"журнал(?:\s+проверок)?|история|audit(?:\s*receipts)?", re.I)
        existing = self._get_open_drawer(pat, testid="drawer-audit")
        if existing is not None:
            return existing
        trigger = self._first_visible(
            [
                self.page.locator("[data-testid='open-audit-btn']"),
                self.page.get_by_role("button", name=pat),
                self.page.locator("header button, nav button, button").filter(has_text=pat),
            ],
            "Audit drawer trigger ([data-testid='open-audit-btn'])",
        )
        trigger.click()
        self.page.wait_for_timeout(150)
        drawer = self._get_open_drawer(pat, testid="drawer-audit")
        if drawer is None:
            raise LocatorLookupError(self.dump_diagnostics("Audit drawer did not open"))
        return drawer

    def get_audit_drawer_text(self) -> str:
        """Return visible text inside open Audit drawer."""
        drawer = self.open_audit_drawer()
        return drawer.inner_text()

    def get_audit_hashes(self) -> list[str]:
        """Extract 64-char SHA-256 hex digests displayed in the Audit drawer."""
        text = self.get_audit_drawer_text()
        return re.findall(r"\b[0-9a-f]{64}\b", text, re.I)

    def export_audit_json(self, target_dir: Path) -> Path:
        """Click Export inside Audit drawer and save downloaded JSON."""
        drawer = self.open_audit_drawer()
        export_btn = self._first_visible(
            [
                drawer.locator("[data-testid='export-audit-btn']"),
                drawer.get_by_role("button", name=re.compile(r"экспорт|скачать|сохранить|export", re.I)),
                drawer.locator("a, button").filter(has_text=re.compile(r"экспорт|скачать|сохранить|export", re.I)),
            ],
            "Audit Export button ([data-testid='export-audit-btn'])",
        )
        with self.page.expect_download(timeout=self.timeout_ms) as dl_info:
            export_btn.click()
        download: Download = dl_info.value
        dest = target_dir / (download.suggested_filename or "promptveil_audit.json")
        download.save_as(str(dest))
        return dest

    def clear_audit_log(self) -> None:
        """Click Clear inside Audit drawer, handling disabled-when-empty, confirm(), or in-DOM confirm."""
        drawer = self.open_audit_drawer()
        clear_btn = self._first_visible(
            [
                drawer.locator("[data-testid='clear-audit-btn']"),
                drawer.get_by_role("button", name=re.compile(r"очистить|удалить|clear", re.I)),
                drawer.locator("button").filter(has_text=re.compile(r"очистить|удалить|clear", re.I)),
            ],
            "Audit Clear button ([data-testid='clear-audit-btn'])",
        )
        if clear_btn.is_disabled():
            return

        def _maybe_confirm_in_dom() -> None:
            self.page.wait_for_timeout(120)
            in_drawer_pat = re.compile(
                r"^(?:подтвердить|да(?:,\s*(?:очистить|удалить))?|очистить\s+журнал|confirm|yes)$",
                re.I,
            )
            ext_pat = re.compile(r"подтвердить|да|очистить|confirm|удалить", re.I)
            ext_dialogs = self.page.locator(
                "dialog[open]:not([data-testid='drawer-audit']), "
                "[role='dialog']:not([data-testid='drawer-audit']), "
                "[role='alertdialog']:not([data-testid='drawer-audit'])"
            )
            confirm_candidates = [
                drawer.locator("[data-testid='confirm-clear-audit-btn']"),
                drawer.locator("button:not([data-testid='clear-audit-btn'])").filter(has_text=in_drawer_pat),
                self.page.locator("[data-testid='confirm-clear-audit-btn']"),
                ext_dialogs.locator("button:not([data-testid='clear-audit-btn'])").filter(has_text=ext_pat),
            ]
            drawer_handle = drawer.element_handle()
            for idx_cand, loc in enumerate(confirm_candidates):
                try:
                    count = loc.count()
                except Exception:  # noqa: BLE001
                    continue
                for idx in range(count):
                    item = loc.nth(idx)
                    try:
                        if not (item.is_visible() and item.is_enabled()):
                            continue
                        if idx_cand >= 3 and drawer_handle is not None:
                            inside_drawer = bool(
                                item.evaluate("(el, drw) => drw.contains(el)", drawer_handle)
                            )
                            if inside_drawer:
                                continue
                        item.click()
                        self.page.wait_for_timeout(120)
                        return
                    except Exception:  # noqa: BLE001
                        continue

        console_monitor = getattr(self.page, "_pv_console_monitor", None)
        if console_monitor is not None and hasattr(console_monitor, "allow_confirm_accept"):
            with console_monitor.allow_confirm_accept():
                clear_btn.click()
                _maybe_confirm_in_dom()
            return

        def _accept_confirm(dialog: Any) -> None:
            if dialog.type == "confirm":
                dialog.accept()

        self.page.on("dialog", _accept_confirm)
        try:
            clear_btn.click()
            _maybe_confirm_in_dom()
        finally:
            self.page.remove_listener("dialog", _accept_confirm)

    # -----------------------------------------------------------------------
    # Copy, Download, Badges, Status & Empty States
    # -----------------------------------------------------------------------

    def click_copy_output(self) -> None:
        """Click the Copy button for the active output pane."""
        primary_testid = (
            "copy-restored-btn" if self._active_mode == "rehydrate" else "copy-sanitized-btn"
        )
        copy_btn = self._first_visible(
            [
                self.page.locator(f"[data-testid='{primary_testid}']"),
                self.page.locator("[data-testid='copy-sanitized-btn'], [data-testid='copy-restored-btn']"),
                self.page.locator("main").get_by_role("button", name=re.compile(r"скопировать|копировать|copy", re.I)),
                self.page.locator("main button").filter(has_text=re.compile(r"скопировать|копировать|copy", re.I)),
            ],
            f"Copy output button ([data-testid='{primary_testid}'])",
        )
        copy_btn.click()
        self.page.wait_for_timeout(120)

    def download_sanitized(self, target_dir: Path) -> Path:
        """Click [data-testid='download-sanitized-btn'] and save downloaded .txt."""
        btn = self._first_visible(
            [
                self.page.locator("[data-testid='download-sanitized-btn']"),
                self.page.locator("main").get_by_role("button", name=re.compile(r"скачать|download", re.I)),
            ],
            "Download sanitized button ([data-testid='download-sanitized-btn'])",
        )
        with self.page.expect_download(timeout=self.timeout_ms) as dl_info:
            btn.click()
        download: Download = dl_info.value
        dest = target_dir / (download.suggested_filename or "sanitized.txt")
        download.save_as(str(dest))
        return dest

    def download_restored(self, target_dir: Path) -> Path:
        """Click [data-testid='download-restored-btn'] and save downloaded .txt."""
        btn = self._first_visible(
            [
                self.page.locator("[data-testid='download-restored-btn']"),
                self.page.locator("main").get_by_role("button", name=re.compile(r"скачать|download", re.I)),
            ],
            "Download restored button ([data-testid='download-restored-btn'])",
        )
        with self.page.expect_download(timeout=self.timeout_ms) as dl_info:
            btn.click()
        download: Download = dl_info.value
        dest = target_dir / (download.suggested_filename or "restored.txt")
        download.save_as(str(dest))
        return dest

    def read_clipboard_text(self) -> str | None:
        """Attempt to read clipboard text via navigator.clipboard.readText()."""
        try:
            val = self.page.evaluate(
                """async () => {
                    if (!navigator.clipboard || !navigator.clipboard.readText) return null;
                    return await navigator.clipboard.readText();
                }"""
            )
            return None if val is None else str(val)
        except Exception:  # noqa: BLE001
            return None

    def get_copy_feedback_text(self) -> str:
        """Return visible copy confirmation feedback text if displayed (RU | EN)."""
        pat = re.compile(r"(?:скопировано|\bcopied\b)", re.I)
        candidates = [
            self.page.locator("[data-testid='status-banner']").filter(has_text=pat),
            self.page.locator("[data-testid='copy-sanitized-btn'], [data-testid='copy-restored-btn']").filter(has_text=pat),
            self.page.locator("main").get_by_text(pat),
            self.page.locator("[role='status'], [aria-live]").filter(has_text=pat),
            self.page.get_by_text(pat),
        ]
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible():
                        txt = (item.inner_text() or "").strip()
                        if txt:
                            return txt
                except Exception:  # noqa: BLE001
                    continue
        return ""

    def get_status_banner_text(self) -> str:
        """Return visible text from [data-testid='status-banner'] if visible."""
        banner = self.page.locator("[data-testid='status-banner']")
        for idx in range(banner.count()):
            item = banner.nth(idx)
            try:
                if item.is_visible():
                    return (item.inner_text() or "").strip()
            except Exception:  # noqa: BLE001
                continue
        return ""

    def get_rulebook_badge_count(self) -> int:
        """Read numeric rule count badge from [data-testid='open-rulebook-btn'] (0 if no digits)."""
        pat = re.compile(r"свои\s+слова|мои\s+правила|правила|rulebook|custom\s*rules", re.I)
        trigger = self._first_visible(
            [
                self.page.locator("[data-testid='open-rulebook-btn']"),
                self.page.locator("header, nav").get_by_role("button", name=pat),
                self.page.get_by_role("button", name=pat),
                self.page.locator("header button, nav button, button").filter(has_text=pat),
            ],
            "Rulebook badge trigger ([data-testid='open-rulebook-btn'])",
        )
        txt = (trigger.inner_text() or "").strip()
        matches = re.findall(r"\d+", txt)
        if not matches:
            return 0
        return int(matches[-1])

    def get_visible_error_notice(self, scope: Locator | None = None) -> str:
        """Return visible error/warning notice text inside scope or page (RU | EN)."""
        root = scope if scope is not None else self.page.locator("body")
        err_pat = re.compile(
            r"ошибка|некоррект|неверн|неподдерж|не\s+удалось|превыша|слишком\s+больш|"
            r"пуст|дубликат|заблокир|буфер|error|invalid|unsupported|failed|malformed|"
            r"rejected|unable|cannot|not\s+supported|parse|duplicate|2\s*(?:mb|мб)",
            re.I,
        )
        candidates = [
            root.locator("[data-testid='status-banner'][role='alert']"),
            root.locator(
                "[role='alert'], [data-error], [data-status='error'], .error, .alert-error, .notice-error"
            ),
            root.locator("[aria-live]").filter(has_text=err_pat),
            root.get_by_text(err_pat),
        ]
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible():
                        txt = (item.inner_text() or "").strip()
                        if txt:
                            return txt
                except Exception:  # noqa: BLE001
                    continue
        return ""

    def get_vault_empty_state_text(self) -> str:
        """Return visible empty-state hint text in the replacement list / Entity Vault area."""
        pat = re.compile(
            r"пока\s+пусто|нет\s+данных|ничего\s+не\s+найдено|не\s+обнаружен|вставьте\s+текст|"
            r"здесь\s+появ|автоматически\s+найд|"
            r"no\s+entities|no\s+detections|empty|nothing\s+detected|no\s+sensitive|enter\s+or\s+upload",
            re.I,
        )
        candidates = [
            self.page.locator("[data-testid='entity-vault-list']").get_by_text(pat),
            self.page.locator("[data-testid='entity-vault-list'] [data-empty], [data-testid='entity-vault-list'] .empty-state"),
            self.page.locator("main")
            .locator("[data-empty], .empty-state, table, [role='table'], section")
            .get_by_text(pat),
            self.page.locator("main").get_by_text(pat),
        ]
        for loc in candidates:
            try:
                count = loc.count()
            except Exception:  # noqa: BLE001
                continue
            for idx in range(count):
                item = loc.nth(idx)
                try:
                    if item.is_visible():
                        txt = (item.inner_text() or "").strip()
                        if txt:
                            return txt
                except Exception:  # noqa: BLE001
                    continue
        return ""

    # -----------------------------------------------------------------------
    # R2–R5: Zero-Retention Proof, UX Speedups, Pricing & Modals, Trust Footer
    # -----------------------------------------------------------------------

    def open_privacy_proof_modal(self, via: Literal["header", "footer"] = "header") -> Locator:
        """Open #modal-privacy-proof from header or footer trigger."""
        testid = "footer-open-proof-btn" if via == "footer" else "brand-badge"
        trigger = self._first_visible(
            [self.page.locator(f"[data-testid='{testid}']")],
            f"Privacy Proof trigger ({testid})",
        )
        trigger.click()
        self.page.wait_for_timeout(120)
        modal = self._first_visible(
            [self.page.locator("[data-testid='modal-privacy-proof']")],
            "Privacy Proof modal ([data-testid='modal-privacy-proof'])",
        )
        return modal

    def run_privacy_proof_check(self) -> None:
        """Click live self-test button inside Privacy Proof modal."""
        btn = self._first_visible(
            [self.page.locator("[data-testid='run-proof-check-btn']")],
            "Run live proof check ([data-testid='run-proof-check-btn'])",
        )
        btn.click()
        self.page.wait_for_timeout(100)

    def click_reset_session_to_zero(self, via: Literal["modal", "workbench"] = "modal") -> None:
        """Trigger instant resetSessionToZero() from Proof modal or workbench."""
        testid = "reset-session-btn" if via == "modal" else "quick-reset-session-btn"
        btn = self._first_visible(
            [self.page.locator(f"[data-testid='{testid}']")],
            f"Reset session button ({testid})",
        )
        btn.click()
        self.page.wait_for_timeout(120)

    def click_paste_raw(self) -> None:
        """Click Step 1 Paste button ([data-testid='paste-raw-btn'])."""
        btn = self._first_visible(
            [self.page.locator("[data-testid='paste-raw-btn']")],
            "Step 1 Paste button ([data-testid='paste-raw-btn'])",
        )
        btn.click()
        self.page.wait_for_timeout(160)

    def click_paste_rehydrate(self) -> None:
        """Click Step 2 Paste button ([data-testid='paste-rehydrate-btn'])."""
        btn = self._first_visible(
            [self.page.locator("[data-testid='paste-rehydrate-btn']")],
            "Step 2 Paste button ([data-testid='paste-rehydrate-btn'])",
        )
        btn.click()
        self.page.wait_for_timeout(160)

    def click_copy_goto_step2(self) -> None:
        """Click Step 1 Copy & Go to Step 2 combo button ([data-testid='copy-goto-step2-btn'])."""
        btn = self._first_visible(
            [self.page.locator("[data-testid='copy-goto-step2-btn']")],
            "Copy & Go Step 2 button ([data-testid='copy-goto-step2-btn'])",
        )
        btn.click()
        self._active_mode = "rehydrate"
        self.page.wait_for_timeout(150)

    def select_billing_cycle(self, cycle: Literal["month", "year"]) -> None:
        """Select Month or Year -20% billing toggle in Pricing section."""
        testid = "billing-year-btn" if cycle == "year" else "billing-month-btn"
        btn = self._first_visible(
            [self.page.locator(f"[data-testid='{testid}']")],
            f"Billing toggle ({testid})",
        )
        btn.click()
        self.page.wait_for_timeout(100)

    def open_plan_request_modal(self, plan: Literal["pro", "team"]) -> Locator:
        """Open Pro or Team client-side request modal."""
        testid = "open-team-modal-btn" if plan == "team" else "open-pro-modal-btn"
        btn = self._first_visible(
            [self.page.locator(f"[data-testid='{testid}']")],
            f"Plan CTA ({testid})",
        )
        btn.click()
        self.page.wait_for_timeout(120)
        return self._first_visible(
            [self.page.locator("[data-testid='modal-plan-request']")],
            "Plan request modal ([data-testid='modal-plan-request'])",
        )

    def open_privacy_policy_modal(self) -> Locator:
        """Open Privacy Policy modal from Trust Footer."""
        btn = self._first_visible(
            [self.page.locator("[data-testid='open-privacy-policy-btn']")],
            "Privacy Policy button ([data-testid='open-privacy-policy-btn'])",
        )
        btn.click()
        self.page.wait_for_timeout(120)
        return self._first_visible(
            [self.page.locator("[data-testid='modal-privacy-policy']")],
            "Privacy Policy modal ([data-testid='modal-privacy-policy'])",
        )

    def close_active_modal(self) -> None:
        """Close whichever centered modal or drawer is currently visible via Escape."""
        self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(120)
