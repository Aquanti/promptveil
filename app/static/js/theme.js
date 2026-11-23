/**
 * Shared light/dark theme resolution, DOM synchronization, and toggle button rendering.
 */

import { getEl } from "./dom.js";
import { getLang, t } from "./i18n.js";
import { loadThemePreference, saveThemePreference } from "./storage.js";

export const THEME_MOON_PATH = "M16.2 12.6A6.8 6.8 0 0 1 7.4 3.8a7 7 0 1 0 8.8 8.8Z";
export const THEME_SUN_PATH =
  "M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4M13 10a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z";

export function resolveInitialTheme() {
  const saved = loadThemePreference();
  if (saved) return saved;
  try {
    if (
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    ) {
      return "dark";
    }
  } catch {
    // Ignore matchMedia unavailability.
  }
  return "light";
}

export function updateThemeToggleButton(theme, lang = getLang()) {
  if (typeof document === "undefined") return;
  const btn = getEl("theme-toggle-btn");
  if (!btn) return;
  const isDark = theme === "dark";
  const key = isDark ? "theme.toLight" : "theme.toDark";
  const label = t(key, {}, lang);
  btn.setAttribute("aria-pressed", isDark ? "true" : "false");
  btn.setAttribute("data-i18n-aria", key);
  btn.setAttribute("data-i18n-title", key);
  btn.setAttribute("aria-label", label);
  btn.setAttribute("title", label);
  const pathEl = btn.querySelector("path");
  if (pathEl) {
    pathEl.setAttribute("d", isDark ? THEME_SUN_PATH : THEME_MOON_PATH);
  }
}

export function applyTheme(nextTheme, state, { persist = false } = {}) {
  const normalized = nextTheme === "dark" ? "dark" : "light";
  const resolved = persist ? saveThemePreference(normalized) : normalized;
  if (state && typeof state === "object") {
    state.theme = resolved;
  }
  if (typeof document !== "undefined" && document.documentElement) {
    document.documentElement.dataset.theme = resolved;
  }
  updateThemeToggleButton(resolved, state?.lang || getLang());
  return resolved;
}
