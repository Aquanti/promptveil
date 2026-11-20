/**
 * Global toast status banners and scoped inline alert notifications.
 */

import { createEl, getEl } from "./dom.js";
import { getLang, t } from "./i18n.js";

let statusBannerTimer = null;
let activeStatusBanner = null;
const activeInlineAlerts = new Map();

function getTimerHost() {
  return typeof window !== "undefined" ? window : globalThis;
}

function resolveAlertVars(varsOrFn, lang) {
  if (typeof varsOrFn === "function") {
    return varsOrFn(lang) || {};
  }
  return varsOrFn || {};
}

export function renderActiveStatusBanner(lang = getLang()) {
  const banner = getEl("global-status-banner");
  if (!banner) return;
  if (!activeStatusBanner) {
    banner.hidden = true;
    return;
  }
  const message = t(
    activeStatusBanner.key,
    resolveAlertVars(activeStatusBanner.varsOrFn, lang),
    lang
  );
  banner.replaceChildren(createEl("span", "status-banner-text", message));
  banner.classList.toggle("status-banner--error", Boolean(activeStatusBanner.isError));
  banner.setAttribute("role", activeStatusBanner.isError ? "alert" : "status");
  banner.hidden = false;
}

export function showStatusBanner(key, varsOrFn = {}, isError = false) {
  const timerHost = getTimerHost();
  activeStatusBanner = { key, varsOrFn, isError: Boolean(isError) };
  renderActiveStatusBanner(getLang());
  timerHost.clearTimeout(statusBannerTimer);
  statusBannerTimer = timerHost.setTimeout(() => {
    activeStatusBanner = null;
    statusBannerTimer = null;
    const banner = getEl("global-status-banner");
    if (banner) banner.hidden = true;
  }, 4500);
}

export function renderInlineAlert(elementId, lang = getLang()) {
  const el = getEl(elementId);
  if (!el) return;
  const spec = activeInlineAlerts.get(elementId);
  if (!spec) {
    el.textContent = "";
    el.hidden = true;
    return;
  }
  el.textContent = t(spec.key, resolveAlertVars(spec.varsOrFn, lang), lang);
  el.className = `inline-alert inline-alert--${spec.variant}`;
  el.setAttribute("role", spec.variant === "error" ? "alert" : "status");
  el.hidden = false;
}

export function showInlineAlert(elementId, key, varsOrFn = {}, variant = "error") {
  activeInlineAlerts.set(elementId, { key, varsOrFn, variant });
  renderInlineAlert(elementId, getLang());
}

export function hideInlineAlert(elementId) {
  activeInlineAlerts.delete(elementId);
  const el = getEl(elementId);
  if (!el) return;
  el.textContent = "";
  el.hidden = true;
}

export function refreshBannersAndAlerts(lang = getLang()) {
  if (activeStatusBanner) {
    renderActiveStatusBanner(lang);
  }
  for (const elementId of activeInlineAlerts.keys()) {
    renderInlineAlert(elementId, lang);
  }
}

export function resetNotifications() {
  getTimerHost().clearTimeout(statusBannerTimer);
  statusBannerTimer = null;
  activeStatusBanner = null;
  activeInlineAlerts.clear();
}
