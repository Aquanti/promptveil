/**
 * PromptVeil Waitlist Pricing Metadata & Client-Only Request Modal Controller.
 */

import { copyWithFeedback } from "./clipboard.js";
import { SITE_CONTACTS, buildMailtoHref } from "./contacts.js";
import { clearCopyFeedback, getEl } from "./dom.js";
import { getLang, t } from "./i18n.js";
import { ensureModalMounted, registerModalHydrator } from "./modals.js";
import { closeDrawers, openDrawer } from "./render-drawers.js";

export function getPlanPricing(plan, lang) {
  if (plan === "team") {
    return {
      planName: t("pricing.teamName", {}, lang),
      status: t("pricing.teamWaitlistTitle", {}, lang),
    };
  }
  return {
    planName: t("pricing.proName", {}, lang),
    status: t("pricing.proWaitlistTitle", {}, lang),
  };
}

export function isValidContactInput(val) {
  const trimmed = String(val || "").trim();
  if (!trimmed) return false;
  const emailLike = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]{2,}$/;
  const telegramLike = /^@[A-Za-z0-9_]{3,64}$/;
  return emailLike.test(trimmed) || telegramLike.test(trimmed);
}

export function syncPlanRequestModalMeta(state, lang = getLang()) {
  const isTeam = state.activeRequestPlan === "team";
  const titleEl = getEl("plan-modal-title");
  const subtitleEl = getEl("plan-modal-subtitle");
  const summaryPillEl = getEl("plan-summary-pill");
  const seatsFieldEl = getEl("plan-req-seats-field");

  if (titleEl) {
    titleEl.textContent = t(isTeam ? "request.teamTitle" : "request.proTitle", {}, lang);
  }
  if (subtitleEl) {
    subtitleEl.textContent = t(isTeam ? "request.teamSubtitle" : "request.proSubtitle", {}, lang);
  }
  if (seatsFieldEl) {
    seatsFieldEl.hidden = !isTeam;
  }
  if (summaryPillEl) {
    const info = getPlanPricing(state.activeRequestPlan, lang);
    summaryPillEl.textContent = `${info.planName} • ${info.status}`;
  }
}

export function clearPlanRequestResult(state) {
  state.lastRequestSummary = "";
  const resultBox = getEl("plan-request-result");
  const previewEl = getEl("plan-request-preview");
  const mailtoLink = getEl("plan-req-mailto-link");
  if (resultBox) resultBox.hidden = true;
  if (previewEl) previewEl.textContent = "";
  if (mailtoLink) {
    mailtoLink.setAttribute("href", buildMailtoHref(SITE_CONTACTS.email));
  }
}

export function openPlanRequestModal(plan, triggerEl, state, hideInlineAlert) {
  ensureModalMounted("modal-plan-request");
  state.activeRequestPlan = plan === "team" ? "team" : "pro";
  hideInlineAlert("plan-request-alert");
  clearPlanRequestResult(state);
  const nameInput = getEl("plan-req-name");
  const contactInput = getEl("plan-req-contact");
  const seatsInput = getEl("plan-req-seats");
  const noteInput = getEl("plan-req-note");
  if (nameInput) nameInput.value = "";
  if (contactInput) contactInput.value = "";
  if (seatsInput) seatsInput.value = "10";
  if (noteInput) noteInput.value = "";
  clearCopyFeedback(getEl("plan-req-copy-btn"), () => t("request.copyBtn"));
  syncPlanRequestModalMeta(state, getLang());
  openDrawer("modal-plan-request", triggerEl, state);
}

export function bindPricingEvents({
  state,
  showInlineAlert,
  hideInlineAlert,
  showStatusBanner,
  onStartFree,
}) {
  registerModalHydrator("modal-plan-request", () => {
    getEl("close-plan-modal-btn")?.addEventListener("click", () => {
      hideInlineAlert("rulebook-alert");
      closeDrawers(true, state);
    });

    getEl("plan-request-form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      hideInlineAlert("plan-request-alert");
      clearPlanRequestResult(state);
      const lang = getLang();
      const isTeam = state.activeRequestPlan === "team";
      const nameVal = (getEl("plan-req-name")?.value || "").trim();
      const contactVal = (getEl("plan-req-contact")?.value || "").trim();
      const seatsInputRaw = (getEl("plan-req-seats")?.value ?? "").trim();
      const seatsRaw = seatsInputRaw === "" ? NaN : Number(seatsInputRaw);
      const noteVal = (getEl("plan-req-note")?.value || "").trim();

      if (!nameVal) {
        showInlineAlert("plan-request-alert", "request.errorName");
        getEl("plan-req-name")?.focus();
        return;
      }
      if (!isValidContactInput(contactVal)) {
        showInlineAlert("plan-request-alert", "request.errorContact");
        getEl("plan-req-contact")?.focus();
        return;
      }
      if (isTeam && (!Number.isInteger(seatsRaw) || seatsRaw < 1 || seatsRaw > 5000)) {
        showInlineAlert("plan-request-alert", "request.errorSeats");
        getEl("plan-req-seats")?.focus();
        return;
      }

      const pricing = getPlanPricing(state.activeRequestPlan, lang);
      const lines = [
        `${t("request.summaryPlan", {}, lang)}: ${pricing.planName}`,
        `${t("request.summaryStatus", {}, lang)}: ${t("request.summaryStatusWaitlist", {}, lang)}`,
        `${t("request.summaryName", {}, lang)}: ${nameVal}`,
        `${t("request.summaryContact", {}, lang)}: ${contactVal}`,
      ];
      if (isTeam) {
        lines.push(`${t("request.summarySeats", {}, lang)}: ${seatsRaw}`);
      }
      if (noteVal) {
        lines.push(`${t("request.summaryNote", {}, lang)}: ${noteVal}`);
      }
      const summaryText = lines.join("\n");
      state.lastRequestSummary = summaryText;

      const previewEl = getEl("plan-request-preview");
      const resultBox = getEl("plan-request-result");
      const mailtoLink = getEl("plan-req-mailto-link");
      if (previewEl) previewEl.textContent = summaryText;
      if (mailtoLink) {
        const subject = t(
          isTeam ? "request.mailSubjectTeam" : "request.mailSubjectPro",
          {},
          lang
        );
        mailtoLink.setAttribute("href", buildMailtoHref(SITE_CONTACTS.email, subject, summaryText));
      }
      if (resultBox) resultBox.hidden = false;
    });

    getEl("plan-req-copy-btn")?.addEventListener("click", async () => {
      const text = state.lastRequestSummary || getEl("plan-request-preview")?.textContent || "";
      await copyWithFeedback({
        text,
        buttonEl: getEl("plan-req-copy-btn"),
        resetLabelGetter: () => t("request.copyBtn"),
        showStatusBanner,
      });
    });
  });

  getEl("pricing-free-start-btn")?.addEventListener("click", onStartFree);
  getEl("open-pro-modal-btn")?.addEventListener("click", (event) => {
    openPlanRequestModal("pro", event.currentTarget, state, hideInlineAlert);
  });
  getEl("open-team-modal-btn")?.addEventListener("click", (event) => {
    openPlanRequestModal("team", event.currentTarget, state, hideInlineAlert);
  });
}
