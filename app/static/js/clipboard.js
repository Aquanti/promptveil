/**
 * PromptVeil Clipboard, File Reader, and Rulebook Import/Download Helpers.
 * Zero network transfer; all file and clipboard operations stay inside the browser.
 */

import {
  copyTextToClipboard,
  downloadTextFile,
  getEl,
  readTextFromClipboard,
  showCopyFeedback,
} from "./dom.js";
import { t } from "./i18n.js";
import { importRulesJson } from "./storage.js";

export {
  copyTextToClipboard,
  downloadTextFile,
  readTextFromClipboard,
  showCopyFeedback,
};

export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const ALLOWED_EXTENSIONS = new Set([".txt", ".md", ".csv", ".json", ".log", ".env"]);

export function translateImportError() {
  return "rulebook.importBadJson";
}

export async function copyWithFeedback({
  text,
  buttonEl = null,
  resetLabelGetter = null,
  showStatusBanner,
  skipEmpty = false,
}) {
  if (skipEmpty && !text) return false;
  const ok = await copyTextToClipboard(text);
  if (ok && buttonEl && typeof resetLabelGetter === "function") {
    showCopyFeedback(buttonEl, t("action.copiedFeedback"), resetLabelGetter);
  }
  showStatusBanner(ok ? "banner.copied" : "banner.copyFailed", {}, !ok);
  return ok;
}

export function createFileController({
  getRules,
  showStatusBanner,
  showInlineAlert,
  hideInlineAlert,
  cancelPendingLiveSanitize,
  cancelPendingLiveAudit,
  onPromptFileLoaded,
  onRulesImported,
}) {
  let activeFileReadId = 0;

  function cancelPendingFileRead() {
    activeFileReadId += 1;
    const loading = getEl("file-loading-indicator");
    if (loading) loading.hidden = true;
  }

  function handleLocalFile(file) {
    hideInlineAlert("input-error-banner");
    if (!file) return;

    const lowerName = file.name.toLowerCase();
    const dotIdx = lowerName.lastIndexOf(".");
    const ext = dotIdx >= 0 ? lowerName.slice(dotIdx) : "";
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      showInlineAlert("input-error-banner", "banner.fileUnsupported", {
        ext: ext || "—",
      });
      return;
    }

    if (file.size > MAX_FILE_BYTES) {
      showInlineAlert("input-error-banner", "banner.fileTooLarge", { name: file.name });
      return;
    }

    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    const readId = ++activeFileReadId;
    const loading = getEl("file-loading-indicator");
    if (loading) loading.hidden = false;

    const reader = new FileReader();
    reader.onload = () => {
      if (readId !== activeFileReadId) return;
      if (loading) loading.hidden = true;
      onPromptFileLoaded(String(reader.result || ""), file.name);
    };
    reader.onerror = () => {
      if (readId !== activeFileReadId) return;
      if (loading) loading.hidden = true;
      showInlineAlert("input-error-banner", "banner.fileReadError", { name: file.name });
    };
    reader.readAsText(file, "UTF-8");
  }

  function bindFileAndRuleImportEvents() {
    const fileInput = getEl("file-upload-input");
    getEl("upload-file-btn")?.addEventListener("click", () => fileInput?.click());
    fileInput?.addEventListener("change", (event) => {
      const file = event.target.files?.[0];
      if (file) handleLocalFile(file);
      event.target.value = "";
    });

    const dropzone = getEl("input-dropzone");
    dropzone?.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropzone.classList.add("is-dragover");
    });
    dropzone?.addEventListener("dragleave", () => {
      dropzone.classList.remove("is-dragover");
    });
    dropzone?.addEventListener("drop", (event) => {
      event.preventDefault();
      dropzone.classList.remove("is-dragover");
      const file = event.dataTransfer?.files?.[0];
      if (file) handleLocalFile(file);
    });

    const importInput = getEl("import-rules-input");
    getEl("import-rules-btn")?.addEventListener("click", () => importInput?.click());
    importInput?.addEventListener("change", (event) => {
      const file = event.target.files?.[0];
      event.target.value = "";
      if (!file) return;
      hideInlineAlert("rulebook-alert");

      const lowerName = file.name.toLowerCase();
      const dotIdx = lowerName.lastIndexOf(".");
      const ext = dotIdx >= 0 ? lowerName.slice(dotIdx) : "";
      if (ext !== ".json") {
        showInlineAlert("rulebook-alert", "rulebook.importInvalidExt", {
          ext: ext || "—",
        });
        return;
      }

      if (file.size > MAX_FILE_BYTES) {
        showInlineAlert("rulebook-alert", "rulebook.importTooLarge", { name: file.name });
        return;
      }

      const reader = new FileReader();
      reader.onload = () => {
        try {
          const imported = importRulesJson(String(reader.result || ""), getRules());
          onRulesImported(imported);
        } catch (err) {
          showInlineAlert("rulebook-alert", translateImportError(err));
        }
      };
      reader.onerror = () => {
        showInlineAlert("rulebook-alert", "rulebook.importReadError");
      };
      reader.readAsText(file, "UTF-8");
    });
  }

  return {
    cancelPendingFileRead,
    handleLocalFile,
    bindFileAndRuleImportEvents,
  };
}

export async function readClipboardForInput({ inputEl, showStatusBanner, onTextRead }) {
  const res = await readTextFromClipboard();
  if (!res.ok) {
    inputEl?.focus();
    showStatusBanner("banner.pasteFallback", {}, true);
    return;
  }
  if (!res.text.trim()) {
    inputEl?.focus();
    showStatusBanner("banner.clipboardEmpty");
    return;
  }
  onTextRead(res.text);
  showStatusBanner("banner.pasted");
}
