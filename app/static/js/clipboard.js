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

let proDocsPromise = null;

function loadProDocuments() {
  if (!proDocsPromise) {
    proDocsPromise = import("./pro-documents.js").catch((err) => {
      proDocsPromise = null;
      throw err;
    });
  }
  return proDocsPromise;
}

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
  isProActive = () => false,
  isBatchActive = () => false,
  showStatusBanner,
  showInlineAlert,
  hideInlineAlert,
  showProUpgradePrompt = null,
  hideProUpgradePrompt = null,
  cancelPendingLiveSanitize,
  cancelPendingLiveAudit,
  onPromptFileLoaded,
  onBatchFilesLoaded = null,
  onRulesImported,
}) {
  let activeFileReadId = 0;

  function cancelPendingFileRead() {
    activeFileReadId += 1;
    const loading = getEl("file-loading-indicator");
    if (loading) loading.hidden = true;
  }

  function readPlainTextFallback(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || "").replace(/^\uFEFF/, ""));
      reader.onerror = () => reject(new Error("FILE_READ_ERROR"));
      reader.readAsText(file, "UTF-8");
    });
  }

  async function handleLocalFiles(fileList) {
    hideInlineAlert("input-error-banner");
    hideProUpgradePrompt?.();

    const files = Array.from(fileList || []).filter(Boolean);
    if (files.length === 0) return;

    const startReadId = activeFileReadId;
    let proDocs;
    try {
      proDocs = await loadProDocuments();
    } catch {
      if (startReadId !== activeFileReadId) return;
      showInlineAlert("input-error-banner", "banner.fileReadError", {
        name: files[0]?.name || "",
      });
      return;
    }
    if (startReadId !== activeFileReadId) return;

    const {
      PRO_DOCUMENT_EXTENSIONS,
      getDocumentErrorI18nKey,
      getFileExtension,
      parseDocumentFile,
      validateBatchFiles,
    } = proDocs;

    const isPro = Boolean(isProActive?.());
    const { accepted, rejection } = validateBatchFiles(files, { isPro });
    if (rejection) {
      if (rejection.code === "free_too_large") {
        showInlineAlert("input-error-banner", "banner.fileTooLarge", { name: rejection.fileName });
        showProUpgradePrompt?.("size", rejection);
      } else if (rejection.code === "pro_format") {
        showInlineAlert("input-error-banner", "banner.fileProFormatRequired", {
          ext: rejection.ext || "—",
        });
        showProUpgradePrompt?.("format", rejection);
      } else if (rejection.code === "pro_multi_file") {
        showInlineAlert("input-error-banner", "banner.fileProBatchRequired", {
          count: rejection.count || files.length,
        });
        showProUpgradePrompt?.("batch", rejection);
      } else if (rejection.code === "pro_too_large") {
        showInlineAlert("input-error-banner", "banner.fileTooLargePro", {
          name: rejection.fileName,
        });
      } else {
        showInlineAlert(
          "input-error-banner",
          isPro ? "banner.fileUnsupportedPro" : "banner.fileUnsupported",
          { ext: rejection.ext || "—" }
        );
      }
      return;
    }

    const firstExt = getFileExtension(accepted[0]?.name || "");
    const useBatch =
      isPro &&
      typeof onBatchFilesLoaded === "function" &&
      (accepted.length > 1 ||
        PRO_DOCUMENT_EXTENSIONS.has(firstExt) ||
        Boolean(isBatchActive?.()));

    cancelPendingLiveSanitize();
    cancelPendingLiveAudit();
    const readId = ++activeFileReadId;
    const loading = getEl("file-loading-indicator");
    if (loading) loading.hidden = false;

    try {
      if (!useBatch) {
        const file = accepted[0];
        const text =
          typeof file.arrayBuffer === "function"
            ? (await parseDocumentFile(file)).text
            : await readPlainTextFallback(file);
        if (readId !== activeFileReadId) return;
        onPromptFileLoaded(text, file.name);
        return;
      }

      const parsedItems = [];
      for (const file of accepted) {
        if (readId !== activeFileReadId) return;
        const ext = getFileExtension(file.name);
        try {
          const parsed = await parseDocumentFile(file);
          parsedItems.push({
            name: file.name,
            ext: parsed.ext || ext,
            size: Number(file.size || parsed.size || 0),
            status: "ok",
            text: parsed.text || "",
            isScannedPdf: Boolean(parsed.isScannedPdf),
            errorCode: "",
          });
        } catch (err) {
          parsedItems.push({
            name: file.name,
            ext,
            size: Number(file.size || 0),
            status: "error",
            text: "",
            isScannedPdf: false,
            errorCode: err?.code || "DOCUMENT_PARSE_ERROR",
          });
        }
      }

      if (readId !== activeFileReadId) return;
      if (parsedItems.every((item) => item.status === "error")) {
        const firstErr = parsedItems[0];
        if (parsedItems.length === 1) {
          showInlineAlert("input-error-banner", getDocumentErrorI18nKey(firstErr.errorCode));
        } else {
          showInlineAlert("input-error-banner", "banner.fileCorrupt", { name: firstErr.name });
        }
      }
      onBatchFilesLoaded(parsedItems);
    } catch {
      if (readId !== activeFileReadId) return;
      showInlineAlert("input-error-banner", "banner.fileReadError", {
        name: accepted[0]?.name || "",
      });
    } finally {
      if (readId === activeFileReadId && loading) {
        loading.hidden = true;
      }
    }
  }

  function handleLocalFile(file) {
    return handleLocalFiles(file ? [file] : []);
  }

  function bindFileAndRuleImportEvents() {
    const fileInput = getEl("file-upload-input");
    getEl("upload-file-btn")?.addEventListener("click", () => fileInput?.click());
    fileInput?.addEventListener("change", (event) => {
      const files = event.target.files;
      if (files && files.length > 0) {
        void handleLocalFiles(files);
      }
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
      const files = event.dataTransfer?.files;
      if (files && files.length > 0) {
        void handleLocalFiles(files);
      }
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
    handleLocalFiles,
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
