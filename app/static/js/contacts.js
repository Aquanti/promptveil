/**
 * Centralized PromptVeil owner contacts & safe mailto builder.
 * Zero external HTTP(S) URLs to comply with strict CSP and static hygiene checks.
 */

export const SITE_CONTACTS = Object.freeze({
  telegramHandle: "@supv1rus",
  email: "kilkauciha@gmail.com",
  githubHandle: "@Aquanti",
  githubDisplay: "github.com/Aquanti",
  authorSignature: "SupV1rus",
});

export function buildMailtoHref(email = SITE_CONTACTS.email, subject = "", body = "") {
  const params = [];
  if (subject) {
    params.push(`subject=${encodeURIComponent(subject)}`);
  }
  if (body) {
    params.push(`body=${encodeURIComponent(body)}`);
  }
  const query = params.length > 0 ? `?${params.join("&")}` : "";
  return `mailto:${email}${query}`;
}
