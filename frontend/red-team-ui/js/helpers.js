/* ══════════════════════════════════════════════
   helpers.js — Shared utility functions
   ══════════════════════════════════════════════ */


const RULE_COLOR = {
  R0:"var(--cyan)", R1:"var(--cyan)", R2:"var(--medium)",
  R3:"var(--blue)", R4:"var(--blue)", R5:"var(--blue)",
  R6:"var(--high)", R7:"var(--critical)", R8:"var(--critical)",
  R9:"var(--purple)", R10:"var(--low)"
};

/** CVSS → CSS color variable */
function cvssColor(score) {
  if (score >= 9) return "var(--critical)";
  if (score >= 7) return "var(--high)";
  if (score >= 4) return "var(--medium)";
  return "var(--low)";
}

/** CVSS → label string */
function cvssLabel(score) {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

/** Risk score → CSS color variable */
function riskColor(r) {
  return r >= RISK_THRESHOLD ? "var(--high)" : "var(--safe)";
}

/** Render a colored badge span */
function badge(label, color) {
  return `<span class="badge" style="background:${color}1a;color:${color};border:1px solid ${color}44">${label}</span>`;
}

/** Render a monospace span */
function mono(text, color = "var(--text)", extraStyle = "") {
  return `<span class="mono" style="color:${color};${extraStyle}">${text}</span>`;
}

/** Log line → CSS color */
function logLineColor(line) {
  if (line.includes("✓"))                          return "var(--low)";
  if (line.includes("[MODULE"))                    return "var(--cyan)";
  if (line.includes("CVE-"))                       return "var(--high)";
  if (line.includes("Risk:") || line.includes("risk=")) return "var(--purple)";
  if (line.includes("ROOT") || line.includes("SUCCESS")) return "var(--low)";
  if (line.includes("[+]"))                        return "#86efac";
  if (line.includes("[-]"))                        return "var(--muted)";
  if (line.includes("[*]"))                        return "var(--blue)";
  return "var(--muted)";
}
