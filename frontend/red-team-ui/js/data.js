/* ══════════════════════════════════════════════
   data.js — Static constants only
   البيانات الحية تيجي من API عبر main.js
   ══════════════════════════════════════════════ */

/* القيم دي ما بتيجي من API */
const RISK_THRESHOLD = 0.30;

const TACTIC_COLOR = {
  "Initial Access":       "#f43f5e",
  "Execution":            "#fb923c",
  "Persistence":          "#eab308",
  "Privilege Escalation": "#a855f7",
  "Credential Access":    "#3b82f6",
  "Discovery":            "#22c55e",
  "Lateral Movement":     "#ec4899",
  "Exfiltration":         "#f43f5e",
  "Collection":           "#06b6d4",
  "Impact":               "#dc2626",
};

const TACTIC_ORDER = [
  "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Credential Access",
  "Discovery", "Lateral Movement", "Collection",
  "Exfiltration", "Impact",
];

