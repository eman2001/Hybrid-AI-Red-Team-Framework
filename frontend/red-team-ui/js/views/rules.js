/* ══════════════════════════════════════════════
   views/rules.js — Rule Trace view renderer
   ══════════════════════════════════════════════ */

function renderRules() {
  const el = document.getElementById("view-rules");

  const rowsHtml = RULES.map(r => {
    const c = RULE_COLOR[r.rule] || "var(--muted)";
    return `
      <div class="rule-row" style="border-color:${c}22">
        ${badge(r.rule, c)}
        ${mono(r.cond,           "var(--muted)", "font-size:12px")}
        ${mono("→ " + r.action,  "var(--text)",  "font-size:12px")}
      </div>`;
  }).join("");

  el.innerHTML = `
    <div class="card">
      <div class="card-label">Rule Execution Trace — Explainability Log</div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:16px;font-family:monospace">
        Every decision made by the framework is logged here. R0–R10 from the Rule Table.
      </div>
      ${rowsHtml}
    </div>`;
}
