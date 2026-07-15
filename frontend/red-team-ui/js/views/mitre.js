/* ══════════════════════════════════════════════
   views/mitre.js — MITRE ATT&CK view (v2)
   ══════════════════════════════════════════════ */

function renderMitre() {
  const el = document.getElementById("view-mitre");
  const totalTech  = Object.values(MITRE).reduce((a, arr) => a + arr.length, 0);
  const tacticsCov = Object.keys(MITRE).length;

  const srcColor = s => ({
    rule_exact:"#f43f5e",rule_service:"#fb923c",rule_cve:"#fb923c",
    post_exploit:"#34d399",stix:"#fbbf24",ml:"#60a5fa"
  }[s] || "#6b7280");
  const srcLabel = s => ({
    rule_exact:"RULE",rule_service:"RULE",rule_cve:"RULE",
    post_exploit:"POST-EXP",stix:"STIX",ml:"ML"
  }[s] || "?");

  const cardsHtml = Object.entries(MITRE).map(([tactic, techs]) => {
    const c = TACTIC_COLOR[tactic] || "var(--purple)";

    const techsHtml = techs.map(t => {
      const sc = srcColor(t.src || "ml");
      return `
        <div class="mitre-tech" style="background:${c}10;border:1px solid ${c}30">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <span class="mitre-id mono" style="color:${c}">${t.id}</span>
            <span class="badge" style="background:${sc}18;color:${sc};
              border:1px solid ${sc}40;font-size:8px">${srcLabel(t.src)}</span>
          </div>
          <div class="mitre-name">${t.name}</div>
          ${t.detail ? `<div class="mitre-detail mono">via: ${t.detail}</div>` : ""}
          ${t.conf !== undefined ? `
            <div style="display:flex;align-items:center;gap:6px;margin-top:6px">
              <div class="progress-wrap" style="flex:1;height:2px">
                <div class="progress-fill" style="width:${Math.round((t.conf||0)*100)}%;background:${sc}"></div>
              </div>
              <span style="font-size:8px;color:${sc}">${Math.round((t.conf||0)*100)}%</span>
            </div>` : ""}
        </div>`;
    }).join("");

    return `
      <div class="card mitre-card" style="border-color:${c}44;box-shadow:0 0 18px ${c}10">
        <div class="mitre-tactic-header">
          <div class="mitre-dot" style="background:${c};box-shadow:0 0 8px ${c}"></div>
          ${mono(tactic, c, "font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase")}
          <span style="font-size:9px;color:var(--muted);margin-left:auto">
            ${techs.length} technique${techs.length > 1 ? "s" : ""}
          </span>
        </div>
        <div class="mitre-techniques">${techsHtml}</div>
      </div>`;
  }).join("");

  el.innerHTML = `
    <div class="stat-grid-2">
      <div class="stat-card" style="border-color:rgba(168,85,247,0.27)">
        <div class="card-label">Techniques Mapped</div>
        <div class="stat-value" style="color:var(--purple)">${totalTech}</div>
      </div>
      <div class="stat-card" style="border-color:rgba(6,182,212,0.27)">
        <div class="card-label">Tactics Covered</div>
        <div class="stat-value" style="color:var(--cyan)">${tacticsCov}/14</div>
      </div>
    </div>

    <div style="display:flex;flex-wrap:wrap;gap:10px;font-size:9px;color:var(--muted)">
      <div>Color coding:</div>
      <span class="badge" style="background:#f43f5e18;color:#f43f5e;border:1px solid #f43f5e40">RULE</span> 0.85–0.95 &nbsp;
      <span class="badge" style="background:#fbbf2418;color:#fbbf24;border:1px solid #fbbf2440">STIX</span> 0.60–0.75 &nbsp;
      <span class="badge" style="background:#60a5fa18;color:#60a5fa;border:1px solid #60a5fa40">ML</span> 0.50–0.70 &nbsp;
      <span class="badge" style="background:#34d39918;color:#34d399;border:1px solid #34d39940">POST-EXP</span> 0.90–0.95
    </div>

    ${cardsHtml}`;
}
