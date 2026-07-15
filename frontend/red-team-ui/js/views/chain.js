/* ══════════════════════════════════════════════
   views/chain.js — Attack Chain view renderer
   ══════════════════════════════════════════════ */

function renderChain() {
  const el = document.getElementById("view-chain");
  if (!el) return;

  const srcColor = s => ({
    rule_exact:"#f43f5e", rule_service:"#fb923c", rule_cve:"#fb923c",
    post_exploit:"#34d399", stix:"#fbbf24", ml:"#60a5fa", ml_fallback:"#6b7280"
  }[s] || "#6b7280");

  const srcLabel = s => ({
    rule_exact:"RULE", rule_service:"RULE", rule_cve:"RULE",
    post_exploit:"POST-EXP", stix:"STIX", ml:"ML", ml_fallback:"ML"
  }[s] || "?");

  const totalTechs = ATTACK_CHAIN.reduce((a,p) => a + p.techniques.length, 0);
  const avgConf    = Math.round(ATTACK_CHAIN.reduce((a,p) => a + p.conf, 0) / ATTACK_CHAIN.length * 100);

  const chainHtml = ATTACK_CHAIN.map(ph => {
    const sc = srcColor(ph.src);
    const techBadges = ph.techniques.map(t =>
      `<div style="padding:4px 10px;border-radius:5px;border:1px solid ${ph.color}30;
        background:${ph.color}10;display:inline-flex;align-items:center;gap:6px;margin:3px">
        <span style="font-size:10px;font-weight:700;color:${ph.color}">${t.id}</span>
        <span style="font-size:9px;color:rgba(241,245,249,0.6)">${t.name}</span>
      </div>`
    ).join("");

    return `
      <div style="display:grid;grid-template-columns:28px 28px 1fr 72px;gap:8px;
        align-items:start;margin-bottom:8px">
        <div style="font-size:10px;color:rgba(241,245,249,0.3);padding-top:12px;text-align:right">
          ${ph.phase}
        </div>
        <div style="display:flex;flex-direction:column;align-items:center;padding-top:8px">
          <div style="width:12px;height:12px;border-radius:50%;background:${ph.color};
            box-shadow:0 0 8px ${ph.color}80;flex-shrink:0"></div>
          ${ph.phase < ATTACK_CHAIN.length
            ? `<div style="width:2px;flex:1;min-height:36px;
                background:linear-gradient(180deg,${ph.color}60,rgba(255,255,255,0.04));
                margin-top:3px"></div>` : ""}
        </div>
        <div style="padding:10px 14px;border-radius:8px;
          border:1px solid ${ph.color}22;background:${ph.color}06">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="font-size:12px;font-weight:700;color:${ph.color}">${ph.name}</span>
            <span style="font-size:8px;color:rgba(241,245,249,0.3);
              text-transform:uppercase;letter-spacing:1.5px">${ph.tactic}</span>
          </div>
          <div style="display:flex;flex-wrap:wrap">${techBadges}</div>
        </div>
        <div style="padding-top:10px;text-align:right">
          ${badge(srcLabel(ph.src), sc)}
          <div style="font-size:13px;font-weight:700;color:${sc};margin-top:5px">
            ${Math.round(ph.conf * 100)}%
          </div>
          <div class="progress-wrap" style="height:2px;margin-top:4px">
            <div class="progress-fill" style="width:${ph.conf*100}%;background:${sc}"></div>
          </div>
        </div>
      </div>`;
  }).join("");

  // Heatmap cells
  const heatCells = ATTACK_CHAIN.flatMap(ph =>
    ph.techniques.map(t => `
      <div style="padding:7px 9px;border-radius:6px;cursor:default;
        background:${ph.color}28;border:1px solid ${ph.color}40;
        transition:transform .15s" onmouseover="this.style.transform='scale(1.06)'"
        onmouseout="this.style.transform='scale(1)'" title="${t.id}: ${t.name} (${Math.round(ph.conf*100)}%)">
        <div style="font-size:10px;font-weight:700;color:${ph.color};margin-bottom:2px">${t.id}</div>
        <div style="font-size:8px;color:rgba(241,245,249,0.55);line-height:1.3">
          ${t.name.substring(0, 18)}
        </div>
        <div style="font-size:7px;color:rgba(241,245,249,0.3);margin-top:3px">
          ${Math.round(ph.conf*100)}%
        </div>
      </div>`)
  ).join("");

  el.innerHTML = `
    <div class="stat-grid-3">
      <div class="stat-card" style="border-color:rgba(244,63,94,0.22)">
        <div class="card-label">Kill-Chain Phases</div>
        <div class="stat-value" style="color:var(--critical)">${ATTACK_CHAIN.length}</div>
      </div>
      <div class="stat-card" style="border-color:rgba(251,146,60,0.22)">
        <div class="card-label">Total Techniques</div>
        <div class="stat-value" style="color:var(--high)">${totalTechs}</div>
      </div>
      <div class="stat-card" style="border-color:rgba(96,165,250,0.22)">
        <div class="card-label">Avg Confidence</div>
        <div class="stat-value" style="color:var(--blue)">${avgConf}%</div>
      </div>
    </div>

    <div class="card">
      <div class="card-label">Kill-Chain — ATT&CK Phase Sequence</div>
      ${chainHtml}
    </div>

    <div class="card">
      <div class="card-label">ATT&CK Navigator Heatmap Preview</div>
      <div style="font-size:10px;color:var(--muted);margin-bottom:12px">
        Import <code style="background:rgba(255,255,255,0.06);padding:1px 6px;border-radius:3px">
        reports/attack_layer_*.json</code> at
        <span style="color:var(--blue)">mitre-attack.github.io/attack-navigator</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(90px,1fr));gap:5px">
        ${heatCells}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:14px">
        ${badge("RULE","#f43f5e")} <span style="font-size:9px;color:var(--muted)">conf ≥0.85</span>&nbsp;
        ${badge("STIX","#fbbf24")} <span style="font-size:9px;color:var(--muted)">conf 0.65–0.85</span>&nbsp;
        ${badge("ML","#60a5fa")}   <span style="font-size:9px;color:var(--muted)">conf &lt;0.65</span>&nbsp;
        ${badge("POST-EXP","#34d399")} <span style="font-size:9px;color:var(--muted)">session evidence</span>
      </div>
    </div>`;
}
