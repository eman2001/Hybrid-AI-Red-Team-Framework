/* ══════════════════════════════════════════════
   views/ai.js — AI Classifier view renderer
   ══════════════════════════════════════════════ */

function renderAI() {
  const el = document.getElementById("view-ai");
  if (!el) return;

  const srcColor = s => ({
    rule_exact:"#f43f5e", rule_service:"#fb923c",
    post_exploit:"#34d399", stix:"#fbbf24", ml:"#60a5fa", ml_fallback:"#6b7280"
  }[s] || "#6b7280");
  const srcLabel = s => ({
    rule_exact:"RULE", rule_service:"RULE",
    post_exploit:"POST-EXP", stix:"STIX", ml:"ML", ml_fallback:"ML"
  }[s] || "?");

  const layers = [
    {name:"Layer 1 — Rule Resolver", conf:"0.85 – 0.95", color:"#f43f5e",
     desc:"Deterministic match against mitre_rules.json + built-in port/CVE tables. Wins if confidence ≥ 0.85."},
    {name:"Layer 2 — STIX Lookup",   conf:"0.60 – 0.75", color:"#fbbf24",
     desc:"Inverted word index over enterprise-attack.json (MITRE CTI). Scores exploit+service text semantically."},
    {name:"Layer 3 — ML Classifier", conf:"0.50 – 0.70", color:"#60a5fa",
     desc:"TF-IDF + Random Forest (200 trees, class_weight=balanced). Overrides only when conf > current + 10%."},
    {name:"Post-Exploit Enrichment", conf:"0.90 – 0.95", color:"#34d399",
     desc:"Pattern-matches Meterpreter commands (hashdump→T1003, sysinfo→T1082, arp→T1016…) with high certainty."},
  ];

  const layerCards = layers.map(l => `
    <div style="padding:12px 14px;border-radius:8px;
      border:1px solid ${l.color}28;background:${l.color}07;margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div style="font-size:11px;font-weight:700;color:${l.color}">${l.name}</div>
        <div style="font-size:9px;color:${l.color};background:${l.color}18;
          border-radius:4px;padding:2px 8px">${l.conf}</div>
      </div>
      <div style="font-size:10px;color:var(--muted);line-height:1.7">${l.desc}</div>
    </div>`).join("");

  const metrics = [
    {label:"Accuracy",     val:"62.5%",  color:"#34d399"},
    {label:"F1 (weighted)",val:"0.617",  color:"#60a5fa"},
    {label:"CV F1 Mean",   val:"0.311",  color:"#a78bfa"},
    {label:"Training rows",val:"37",     color:"#fbbf24"},
  ];
  const metricsHtml = metrics.map(m => `
    <div style="text-align:center;padding:10px 8px;border-radius:7px;
      background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06)">
      <div style="font-size:9px;color:var(--muted);margin-bottom:4px">${m.label}</div>
      <div style="font-size:18px;font-weight:700;color:${m.color}">${m.val}</div>
    </div>`).join("");

  const resultCards = ML_RESULTS.map(r => {
    const sc = srcColor(r.layer);
    const tcColor = Object.entries(TACTIC_COLOR).find(([k]) =>
      k.toLowerCase().replace(/ /g,"-") === r.tactic
    )?.[1] || "#60a5fa";

    return `
      <div style="padding:12px 16px;border-radius:8px;
        border:1px solid rgba(255,255,255,0.06);background:rgba(255,255,255,0.025);margin-bottom:8px">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px">
          <div style="flex:1">
            <div style="font-size:11px;font-weight:700;color:var(--text)">
              ${r.exploit}
            </div>
            <div style="font-size:9px;color:var(--muted);margin-top:2px">
              ${r.service}:${r.port}
            </div>
          </div>
          <div style="text-align:right">
            ${badge(srcLabel(r.layer), sc)}
            <div style="font-size:16px;font-weight:700;color:${sc};margin-top:4px">
              ${Math.round(r.conf * 100)}%
            </div>
          </div>
        </div>

        <div style="margin:10px 0 6px">
          <div style="font-size:9px;color:var(--muted);margin-bottom:4px">PREDICTED TACTIC</div>
          ${badge(r.tactic.replace(/-/g," ").toUpperCase(), tcColor)}
        </div>

        <div class="progress-wrap" style="height:3px">
          <div class="progress-fill" style="width:${r.conf*100}%;background:${sc}"></div>
        </div>

        <div style="display:flex;gap:8px;margin-top:10px">
          ${r.top.map(t => `
            <div style="flex:1;padding:5px 8px;border-radius:5px;
              background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06)">
              <div style="font-size:8px;color:var(--muted)">${t.t}</div>
              <div style="font-size:12px;color:var(--text)">${Math.round(t.c*100)}%</div>
            </div>`).join("")}
        </div>
      </div>`;
  }).join("");

  el.innerHTML = `
    <div class="stat-grid-2">
      <div class="card">
        <div class="card-label">3-Layer Hybrid Engine</div>
        ${layerCards}
      </div>
      <div>
        <div class="card" style="margin-bottom:14px">
          <div class="card-label">Training Metrics (synthetic dataset)</div>
          <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:12px">
            ${metricsHtml}
          </div>
          <div style="font-size:9px;color:var(--muted);line-height:1.8;
            padding:8px 12px;background:rgba(255,255,255,0.02);
            border-radius:6px;border:1px solid rgba(255,255,255,0.06)">
            Note: Accuracy improves with live scan data.<br>
            Run: <code style="color:var(--cyan)">python train_mitre_model.py</code>
          </div>
        </div>
        <div class="card">
          <div class="card-label">Per-Exploit Classification Results</div>
          ${resultCards}
        </div>
      </div>
    </div>`;
}
