/* ══════════════════════════════════════════════
   views/threatintel.js — Threat Intelligence view
   ══════════════════════════════════════════════ */

function renderThreatIntel() {
  const el = document.getElementById("view-threatintel");
  if (!el) return;

  const kevCount      = THREAT_INTEL.filter(t => t.kev).length;
  const ransomCount   = THREAT_INTEL.filter(t => t.kev_ransomware).length;
  const imminentCount = THREAT_INTEL.filter(t => t.epss >= 0.9).length;
  const avgEpss       = (THREAT_INTEL.reduce((a,t) => a + t.epss, 0) / THREAT_INTEL.length).toFixed(3);

  function tierColor(s) {
    return {patch_immediately:"#f43f5e",patch_within_week:"#fb923c",monitor:"#34d399"}[s] || "#6b7280";
  }
  function epssBar(epss) {
    const pct = Math.round(epss * 100);
    const c   = epss >= 0.9 ? "#f43f5e" : epss >= 0.7 ? "#fb923c" : "#fbbf24";
    return `<div style="display:flex;align-items:center;gap:8px">
      <div style="flex:1;height:5px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden">
        <div style="width:${pct}%;height:100%;background:${c};border-radius:3px"></div>
      </div>
      <span style="font-size:10px;color:${c};font-weight:700;width:34px">${pct}%</span>
    </div>`;
  }

  const cardsHtml = THREAT_INTEL.map(t => {
    const tc = tierColor(t.tier);
    return `
      <div style="padding:14px 18px;border-radius:9px;border:1px solid ${tc}28;
        background:${tc}07;margin-bottom:8px;transition:border-color .15s"
        onmouseover="this.style.borderColor='${tc}50'"
        onmouseout="this.style.borderColor='${tc}28'">
        <div style="display:grid;grid-template-columns:160px 1fr 90px 90px;gap:14px;align-items:center">
          <div>
            ${mono(t.cve, tc, "font-size:12px;font-weight:700")}
            <div style="font-size:9px;color:var(--muted);margin-top:3px">${t.vendor} · ${t.product}</div>
          </div>
          <div>
            <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:6px">
              ${badge(t.severity.toUpperCase(), tc)}
              ${t.kev ? badge("KEV","#f43f5e") : ""}
              ${t.kev_ransomware ? badge("RANSOMWARE","#dc2626") : ""}
            </div>
            <div style="font-size:9px;color:var(--muted)">EPSS exploitation probability</div>
            ${epssBar(t.epss)}
          </div>
          <div style="text-align:center">
            <div style="font-size:9px;color:var(--muted)">CVSS</div>
            <div style="font-size:26px;font-weight:900;color:${tc};font-family:'Syne',sans-serif">${t.cvss}</div>
          </div>
          <div style="text-align:center">
            <div style="font-size:9px;color:var(--muted)">Score</div>
            <div style="font-size:22px;font-weight:900;color:${tc};font-family:'Syne',sans-serif">${t.score}</div>
            <div style="font-size:8px;color:${tc};margin-top:2px">${t.tier.replace(/_/g," ")}</div>
          </div>
        </div>
      </div>`;
  }).join("");

  // EPSS distribution mini-chart (SVG)
  const chartW = 280, chartH = 80;
  const sorted = [...THREAT_INTEL].sort((a,b) => b.epss - a.epss);
  const bW = 34, bGap = 8;
  const barsHtml = sorted.map((t, i) => {
    const h   = Math.round(t.epss * chartH);
    const x   = i * (bW + bGap);
    const c   = t.epss >= 0.9 ? "#f43f5e" : t.epss >= 0.7 ? "#fb923c" : "#fbbf24";
    const lbl = t.cve.slice(-4);
    return `<g>
      <rect x="${x}" y="${chartH-h}" width="${bW}" height="${h}" rx="3" fill="${c}" opacity="0.85"/>
      <text x="${x+bW/2}" y="${chartH+12}" text-anchor="middle" fill="rgba(241,245,249,0.35)" font-size="8">${lbl}</text>
      <text x="${x+bW/2}" y="${chartH-h-4}" text-anchor="middle" fill="${c}" font-size="9" font-weight="700">${Math.round(t.epss*100)}%</text>
    </g>`;
  }).join("");

  el.innerHTML = `
    <!-- Stats row -->
    <div class="stat-grid-4" style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
      <div class="stat-card" style="border-color:rgba(244,63,94,0.22)">
        <div class="card-label">KEV Confirmed</div>
        <div class="stat-value" style="color:var(--critical)">${kevCount}</div>
        <div class="stat-sub">active exploitation</div>
        <div style="height:2px;background:var(--critical);border-radius:0 0 10px 10px;position:absolute;bottom:0;left:0;right:0"></div>
      </div>
      <div class="stat-card" style="border-color:rgba(220,38,38,0.22)">
        <div class="card-label">Ransomware Risk</div>
        <div class="stat-value" style="color:#dc2626">${ransomCount}</div>
        <div class="stat-sub">ransomware-linked CVEs</div>
        <div style="height:2px;background:#dc2626;border-radius:0 0 10px 10px;position:absolute;bottom:0;left:0;right:0"></div>
      </div>
      <div class="stat-card" style="border-color:rgba(251,146,60,0.22)">
        <div class="card-label">Imminent (EPSS≥90%)</div>
        <div class="stat-value" style="color:var(--high)">${imminentCount}</div>
        <div class="stat-sub">patch immediately</div>
        <div style="height:2px;background:var(--high);border-radius:0 0 10px 10px;position:absolute;bottom:0;left:0;right:0"></div>
      </div>
      <div class="stat-card" style="border-color:rgba(96,165,250,0.22)">
        <div class="card-label">Avg EPSS Score</div>
        <div class="stat-value" style="color:var(--blue)">${avgEpss}</div>
        <div class="stat-sub">exploitation probability</div>
        <div style="height:2px;background:var(--blue);border-radius:0 0 10px 10px;position:absolute;bottom:0;left:0;right:0"></div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 300px;gap:14px;margin-bottom:14px">
      <!-- Formula -->
      <div class="card">
        <div class="card-label">Composite Threat Score Formula</div>
        <div style="padding:10px 14px;background:#030508;border-radius:7px;font-family:monospace;font-size:11px;line-height:2;color:#86efac">
          Score = (CVSS × 4.0) + (EPSS × 25.0) + KEV_BONUS(+20) + RANSOM_BONUS(+5)<br>
          <span style="color:rgba(134,239,172,0.5)">Max Score = 100.0  |  Threshold: ≥80 = CRITICAL</span>
        </div>
        <div style="display:flex;gap:12px;margin-top:10px;font-size:9px;color:var(--muted)">
          <span>CVSS: NVD/embedded DB</span>
          <span>EPSS: FIRST.org API</span>
          <span>KEV: CISA catalog</span>
        </div>
      </div>
      <!-- EPSS Chart -->
      <div class="card">
        <div class="card-label">EPSS Distribution</div>
        <svg viewBox="0 0 ${sorted.length*(bW+bGap)-bGap+10} ${chartH+20}" style="width:100%;overflow:visible">
          <line x1="0" y1="${chartH}" x2="${sorted.length*(bW+bGap)}" y2="${chartH}" stroke="rgba(255,255,255,0.06)" stroke-width="1"/>
          ${barsHtml}
        </svg>
      </div>
    </div>

    <!-- Cards -->
    <div class="card">
      <div class="card-label">CVE Threat Intelligence — CVSS · EPSS · CISA KEV</div>
      ${cardsHtml}
    </div>`;
}
