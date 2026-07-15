/* ══════════════════════════════════════════════
   views/dashboard.js — Dashboard view renderer
   ══════════════════════════════════════════════ */

function renderDashboard() {
  const el = document.getElementById("view-dashboard");

  const successCount = EXPLOITS.filter(e => e.result === "SUCCESS").length;
  const aboveThresh  = VULNS.filter(v => v.risk >= RISK_THRESHOLD).length;

  // Bar chart data
  const barData = [...VULNS]
    .sort((a, b) => b.risk - a.risk)
    .map(v => ({
      label: v.cve.replace("CVE-", ""),
      val:   Math.round(v.risk * 100),
      color: v.risk >= RISK_THRESHOLD ? "var(--high)" : "var(--safe)",
    }));

  el.innerHTML = `
    <!-- Stat row -->
    <div class="stat-grid">
      <div class="stat-card" style="border-color:rgba(6,182,212,0.27);box-shadow:0 0 18px rgba(6,182,212,0.09)">
        <div class="card-label">Hosts Discovered</div>
        <div class="stat-value" style="color:var(--cyan)">1</div>
        <div class="stat-sub">live, scanned</div>
      </div>
      <div class="stat-card" style="border-color:rgba(239,68,68,0.27);box-shadow:0 0 18px rgba(239,68,68,0.09)">
        <div class="card-label">Vulnerabilities</div>
        <div class="stat-value" style="color:var(--critical)">${VULNS.length}</div>
        <div class="stat-sub">${aboveThresh} above threshold</div>
      </div>
      <div class="stat-card" style="border-color:rgba(249,115,22,0.27);box-shadow:0 0 18px rgba(249,115,22,0.09)">
        <div class="card-label">Successful Exploits</div>
        <div class="stat-value" style="color:var(--high)">${successCount}/${EXPLOITS.length}</div>
        <div class="stat-sub">attempts</div>
      </div>
      <div class="stat-card" style="border-color:rgba(168,85,247,0.27);box-shadow:0 0 18px rgba(168,85,247,0.09)">
        <div class="card-label">Rules Fired</div>
        <div class="stat-value" style="color:var(--purple)">8</div>
        <div class="stat-sub">R0–R10</div>
      </div>
    </div>

    <!-- Charts -->
    <div class="chart-grid">

      <!-- Pie -->
      <div class="card">
        <div class="card-label">Severity Distribution</div>
        <svg viewBox="0 0 160 120" style="width:100%;max-height:150px">
          <circle cx="80" cy="60" r="40" fill="none" stroke="var(--critical)" stroke-width="20"
            stroke-dasharray="100.5 150.7" stroke-dashoffset="0" transform="rotate(-90 80 60)"/>
          <circle cx="80" cy="60" r="40" fill="none" stroke="var(--high)" stroke-width="20"
            stroke-dasharray="50.3 201" stroke-dashoffset="-100.5" transform="rotate(-90 80 60)"/>
          <circle cx="80" cy="60" r="40" fill="none" stroke="var(--medium)" stroke-width="20"
            stroke-dasharray="50.3 201" stroke-dashoffset="-150.8" transform="rotate(-90 80 60)"/>
          <circle cx="80" cy="60" r="40" fill="none" stroke="var(--low)" stroke-width="20"
            stroke-dasharray="50.3 201" stroke-dashoffset="-201.1" transform="rotate(-90 80 60)"/>
          <text x="80" y="55" text-anchor="middle" fill="var(--text)" font-size="14" font-weight="900" font-family="Syne">5</text>
          <text x="80" y="69" text-anchor="middle" fill="var(--muted)" font-size="8">vulns</text>
        </svg>
        <div class="pie-legend">
          <div class="pie-legend-item"><div class="pie-dot" style="background:var(--critical)"></div>Critical (≥9): 2</div>
          <div class="pie-legend-item"><div class="pie-dot" style="background:var(--high)"></div>High (7–9): 1</div>
          <div class="pie-legend-item"><div class="pie-dot" style="background:var(--medium)"></div>Medium (4–7): 1</div>
          <div class="pie-legend-item"><div class="pie-dot" style="background:var(--low)"></div>Low (&lt;4): 1</div>
        </div>
      </div>

      <!-- Bar chart -->
      <div class="card">
        <div class="card-label">Risk Score (threshold = ${RISK_THRESHOLD})</div>
        <div class="bar-chart">
          ${barData.map(b => `
            <div class="bar-col">
              <div class="bar-fill" style="height:${b.val}%;background:${b.color};max-height:120px"></div>
              <div class="bar-label">${b.label.substring(0, 7)}</div>
            </div>`).join("")}
        </div>
        <div style="display:flex;gap:14px;margin-top:8px">
          <span style="font-size:11px;color:var(--high)">■ Above threshold (≥${RISK_THRESHOLD})</span>
          <span style="font-size:11px;color:var(--safe)">■ Below threshold</span>
        </div>
      </div>

      <!-- Radar (SVG) -->
      <div class="card">
        <div class="card-label">MITRE Tactic Coverage</div>
        <svg viewBox="0 0 160 150" style="width:100%">
          <g transform="translate(80,75)">
            <polygon points="0,-55 47.6,-27.5 47.6,27.5 0,55 -47.6,27.5 -47.6,-27.5"
              fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>
            <polygon points="0,-38 33,-19 33,19 0,38 -33,19 -33,-19"
              fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
            <polygon points="0,-20 17,-10 17,10 0,20 -17,10 -17,-10"
              fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="1"/>
            <polygon points="0,-50 40,-20 35,22 0,45 -38,20 -30,-25"
              fill="rgba(168,85,247,0.25)" stroke="var(--purple)" stroke-width="1.5"/>
            <text y="-60" text-anchor="middle" fill="var(--muted)" font-size="8">Initial</text>
            <text x="54" y="-30" fill="var(--muted)" font-size="8">Exec</text>
            <text x="50" y="36" fill="var(--muted)" font-size="8">Persist</text>
            <text y="66" text-anchor="middle" fill="var(--muted)" font-size="8">Lateral</text>
            <text x="-68" y="36" fill="var(--muted)" font-size="8">Cred</text>
            <text x="-68" y="-30" fill="var(--muted)" font-size="8">Disc</text>
          </g>
        </svg>
      </div>
    </div>

    <!-- Pipeline modules -->
    <div class="card">
      <div class="card-label">Pipeline Modules — Session ${SESSION.id}</div>
      <div class="pipeline-grid">
        ${[["🔍","Recon"],["📡","Scanning"],["🧬","Vuln Map"],["⚡","Exploitation"],["🔓","Post Exploit"],["📄","Reporting"]]
          .map(([icon, name]) => `
            <div class="pipeline-module">
              <div class="pipeline-icon">${icon}</div>
              <div class="pipeline-name">${name}</div>
              <div style="margin-top:8px">${badge("DONE","var(--low)")}</div>
            </div>`).join("")}
      </div>
    </div>`;
}
