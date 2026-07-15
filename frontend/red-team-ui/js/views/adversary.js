/* ══════════════════════════════════════════════
   views/adversary.js — Adversary Profiles view
   ══════════════════════════════════════════════ */

function renderAdversary() {
  const el = document.getElementById("view-adversary");
  if (!el) return;

  const bestMatch = [...ADVERSARY_PROFILES].sort((a,b) => b.similarity - a.similarity)[0];

  // Similarity gauge SVG
  function gauge(pct, color) {
    const r = 36, cx = 50, cy = 50;
    const circ = Math.PI * r;
    const dash  = (pct / 100) * circ;
    return `<svg viewBox="0 0 100 60" style="width:100%">
      <path d="M ${cx-r},${cy} A ${r},${r} 0 0 1 ${cx+r},${cy}"
        fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10" stroke-linecap="round"/>
      <path d="M ${cx-r},${cy} A ${r},${r} 0 0 1 ${cx+r},${cy}"
        fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round"
        stroke-dasharray="${dash} ${circ}" opacity="0.9"/>
      <text x="${cx}" y="${cy}-2" text-anchor="middle" fill="${color}"
        font-size="16" font-weight="900" font-family="Syne,sans-serif"
        dominant-baseline="auto" dy="-4">${pct}%</text>
      <text x="${cx}" y="${cy}+12" text-anchor="middle" fill="rgba(241,245,249,0.4)"
        font-size="8" dy="10">similarity</text>
    </svg>`;
  }

  // Technique overlap bar
  function overlapBar(profile) {
    const allT   = profile.techniques.length;
    const matched= profile.matched.length;
    const pct    = Math.round(matched / allT * 100);
    return `
      <div style="margin-top:10px">
        <div style="display:flex;justify-content:space-between;font-size:9px;color:var(--muted);margin-bottom:4px">
          <span>Technique overlap</span>
          <span style="color:${profile.color}">${matched}/${allT} (${pct}%)</span>
        </div>
        <div style="height:4px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden">
          <div style="width:${pct}%;height:100%;background:${profile.color};border-radius:2px"></div>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:7px">
          ${profile.techniques.map(t => {
            const isMatch = profile.matched.includes(t);
            return `<span style="padding:2px 7px;border-radius:3px;font-size:8px;font-weight:700;
              background:${isMatch ? profile.color+'25' : 'rgba(255,255,255,0.04)'};
              color:${isMatch ? profile.color : 'rgba(241,245,249,0.25)'};
              border:1px solid ${isMatch ? profile.color+'40' : 'rgba(255,255,255,0.06)'}">
              ${t}
            </span>`;
          }).join("")}
        </div>
      </div>`;
  }

  const profileCards = ADVERSARY_PROFILES.map(p => `
    <div style="padding:16px 20px;border-radius:10px;
      border:1px solid ${p.color}${p.similarity >= 70 ? '40' : '20'};
      background:${p.color}${p.similarity >= 70 ? '08' : '04'};
      position:relative;overflow:hidden">
      ${p.similarity === bestMatch.similarity
        ? `<div style="position:absolute;top:10px;right:12px;
            background:${p.color}20;border:1px solid ${p.color}40;
            border-radius:20px;padding:2px 10px;font-size:8px;color:${p.color};
            font-weight:700;letter-spacing:1px">BEST MATCH</div>` : ""}

      <div style="display:flex;gap:14px;align-items:flex-start">
        <!-- Gauge -->
        <div style="width:90px;flex-shrink:0">
          ${gauge(p.similarity, p.color)}
        </div>
        <!-- Info -->
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">
            <span style="font-family:'Syne',sans-serif;font-weight:900;font-size:15px;color:${p.color}">${p.name}</span>
            ${mono(p.alias,"rgba(241,245,249,0.4)","font-size:10px")}
          </div>
          <div style="display:flex;gap:6px;margin-bottom:7px;flex-wrap:wrap">
            ${badge(p.nation,"#6b7280")}
            ${badge(p.motivation,"#a78bfa")}
          </div>
          <div style="font-size:10px;color:var(--muted);line-height:1.7">${p.desc}</div>
          ${overlapBar(p)}
        </div>
      </div>

      <!-- Tactics -->
      <div style="margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,255,255,0.05)">
        <div style="font-size:8px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:1.5px">
          ATT&CK Tactics Used
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${p.tactics.map(t => `
            <span style="padding:3px 9px;border-radius:4px;font-size:9px;
              background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
              color:rgba(241,245,249,0.5)">${t}</span>`).join("")}
        </div>
      </div>
    </div>`).join("");

  // Radar comparison SVG
  const tactics = ["Recon","Init.Access","Exec","Persist","Priv.Esc","Cred","Discovery","Lateral","Collect","Exfil"];
  const profiles_radar = [
    {name:"APT29",color:"#f43f5e", vals:[0.6,0.9,0.8,0.9,0.7,0.9,0.8,0.9,0.9,0.9]},
    {name:"APT28",color:"#fb923c", vals:[0.8,0.9,0.7,0.7,0.6,0.8,0.7,0.8,0.7,0.8]},
    {name:"Lazarus",color:"#60a5fa",vals:[0.5,0.8,0.7,0.8,0.7,0.6,0.6,0.7,0.6,0.7]},
    {name:"FIN7",  color:"#34d399", vals:[0.3,0.8,0.7,0.6,0.5,0.7,0.5,0.5,0.8,0.6]},
  ];
  const rMax=55, rcx=80, rcy=80, sides=tactics.length;
  function rPt(angle, val) {
    return [rcx + Math.cos(angle - Math.PI/2)*rMax*val,
            rcy + Math.sin(angle - Math.PI/2)*rMax*val];
  }
  const gridLines = [0.33,0.66,1].map(s => {
    const pts = tactics.map((_,i) => { const [x,y]=rPt(i*2*Math.PI/sides,s); return`${x},${y}`; }).join(" ");
    return `<polygon points="${pts}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>`;
  }).join("");
  const axisLines = tactics.map((_,i) => {
    const [x,y]=rPt(i*2*Math.PI/sides,1);
    return `<line x1="${rcx}" y1="${rcy}" x2="${x}" y2="${y}" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>`;
  }).join("");
  const axisLabels = tactics.map((t,i) => {
    const [x,y]=rPt(i*2*Math.PI/sides,1.3);
    return `<text x="${x}" y="${y}" text-anchor="middle" fill="rgba(241,245,249,0.35)" font-size="7">${t}</text>`;
  }).join("");
  const polyLines = profiles_radar.map(p => {
    const pts = p.vals.map((v,i) => { const [x,y]=rPt(i*2*Math.PI/sides,v); return`${x},${y}`; }).join(" ");
    return `<polygon points="${pts}" fill="${p.color}18" stroke="${p.color}" stroke-width="1.5" opacity="0.8"/>`;
  }).join("");
  const radarLegend = profiles_radar.map(p =>
    `<div style="display:flex;align-items:center;gap:5px;font-size:9px">
      <div style="width:10px;height:2px;background:${p.color}"></div>
      <span style="color:rgba(241,245,249,0.5)">${p.name}</span>
    </div>`
  ).join("");

  el.innerHTML = `
    <!-- Top stats -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
      ${ADVERSARY_PROFILES.map(p => `
        <div class="stat-card" style="border-color:${p.color}33;text-align:center">
          <div style="font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px">${p.name}</div>
          <div style="font-size:30px;font-weight:900;color:${p.color};font-family:'Syne',sans-serif">${p.similarity}%</div>
          <div style="font-size:9px;color:var(--muted);margin-top:3px">${p.nation}</div>
          <div style="height:2px;background:${p.color};border-radius:0 0 10px 10px;position:absolute;bottom:0;left:0;right:0"></div>
        </div>`).join("")}
    </div>

    <div style="display:grid;grid-template-columns:1fr 210px;gap:14px;margin-bottom:14px">
      <!-- Alert box -->
      <div style="padding:12px 16px;border-radius:8px;
        background:rgba(244,63,94,0.06);border:1px solid rgba(244,63,94,0.25)">
        <div style="font-size:10px;font-weight:700;color:#f43f5e;margin-bottom:5px">
          ⚠ Closest Match: ${bestMatch.name} (${bestMatch.alias}) — ${bestMatch.similarity}% similarity
        </div>
        <div style="font-size:10px;color:var(--muted);line-height:1.7">
          ${bestMatch.desc}<br>
          <span style="color:rgba(241,245,249,0.4)">Matched techniques: ${bestMatch.matched.join(", ")}</span>
        </div>
      </div>
      <!-- Radar -->
      <div class="card" style="padding:12px">
        <div class="card-label" style="margin-bottom:6px">Tactic Coverage</div>
        <svg viewBox="0 0 160 165" style="width:100%">
          ${gridLines}${axisLines}${polyLines}${axisLabels}
        </svg>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px">${radarLegend}</div>
      </div>
    </div>

    <!-- Profile cards -->
    <div style="display:flex;flex-direction:column;gap:10px">
      ${profileCards}
    </div>`;
}
