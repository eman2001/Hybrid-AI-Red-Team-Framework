/* ══════════════════════════════════════════════
   views/graph.js — Attack Graph view
   (Pure SVG force-directed simulation — no deps)
   ══════════════════════════════════════════════ */

function renderGraph() {
  const el = document.getElementById("view-graph");
  if (!el) return;

  const G = GRAPH_DATA;
  const nodeMap = {};
  G.nodes.forEach(n => { nodeMap[n.id] = n; });

  // Node type → icon
  function nodeIcon(type) {
    return {attacker:"👤", service:"⚙", host:"⊡", data:"📁", pivot:"⟳"}[type] || "○";
  }
  function nodeRadius(n) {
    if (n.type === "attacker") return 22;
    if (n.type === "host")     return 20;
    if (n.risk >= 90)          return 18;
    return 14;
  }

  // Build SVG
  const W = 680, H = 360;

  // Position nodes on fixed layout (no physics needed for small graph)
  const positions = {
    "ATTACKER":              {x: 70,  y: 180},
    "192.168.1.100:21":      {x: 240, y: 70},
    "192.168.1.100:445":     {x: 240, y: 180},
    "192.168.1.100:80":      {x: 240, y: 295},
    "192.168.1.100":         {x: 430, y: 180},
    "CREDS":                 {x: 600, y: 100},
    "PIVOT":                 {x: 600, y: 265},
  };

  // Draw edges
  const edgesHtml = G.edges.map(e => {
    const s = positions[e.from] || {x:100,y:100};
    const t = positions[e.to]   || {x:200,y:200};
    const mx = (s.x + t.x) / 2;
    const my = (s.y + t.y) / 2 - 18;
    const angle = Math.atan2(t.y-s.y, t.x-s.x);
    const headLen = 9;
    const ax  = t.x - headLen * Math.cos(angle - 0.35);
    const ay  = t.y - headLen * Math.sin(angle - 0.35);
    const bx  = t.x - headLen * Math.cos(angle + 0.35);
    const by_ = t.y - headLen * Math.sin(angle + 0.35);
    return `
      <line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}"
        stroke="${e.color}" stroke-width="1.5" opacity="0.5" stroke-dasharray="5,3"/>
      <polygon points="${t.x},${t.y} ${ax},${ay} ${bx},${by_}"
        fill="${e.color}" opacity="0.7"/>
      <text x="${mx}" y="${my}" text-anchor="middle"
        fill="${e.color}" font-size="8" opacity="0.8">${e.label}</text>`;
  }).join("");

  // Draw nodes
  const nodesHtml = G.nodes.map(n => {
    const pos = positions[n.id] || {x:100,y:100};
    const r   = nodeRadius(n);
    const ic  = nodeIcon(n.type);
    return `
      <g transform="translate(${pos.x},${pos.y})" style="cursor:pointer"
        onmouseover="document.getElementById('graph-info').innerHTML=this.dataset.info"
        data-info="${n.id}: ${n.type}${n.service ? ' · '+n.service : ''}${n.risk ? ' · risk='+n.risk : ''}">
        <circle r="${r}" fill="${n.color}20" stroke="${n.color}" stroke-width="1.5"/>
        ${n.type === "attacker" || n.type === "host"
          ? `<circle r="${r+5}" fill="none" stroke="${n.color}" stroke-width="0.5" opacity="0.3"/>`
          : ""}
        <text text-anchor="middle" dominant-baseline="central"
          font-size="${r > 16 ? '12' : '10'}">${ic}</text>
        <text text-anchor="middle" y="${r + 12}"
          fill="rgba(241,245,249,0.6)" font-size="9"
          font-family="IBM Plex Mono,monospace">${n.label}</text>
      </g>`;
  }).join("");

  // Legend
  const legendItems = [
    {color:"#f43f5e",label:"Attacker"},
    {color:"#fb923c",label:"Vulnerable Service"},
    {color:"#a78bfa",label:"Compromised Host"},
    {color:"#60a5fa",label:"Credential Data"},
    {color:"#34d399",label:"Pivot Point"},
  ];
  const legendHtml = legendItems.map(l =>
    `<div style="display:flex;align-items:center;gap:6px;font-size:9px;color:var(--muted)">
      <div style="width:8px;height:8px;border-radius:50%;background:${l.color}"></div>
      ${l.label}
    </div>`).join("");

  // Table of edges
  const edgeTable = G.edges.map(e => `
    <div style="display:grid;grid-template-columns:120px 120px 1fr 110px;
      gap:10px;align-items:center;padding:7px 12px;border-radius:6px;
      background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);margin-bottom:4px">
      ${mono(e.from.split(":").pop(),"rgba(241,245,249,0.5)","font-size:10px")}
      ${mono(e.to.split(":").pop()  ,"rgba(241,245,249,0.5)","font-size:10px")}
      ${mono(e.label, e.color, "font-size:10px;font-weight:700")}
      ${badge(e.tactic.replace(/-/g," ").toUpperCase(),e.color)}
    </div>`).join("");

  el.innerHTML = `
    <!-- Stats -->
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">
      <div class="stat-card" style="border-color:rgba(96,165,250,0.22)">
        <div class="card-label">Nodes</div>
        <div class="stat-value" style="color:var(--blue)">${G.nodes.length}</div>
        <div class="stat-sub">hosts + services</div>
      </div>
      <div class="stat-card" style="border-color:rgba(251,146,60,0.22)">
        <div class="card-label">Edges (Attack Paths)</div>
        <div class="stat-value" style="color:var(--high)">${G.edges.length}</div>
        <div class="stat-sub">exploit → pivot chains</div>
      </div>
      <div class="stat-card" style="border-color:rgba(244,63,94,0.22)">
        <div class="card-label">Critical Entry Points</div>
        <div class="stat-value" style="color:var(--critical)">3</div>
        <div class="stat-sub">direct attacker access</div>
      </div>
    </div>

    <!-- Graph -->
    <div class="card" style="padding:14px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div class="card-label" style="margin:0">Attack Graph — Node-Edge Visualization</div>
        <div style="font-size:9px;color:var(--muted)">Hover nodes for details</div>
      </div>
      <div style="background:#030508;border-radius:8px;border:1px solid rgba(255,255,255,0.05);padding:8px;overflow:hidden">
        <svg viewBox="0 0 ${W} ${H}" style="width:100%;display:block">
          <!-- Grid -->
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.02)" stroke-width="1"/>
            </pattern>
          </defs>
          <rect width="${W}" height="${H}" fill="url(#grid)"/>
          ${edgesHtml}
          ${nodesHtml}
        </svg>
      </div>
      <!-- Info bar -->
      <div id="graph-info" style="margin-top:8px;padding:6px 12px;border-radius:5px;
        background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);
        font-size:10px;color:var(--muted);min-height:28px">
        Hover over a node to see details...
      </div>
      <!-- Legend -->
      <div style="display:flex;flex-wrap:wrap;gap:14px;margin-top:10px">${legendHtml}</div>
    </div>

    <!-- Edge table -->
    <div class="card">
      <div class="card-label">Attack Paths — Edge Breakdown</div>
      <div style="display:grid;grid-template-columns:120px 120px 1fr 110px;gap:10px;
        padding:5px 12px;margin-bottom:4px">
        <span style="font-size:8px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px">FROM</span>
        <span style="font-size:8px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px">TO</span>
        <span style="font-size:8px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px">TECHNIQUE</span>
        <span style="font-size:8px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px">TACTIC</span>
      </div>
      ${edgeTable}
    </div>`;
}
