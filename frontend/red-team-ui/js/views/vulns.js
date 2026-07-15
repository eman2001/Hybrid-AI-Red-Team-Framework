/* ══════════════════════════════════════════════
   views/vulns.js — Vulnerabilities view renderer
   ══════════════════════════════════════════════ */

const FILTERS = [
  { id:"all",         label:"All" },
  { id:"exploitable", label:`Exploitable (risk ≥ ${RISK_THRESHOLD})`, color:"var(--high)"     },
  { id:"critical",    label:"Critical",                                color:"var(--critical)" },
  { id:"high",        label:"High",                                    color:"var(--high)"     },
  { id:"medium",      label:"Medium",                                  color:"var(--medium)"   },
  { id:"low",         label:"Low",                                     color:"var(--low)"      },
];

let activeFilter = "all";

function getFilteredVulns() {
  if (activeFilter === "all")         return VULNS;
  if (activeFilter === "exploitable") return VULNS.filter(v => v.risk >= RISK_THRESHOLD);
  return VULNS.filter(v => cvssLabel(v.cvss).toLowerCase() === activeFilter);
}

function renderVulnList() {
  const list = getFilteredVulns();
  const el   = document.getElementById("vuln-list");

  el.innerHTML = list.map(v => {
    const cc = cvssColor(v.cvss);
    const rc = riskColor(v.risk);
    const accentStyle = v.risk >= RISK_THRESHOLD
      ? `border-color:${cc}44;box-shadow:0 0 18px ${cc}18`
      : "";

    return `
      <div class="card vuln-card" style="${accentStyle}">
        <div class="vuln-row">
          <div>
            ${mono(v.cve, cc, "font-size:13px;font-weight:700")}
            <div style="color:var(--muted);font-size:11px;margin-top:3px">${v.ip}:${v.port}</div>
          </div>

          <div>
            <div style="font-size:13px">${v.desc}</div>
            <div style="display:flex;gap:10px;margin-top:6px;flex-wrap:wrap">
              ${mono("service: " + v.service, "var(--muted)", "font-size:11px")}
              ${mono("attack: "  + v.attack,  "var(--muted)", "font-size:11px")}
              ${v.msf ? mono("MSF: " + v.msf.split("/").slice(-1)[0], "var(--blue)",
                "font-size:10px;background:rgba(59,130,246,0.1);border-radius:4px;padding:1px 6px") : ""}
              ${v.auth ? badge("AUTH REQUIRED", "var(--medium)") : ""}
            </div>
          </div>

          <div style="text-align:center">
            <div style="font-size:10px;color:var(--muted)">CVSS</div>
            <div style="font-size:22px;font-weight:900;color:${cc};font-family:monospace">${v.cvss}</div>
          </div>

          <div style="text-align:center">
            <div style="font-size:10px;color:var(--muted)">RISK SCORE</div>
            <div style="font-size:22px;font-weight:900;color:${rc};font-family:monospace">${v.risk.toFixed(2)}</div>
            <div class="progress-wrap" style="height:3px;margin-top:4px">
              <div class="progress-fill" style="width:${v.risk * 100}%;background:${rc}"></div>
            </div>
          </div>

          ${badge(cvssLabel(v.cvss), cc)}
        </div>
      </div>`;
  }).join("");
}

function setFilter(id) {
  activeFilter = id;

  // Update button styles
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.classList.remove("active-filter");
    btn.style.background   = "rgba(255,255,255,0.04)";
    btn.style.borderColor  = "var(--border)";
    btn.style.color        = "var(--muted)";
  });

  const f   = FILTERS.find(f => f.id === id);
  const col = f.color || "var(--blue)";
  const btn = document.getElementById("filter-btn-" + id);
  btn.classList.add("active-filter");
  btn.style.borderColor = col;
  btn.style.color       = col;
  btn.style.background  = col.replace("var(--", "").replace(")", "")
    // crude lighten: just use opacity via inline rgba fallback
    .length > 0 ? col + "22" : "rgba(59,130,246,0.13)";

  renderVulnList();
}

function renderVulns() {
  const el = document.getElementById("view-vulns");

  // Filter row
  const filterHtml = FILTERS.map(f => `
    <button class="filter-btn${f.id === "all" ? " active-filter" : ""}"
      id="filter-btn-${f.id}"
      style="${f.id === "all" ? "border-color:var(--blue);color:var(--blue);background:rgba(59,130,246,0.13)" : ""}"
    >${f.label}</button>`).join("");

  el.innerHTML = `
    <div class="filter-row">${filterHtml}</div>
    <div class="threshold-banner">
      ⚖ RISK_THRESHOLD = ${RISK_THRESHOLD} — Vulnerabilities with risk_score ≥ ${RISK_THRESHOLD} trigger Rule R7 (exploit)
    </div>
    <div id="vuln-list"></div>`;

  // Bind filter buttons
  FILTERS.forEach(f => {
    document.getElementById("filter-btn-" + f.id)
      .addEventListener("click", () => setFilter(f.id));
  });

  renderVulnList();
}
