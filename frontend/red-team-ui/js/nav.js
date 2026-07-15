/* ══════════════════════════════════════════════
   nav.js — Navigation (v2: 3 new views added)
   ══════════════════════════════════════════════ */

const NAV_ITEMS = [
  { id:"dashboard",   label:"Dashboard",       icon:"⬡", group:"OVERVIEW"     },
  { id:"new",         label:"New Session",      icon:"▶", group:"OVERVIEW"     },
  { id:"hosts",       label:"Hosts",            icon:"⊡", group:"ANALYSIS"     },
  { id:"vulns",       label:"Vulnerabilities",  icon:"⚠", group:"ANALYSIS"     },
  { id:"exploits",    label:"Exploitation",     icon:"⚡", group:"ANALYSIS"     },
  { id:"postexploit", label:"Post-Exploit",     icon:"🔓", group:"MITRE ENGINE","INTELLIGENCE", badge:"NEW" },
  { id:"ai",          label:"AI Classifier",    icon:"◈", group:"MITRE ENGINE","INTELLIGENCE", badge:"NEW" },
  { id:"mitre",       label:"MITRE ATT&CK",     icon:"⬢", group:"MITRE ENGINE" },
  { id:"chain",       label:"Attack Chain",     icon:"⛓", group:"MITRE ENGINE","INTELLIGENCE", badge:"NEW" },
  { id:"threatintel",  label:"Threat Intel",     icon:"🛡", group:"INTELLIGENCE", badge:"NEW" },
  { id:"adversary",    label:"Adversary Profiles",icon:"👤", group:"INTELLIGENCE", badge:"NEW" },
  { id:"graph",        label:"Attack Graph",      icon:"⬡", group:"INTELLIGENCE", badge:"NEW" },
  { id:"rules",        label:"Rule Trace",        icon:"≡", group:"SYSTEM"       },
  { id:"logs",        label:"Session Logs",     icon:"⌨", group:"SYSTEM"       },
];

const PAGE_TITLES = {
  dashboard:"Dashboard", new:"New Session", hosts:"Host Discovery",
  vulns:"Vulnerabilities", exploits:"Exploitation",
  postexploit:"Post-Exploitation",
  ai:"AI Classifier — 3-Layer MITRE Engine",
  mitre:"MITRE ATT&CK Mapping",
  chain:"Attack Chain Reconstruction",
  rules:"Rule Execution Trace",
  threatintel:"Threat Intelligence — CVE · EPSS · CISA KEV",
  adversary:"Adversary Profile Matching",
  graph:"Attack Graph — Node/Edge Visualization",
  logs:"Session Logs",
};

let currentView = "dashboard";

function setView(id) {
  currentView = id;
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.getElementById("view-" + id).classList.add("active");
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  const btn = document.getElementById("nb-" + id);
  if (btn) btn.classList.add("active");
  document.getElementById("page-title").textContent = PAGE_TITLES[id] || id;
}

function buildNav() {
  const navEl = document.getElementById("nav");
  let lastGroup = "";

  NAV_ITEMS.forEach(n => {
    if (n.group !== lastGroup) {
      const g = document.createElement("div");
      g.className   = "sb-section-label";
      g.textContent = n.group;
      g.style.cssText = "padding:10px 12px 4px;font-size:8px;letter-spacing:2px;color:rgba(241,245,249,0.3)";
      navEl.appendChild(g);
      lastGroup = n.group;
    }
    const btn = document.createElement("button");
    btn.className = "nav-btn" + (n.id === "dashboard" ? " active" : "");
    btn.id = "nb-" + n.id;
    const badgeHtml = n.badge
      ? `<span style="margin-left:auto;background:rgba(244,63,94,0.18);border-radius:20px;
           padding:1px 7px;font-size:8px;color:#f43f5e;letter-spacing:.5px">${n.badge}</span>`
      : "";
    btn.innerHTML = `<span style="font-size:13px;opacity:0.7;width:18px;text-align:center">${n.icon}</span>${n.label}${badgeHtml}`;
    btn.addEventListener("click", () => setView(n.id));
    navEl.appendChild(btn);
  });
}
