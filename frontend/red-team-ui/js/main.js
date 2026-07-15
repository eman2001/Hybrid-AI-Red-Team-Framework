/* ══════════════════════════════════════════════
   main.js — Boot (API-driven)
   ══════════════════════════════════════════════ */

window.APP = {
  vulns:   [],
  exploits:[],
  mitre:   {},
  chain:   {},
  session: {},
};

async function loadFromAPI() {
  console.log("[App] Loading data from FastAPI...");

  const [vulnData, mitreData, chainData] = await Promise.all([
    API.getVulns(),
    API.getMitre(),
    API.getChain(),
  ]);

  // Vulns
  if (vulnData && vulnData.vulnerabilities) {
    window.VULNS = vulnData.vulnerabilities.map(v => ({
      cve:     v.cve,
      ip:      v.host,
      port:    v.port,
      service: v.service,
      cvss:    v.cvss,
      risk:    v.risk_score / 100,
      attack:  v.exploit ? "remote" : "local",
      auth:    false,
      msf:     v.exploit || null,
      desc:    v.title,
      severity:v.severity,
    }));
    console.log(`[API] ✓ Vulns: ${window.VULNS.length}`);
  } else {
    window.VULNS = VULNS;
    console.warn("[API] Vulns fallback → data.js");
  }

  // MITRE
  if (mitreData && mitreData.techniques) {
    const grouped = {};
    mitreData.techniques.forEach(t => {
      const tactic = t.tactic.split("-")
        .map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
      if (!grouped[tactic]) grouped[tactic] = [];
      grouped[tactic].push({
        id: t.technique_id, name: t.technique_name,
        detail: t.host, conf: t.confidence, src: t.source,
      });
    });
    window.MITRE = grouped;
    console.log(`[API] ✓ MITRE: ${mitreData.techniques.length} techniques`);
  } else {
    window.MITRE = MITRE;
    console.warn("[API] MITRE fallback → data.js");
  }

  // Chain
  if (chainData && chainData.phases) {
    window.CHAIN = chainData.phases;
    console.log(`[API] ✓ Chain: ${chainData.phase_count} phases`);
  } else {
    window.CHAIN = typeof CHAIN !== "undefined" ? CHAIN : {};
    console.warn("[API] Chain fallback → data.js");
  }

  // Session
  const sessionData = await API.getSessions();
  if (sessionData && sessionData.sessions && sessionData.sessions.length > 0) {
    const lastId = sessionData.sessions[sessionData.sessions.length - 1];
    const sess   = await API.getSession(lastId);
    if (sess) {
      window.SESSION = {
        id:       sess.session_id || lastId,
        target:   sess.target    || SESSION.target,
        status:   sess.status    || "done",
        mode:     "live",
        progress: 100,
      };
      console.log(`[API] ✓ Session: ${window.SESSION.id}`);
    }
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  buildNav();

  // Loading bar
  document.body.insertAdjacentHTML("afterbegin",
    `<div id="api-loader" style="position:fixed;top:0;left:0;right:0;
     background:rgba(99,102,241,0.15);color:#a5b4fc;font-size:12px;
     text-align:center;padding:4px;z-index:9999;letter-spacing:1px">
     ⟳ Connecting to API...
    </div>`
  );

  await loadFromAPI();

  const loader = document.getElementById("api-loader");
  if (loader) loader.remove();

  renderDashboard();
  renderSession();
  renderHosts();
  renderVulns();
  renderExploits();
  renderPostExploit();
  renderAI();
  renderMitre();
  renderChain();
  renderThreatIntel();
  renderAdversary();
  renderGraph();
  renderRules();
  renderLogs();

  setView("dashboard");
});
