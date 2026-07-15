/* ══════════════════════════════════════════════
   views/session.js — New Session view renderer
   ══════════════════════════════════════════════ */

function renderSession() {
  const el = document.getElementById("view-new");

  el.innerHTML = `
    <div style="max-width:560px">
      <div class="card">
        <div class="card-label">Launch New Pentest Session</div>

        <div style="margin-bottom:18px">
          <div class="form-label">TARGET IP / CIDR</div>
          <input class="form-input" id="target-input"
            value="192.168.1.100"
            placeholder="192.168.1.0/24 or 192.168.1.100" />
        </div>

        <label class="form-check">
          <input type="checkbox" id="dry-run-check" checked />
          <span>Dry-Run (simulation — no real tools executed)</span>
        </label>

        <button class="launch-btn" id="launch-btn"
          style="background:var(--blue)">▶  Run Simulation</button>

        <div class="launch-msg" id="launch-msg"></div>

        <div class="info-box">
          <div>⚖ RISK THRESHOLD = <span style="color:var(--high)">${RISK_THRESHOLD}</span></div>
          <div>📌 Rule R7: risk ≥ ${RISK_THRESHOLD} → exploit via Metasploit</div>
          <div>📌 Rule R8: fail + auth → brute force via Hydra</div>
          <div>📌 Rule R10: complete → generate PDF + JSON report</div>
        </div>
      </div>
    </div>`;

  // Toggle dry-run
  const dryCheck  = document.getElementById("dry-run-check");
  const launchBtn = document.getElementById("launch-btn");

  dryCheck.addEventListener("change", () => {
    launchBtn.style.background = dryCheck.checked ? "var(--blue)" : "var(--critical)";
    launchBtn.textContent      = dryCheck.checked ? "▶  Run Simulation" : "⚡  Launch Pentest";
  });

  // Launch button
  launchBtn.addEventListener("click", async () => {
    const target = document.getElementById("target-input").value.trim();
    if (!target) return;

    launchBtn.textContent = "Launching...";
    launchBtn.disabled    = true;

    // Simulate network delay
    await new Promise(r => setTimeout(r, 900));

    const msgEl       = document.getElementById("launch-msg");
    msgEl.style.display = "block";
    msgEl.textContent   = `Demo mode — backend not connected. Session would target: ${target}`;

    launchBtn.textContent = dryCheck.checked ? "▶  Run Simulation" : "⚡  Launch Pentest";
    launchBtn.disabled    = false;

    // Redirect to logs after short delay
    setTimeout(() => setView("logs"), 1200);
  });
}
