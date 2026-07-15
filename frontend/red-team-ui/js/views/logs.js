/* ══════════════════════════════════════════════
   views/logs.js — Session Logs view renderer
   ══════════════════════════════════════════════ */

function renderLogs() {
  const el = document.getElementById("view-logs");

  // Build log lines
  const linesHtml = LOGS.map(line => {
    const div = document.createElement("div");
    div.className    = "log-line";
    div.style.color  = logLineColor(line);
    div.textContent  = line || "\u00A0";
    return div.outerHTML;
  }).join("");

  el.innerHTML = `
    <div class="card" style="display:flex;flex-direction:column">
      <div class="log-header">
        <div class="log-dot"></div>
        <div class="card-label" style="margin:0">Session Log — ${SESSION.id} (dry-run)</div>
      </div>
      <div class="log-terminal">${linesHtml}</div>
    </div>`;

  // Auto-scroll to bottom
  const terminal = el.querySelector(".log-terminal");
  if (terminal) terminal.scrollTop = terminal.scrollHeight;
}
