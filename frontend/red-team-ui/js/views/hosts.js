/* ══════════════════════════════════════════════
   views/hosts.js — Hosts view renderer
   ══════════════════════════════════════════════ */

function renderHosts() {
  const el = document.getElementById("view-hosts");

  el.innerHTML = HOSTS.map(host => `
    <div class="card" style="border-color:rgba(6,182,212,0.27);box-shadow:0 0 18px rgba(6,182,212,0.09)">
      <div class="host-header">
        <div style="font-size:32px">🖥️</div>
        <div>
          ${mono(host.ip, "var(--cyan)", "font-size:16px;font-weight:700")}
          <div style="color:var(--muted);font-size:12px;margin-top:2px">
            ${host.hostname} · OS: ${host.os}
          </div>
        </div>
        ${badge(host.os, "var(--blue)")}
      </div>

      <div class="card-label">Open Services</div>

      ${host.services.map(s => `
        <div class="service-row">
          ${mono(s.port + "/" + s.proto, "var(--high)", "font-weight:700")}
          ${mono(s.service)}
          ${mono(s.product, "var(--muted)")}
          ${mono(s.version, "var(--purple)")}
        </div>`).join("")}
    </div>`).join("");
}
