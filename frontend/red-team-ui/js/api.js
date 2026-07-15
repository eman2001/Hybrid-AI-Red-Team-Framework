/* ══════════════════════════════════════════════
   api.js — Centralized API client
   ══════════════════════════════════════════════ */

const API_BASE = "http://127.0.0.1:8000";

const API = {

  async get(endpoint) {
    try {
      const res = await fetch(`${API_BASE}${endpoint}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn(`[API] GET ${endpoint} failed:`, err.message);
      return null;
    }
  },

  async post(endpoint, body = {}) {
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn(`[API] POST ${endpoint} failed:`, err.message);
      return null;
    }
  },

  getSessions:    ()             => API.get("/api/scan/sessions"),
  getSession:     (id)           => API.get(`/api/scan/sessions/${id}`),
  runScan:        (target, dry_run=true) => API.post("/api/scan/run", { target, dry_run }),
  getVulns:       ()             => API.get("/api/vulnerabilities/"),
  getMitre:       ()             => API.get("/api/mitre/techniques"),
  getChain:       ()             => API.get("/api/attack-chain/"),
  getGraph:       ()             => API.get("/api/attack_graph/"),
  getThreatIntel: ()             => API.get("/api/threat_intelligence/"),
  getAnalytics:   ()             => API.get("/api/analytics/summary"),
};
