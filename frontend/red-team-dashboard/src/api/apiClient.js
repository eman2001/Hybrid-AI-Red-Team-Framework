const API = "http://127.0.0.1:8000";


async function parseResponse(response, endpoint) {
  if (!response.ok) {
    let message = `${endpoint} failed with status ${response.status}`;

    try {
      const errorData = await response.json();

      message =
        errorData.detail
        || errorData.message
        || message;
    } catch {
      // Response may not contain JSON.
    }

    throw new Error(message);
  }

  return response.json();
}


// ============================================================
// Scan
// ============================================================

export async function startScan(target, lhost) {
  const response = await fetch(
    `${API}/api/scan/run`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      cache: "no-store",

      body: JSON.stringify({
        target,
        lhost,

        /*
         * Full real assessment.
         * Do not use true unless you intentionally want simulation mode.
         */
        dry_run: false,

        threshold: 30
      })
    }
  );

  return parseResponse(
    response,
    "/api/scan/run"
  );
}


export async function getProgress() {
  /*
   * The timestamp prevents browsers and proxies
   * from returning an old completed response.
   */
  const response = await fetch(
    `${API}/api/progress?_=${Date.now()}`,
    {
      method: "GET",

      cache: "no-store",

      headers: {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache"
      }
    }
  );

  return parseResponse(
    response,
    "/api/progress"
  );
}


// ============================================================
// Sessions
// ============================================================

export async function getSession(id) {
  const response = await fetch(
    `${API}/api/session/${id}`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    `/api/session/${id}`
  );
}


// ============================================================
// Vulnerabilities
// ============================================================

export async function getVulnerabilities() {
  const response = await fetch(
    `${API}/api/vulnerabilities/`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    "/api/vulnerabilities/"
  );
}


// ============================================================
// MITRE ATT&CK
// ============================================================

export async function getMitre() {
  const response = await fetch(
    `${API}/api/mitre/techniques`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    "/api/mitre/techniques"
  );
}


export async function getMitreHeatmap() {
  const response = await fetch(
    `${API}/api/mitre/heatmap`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    "/api/mitre/heatmap"
  );
}


// ============================================================
// Attack Chain
// ============================================================

export async function getAttackChain() {
  const response = await fetch(
    `${API}/api/attack-chain/`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    "/api/attack-chain/"
  );
}


// ============================================================
// Dashboard Analytics
// ============================================================

export async function getDashboardAnalytics() {
  const response = await fetch(
    `${API}/api/analytics/dashboard`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    "/api/analytics/dashboard"
  );
}


// ============================================================
// Reports
// ============================================================

export async function getLatestReportId() {
  const response = await fetch(
    `${API}/api/report/latest?_=${Date.now()}`,
    {
      cache: "no-store"
    }
  );

  if (!response.ok) {
    return null;
  }

  const data = await response.json();

  return data.session_id;
}


export async function getReportList() {
  const response = await fetch(
    `${API}/api/report/list`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    "/api/report/list"
  );
}


export function getReportPdfUrl(sessionId) {
  return `${API}/api/report/${sessionId}/pdf?v=${Date.now()}`;
}

export function getReportJsonUrl(sessionId) {
  return `${API}/api/report/${sessionId}/json?v=${Date.now()}`;
}


// ============================================================
// Attack Graph
// ============================================================

export async function getAttackGraph() {
  const response = await fetch(
    `${API}/api/attack-graph/`,
    {
      cache: "no-store"
    }
  );

  return parseResponse(
    response,
    "/api/attack-graph/"
  );
}
