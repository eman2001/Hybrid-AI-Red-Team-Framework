import {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  AlertTriangle,
  BarChart3,
  BrainCircuit,
  CheckCircle2,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  RefreshCw,
  Server,
  ShieldAlert,
  Sparkles,
  Target
} from "lucide-react";

import {
  getDashboardAnalytics,
  getLatestReportId,
  getReportPdfUrl,
  getReportJsonUrl
} from "../api/apiClient";


function Reports() {
  const [analytics, setAnalytics] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [sessionId, setSessionId] = useState(null);

  const [status, setStatus] = useState("loading");
  const [jsonLoading, setJsonLoading] = useState(false);


  useEffect(() => {
    loadReports();
  }, []);


  async function loadReports() {
    setStatus("loading");
    setReportData(null);

    try {
      const analyticsData =
        await getDashboardAnalytics();

      setAnalytics(
        analyticsData || null
      );

    } catch (error) {
      console.warn(
        "Analytics unavailable:",
        error
      );
    }


    try {
      const id =
        await getLatestReportId();

      if (!id) {
        setSessionId(null);
        setStatus("empty");
        return;
      }

      setSessionId(id);
      setStatus("ready");

      await loadJsonReport(id);

    } catch (error) {
      console.error(
        "Report loading error:",
        error
      );

      setStatus("error");
    }
  }


  async function loadJsonReport(id) {
    if (!id) {
      return;
    }

    setJsonLoading(true);

    try {
      const url =
        getReportJsonUrl(id);

      const response =
        await fetch(url);

      if (!response.ok) {
        throw new Error(
          `JSON request failed: ${response.status}`
        );
      }

      const data =
        await response.json();

      setReportData(
        data || null
      );

    } catch (error) {
      console.warn(
        "JSON report preview unavailable:",
        error
      );

      /*
       * لا نغيّر حالة الصفحة إلى error،
       * لأن ملف PDF قد يبقى متاحًا حتى لو فشل JSON.
       */
    } finally {
      setJsonLoading(false);
    }
  }


  const pdfUrl =
    sessionId
      ? getReportPdfUrl(sessionId)
      : null;


  const jsonUrl =
    sessionId
      ? getReportJsonUrl(sessionId)
      : null;


  const reportSummary =
    useMemo(() => {
      const executive =
        reportData?.executive_summary || {};

      const risk =
        reportData?.risk_summary || {};

      return {
        hosts:
          analytics?.host_count
          ??
          executive.total_hosts
          ??
          executive.scope?.length
          ??
          0,

        vulnerabilities:
          analytics?.vuln_count
          ??
          executive.total_findings
          ??
          reportData?.vulnerabilities?.length
          ??
          0,

        techniques:
          analytics?.technique_count
          ??
          reportData
            ?.mitre_analysis
            ?.techniques
            ?.length
          ??
          0,

        kev:
          analytics?.kev_count
          ??
          risk.kev_count
          ??
          0,

        riskLevel:
          risk.overall_risk
          ??
          risk.risk_level
          ??
          executive.overall_risk
          ??
          "UNKNOWN",

        riskScore:
          risk.risk_score
          ??
          executive.risk_score
          ??
          0
      };
    }, [analytics, reportData]);


  const aiAnalysis =
    reportData?.ai_analysis || {};


  const executiveNarrative =
    normalizeNarrative(
      aiAnalysis.executive_summary
      ??
      aiAnalysis.summary
    );


  const recommendations =
    normalizeRecommendations(
      aiAnalysis.recommendations
    );


  const generatedAt =
    formatDate(
      reportData?.generated_at
    );


  return (
    <div className="reports-page">

      {/* =====================================
          HERO
      ====================================== */}

      <section className="reports-hero">

        <div className="reports-hero-icon">
          <FileText size={46} />
        </div>


        <div className="reports-hero-copy">

          <span className="reports-eyebrow">
            Assessment Documentation
          </span>

          <h1>
            Security Assessment
            <span> Reports</span>
          </h1>

          <p>
            Review the latest generated penetration-testing
            report, AI-assisted analysis, security findings,
            MITRE ATT&amp;CK coverage and prioritized
            recommendations.
          </p>


          <div className="reports-engine-state">

            <span
              className={
                `reports-engine-dot ${status}`
              }
            />

            <strong>
              {status === "loading"
                ? "Searching for the latest report"
                : status === "ready"
                  ? `Report session ${sessionId} is available`
                  : status === "empty"
                    ? "No generated report is available"
                    : "Report service unavailable"
              }
            </strong>

          </div>

        </div>


        <div className="reports-hero-meta">

          <div>
            <span>
              Session
            </span>

            <strong>
              {sessionId || "N/A"}
            </strong>
          </div>


          <div>
            <span>
              Generated
            </span>

            <strong>
              {generatedAt}
            </strong>
          </div>

        </div>

      </section>



      {/* =====================================
          ACTION BAR
      ====================================== */}

      <section className="reports-action-panel">

        <div className="reports-session-info">

          <div className="reports-session-icon">
            <Server size={21} />
          </div>

          <div>
            <span>
              Latest Report Session
            </span>

            <strong>
              {sessionId || "No active report"}
            </strong>
          </div>

        </div>


        <div className="reports-actions">

          <button
            type="button"
            className="report-action-button refresh"
            onClick={loadReports}
            disabled={status === "loading"}
          >
            <RefreshCw
              size={17}
              className={
                status === "loading"
                  ? "reports-spin"
                  : ""
              }
            />

            Refresh
          </button>


          <a
            href={jsonUrl || undefined}
            target="_blank"
            rel="noreferrer"
            className={
              `report-action-button secondary ${
                !jsonUrl ? "disabled" : ""
              }`
            }
            aria-disabled={!jsonUrl}
            onClick={
              event => {
                if (!jsonUrl) {
                  event.preventDefault();
                }
              }
            }
          >
            <FileJson size={17} />

            View JSON

            <ExternalLink size={14} />
          </a>


          <a
            href={pdfUrl || undefined}
            target="_blank"
            rel="noreferrer"
            className={
              `report-action-button primary ${
                !pdfUrl ? "disabled" : ""
              }`
            }
            aria-disabled={!pdfUrl}
            onClick={
              event => {
                if (!pdfUrl) {
                  event.preventDefault();
                }
              }
            }
          >
            <Download size={17} />

            Open PDF
          </a>

        </div>

      </section>



      {/* =====================================
          SUMMARY
      ====================================== */}

      <section className="reports-summary-grid">

        <ReportMetric
          icon={Server}
          title="Hosts"
          value={reportSummary.hosts}
          hint="Assessed assets"
          type="hosts"
        />


        <ReportMetric
          icon={ShieldAlert}
          title="Vulnerabilities"
          value={reportSummary.vulnerabilities}
          hint="Confirmed findings"
          type="vulnerabilities"
        />


        <ReportMetric
          icon={Target}
          title="MITRE Techniques"
          value={reportSummary.techniques}
          hint="Mapped techniques"
          type="mitre"
        />


        <ReportMetric
          icon={AlertTriangle}
          title="KEV Listed"
          value={reportSummary.kev}
          hint="Known exploited findings"
          type="kev"
        />


        <ReportMetric
          icon={BarChart3}
          title="Risk Score"
          value={reportSummary.riskScore}
          hint={reportSummary.riskLevel}
          type="risk"
        />

      </section>



      {/* =====================================
          AI ANALYSIS
      ====================================== */}

      {status === "ready" && (
        <section className="reports-ai-grid">

          <article className="reports-panel reports-ai-summary">

            <div className="reports-panel-header">

              <div className="reports-panel-heading">

                <div className="reports-panel-icon ai">
                  <BrainCircuit size={21} />
                </div>

                <div>
                  <h2>
                    AI Executive Summary
                  </h2>

                  <p>
                    Qwen2.5-assisted report narrative
                  </p>
                </div>

              </div>


              <span className="reports-ai-badge">
                <Sparkles size={13} />
                AI Assisted
              </span>

            </div>


            <div className="reports-ai-content">

              {jsonLoading ? (

                <div className="reports-inline-loading">
                  <div />
                  Loading AI narrative...
                </div>

              ) : executiveNarrative ? (

                <p>
                  {executiveNarrative}
                </p>

              ) : (

                <div className="reports-unavailable-text">
                  AI narrative is not available in the
                  current JSON report.
                </div>

              )}

            </div>

          </article>



          <article className="reports-panel reports-recommendations">

            <div className="reports-panel-header">

              <div className="reports-panel-heading">

                <div className="reports-panel-icon">
                  <CheckCircle2 size={21} />
                </div>

                <div>
                  <h2>
                    Security Recommendations
                  </h2>

                  <p>
                    Prioritized remediation actions
                  </p>
                </div>

              </div>


              <span className="reports-panel-badge">
                {recommendations.length} actions
              </span>

            </div>


            <div className="reports-recommendation-list">

              {jsonLoading ? (

                <div className="reports-inline-loading">
                  <div />
                  Loading recommendations...
                </div>

              ) : recommendations.length > 0 ? (

                recommendations.map(
                  (item, index) => (

                    <div
                      className="reports-recommendation-item"
                      key={`${item}-${index}`}
                    >

                      <span>
                        {index + 1}
                      </span>

                      <p>
                        {item}
                      </p>

                    </div>

                  )
                )

              ) : (

                <div className="reports-unavailable-text">
                  No AI recommendations were included
                  in this report.
                </div>

              )}

            </div>

          </article>

        </section>
      )}



      {/* =====================================
          PDF VIEWER
      ====================================== */}

      <section className="reports-panel reports-viewer-panel">

        <div className="reports-panel-header">

          <div className="reports-panel-heading">

            <div className="reports-panel-icon">
              <FileText size={21} />
            </div>

            <div>
              <h2>
                Report Preview
              </h2>

              <p>
                Read-only PDF security assessment
              </p>
            </div>

          </div>


          {status === "ready" && (
            <span className="reports-panel-badge">
              PDF
            </span>
          )}

        </div>


        <div className="reports-viewer">

          {status === "loading" && (
            <ReportLoading />
          )}


          {status === "empty" && (
            <div className="reports-empty-state">

              <FileText size={48} />

              <h3>
                No Report Generated Yet
              </h3>

              <p>
                Run a complete security assessment from
                the Scan page to generate JSON and PDF
                reports.
              </p>

            </div>
          )}


          {status === "error" && (
            <div className="reports-error-state">

              <AlertTriangle size={48} />

              <h3>
                Report Service Unavailable
              </h3>

              <p>
                Check that the FastAPI backend is running
                and accessible on port 8000.
              </p>

              <button
                type="button"
                onClick={loadReports}
              >
                Retry Connection
              </button>

            </div>
          )}


          {status === "ready" && pdfUrl && (
            <>

              <div className="reports-viewer-chrome">

                <div className="reports-viewer-dots">
                  <span />
                  <span />
                  <span />
                </div>


                <div className="reports-viewer-filename">
                  attack_report — {sessionId}.pdf
                </div>


                <div className="reports-viewer-badge">
                  Read Only
                </div>

              </div>


              <iframe
                src={pdfUrl}
                title="Security Assessment PDF"
                className="reports-viewer-frame"
              />

            </>
          )}

        </div>

      </section>

    </div>
  );
}



function ReportMetric({
  icon: Icon,
  title,
  value,
  hint,
  type
}) {
  return (
    <article
      className={
        `report-metric-card ${type}`
      }
    >

      <div className="report-metric-top">

        <div className="report-metric-icon">
          <Icon size={24} />
        </div>

        <BarChart3 size={17} />

      </div>


      <span>
        {title}
      </span>

      <strong>
        {value}
      </strong>

      <p>
        {hint}
      </p>

    </article>
  );
}



function ReportLoading() {
  return (
    <div className="reports-loading-state">

      <div className="reports-loading-spinner" />

      <h3>
        Loading Security Report
      </h3>

      <p>
        Locating the latest report session and
        preparing the PDF preview.
      </p>

      <div className="reports-skeleton">
        <span />
        <span />
        <span />
        <span />
      </div>

    </div>
  );
}



function normalizeNarrative(value) {
  if (!value) {
    return "";
  }

  if (typeof value === "string") {
    return value.trim();
  }

  if (typeof value === "object") {
    return (
      value.text
      ||
      value.summary
      ||
      value.content
      ||
      JSON.stringify(value)
    );
  }

  return String(value);
}



function normalizeRecommendations(value) {
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value
      .map(
        item =>
          typeof item === "string"
            ? item.trim()
            : item?.recommendation
              ||
              item?.text
              ||
              String(item)
      )
      .filter(Boolean);
  }

  if (typeof value === "string") {
    return value
      .split(/\n+/)
      .map(
        line =>
          line
            .replace(
              /^\s*\d+[.)]\s*/,
              ""
            )
            .replace(
              /^\s*[-•]\s*/,
              ""
            )
            .trim()
      )
      .filter(Boolean);
  }

  return [];
}



function formatDate(value) {
  if (!value) {
    return "Latest";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return "Latest";
  }

  return date.toLocaleString(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short"
    }
  );
}


export default Reports;
