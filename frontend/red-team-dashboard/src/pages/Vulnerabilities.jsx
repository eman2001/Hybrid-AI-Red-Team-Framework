import {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  ChevronDown,
  Flame,
  Gauge,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  Skull,
  Target,
  TrendingUp,
  XCircle
} from "lucide-react";


const API_BASE =
  "http://127.0.0.1:8000";


const SEVERITY_OPTIONS = [
  "all",
  "critical",
  "high",
  "medium",
  "low"
];


function Vulnerabilities() {
  const [
    vulnerabilities,
    setVulnerabilities
  ] = useState([]);

  const [
    loading,
    setLoading
  ] = useState(true);

  const [
    error,
    setError
  ] = useState("");

  const [
    search,
    setSearch
  ] = useState("");

  const [
    severityFilter,
    setSeverityFilter
  ] = useState("all");

  const [
    exploitOnly,
    setExploitOnly
  ] = useState(false);


  useEffect(() => {
    loadVulnerabilities();
  }, []);


  async function loadVulnerabilities() {
    try {
      setLoading(true);
      setError("");

      const response =
        await fetch(
          `${API_BASE}/api/vulnerabilities/`
        );

      if (!response.ok) {
        throw new Error(
          `Request failed with status ${response.status}`
        );
      }

      const data =
        await response.json();

      setVulnerabilities(
        data.vulnerabilities || []
      );

    } catch (requestError) {
      console.error(
        "Vulnerability Error:",
        requestError
      );

      setError(
        "Unable to load vulnerability data from the framework engine."
      );

    } finally {
      setLoading(false);
    }
  }


  const normalizedVulnerabilities =
    useMemo(() => {
      return vulnerabilities.map(
        (item, index) => ({
          ...item,

          id:
            item.id
            ||
            item.cve
            ||
            `${item.host}-${item.port}-${index}`,

          severity:
            String(
              item.severity || "unknown"
            ).toLowerCase(),

          cvss:
            normalizeNumber(
              item.cvss_live
              ??
              item.cvss
            ),

          epss:
            normalizeEpss(
              item.epss
              ??
              item.epss_score
            ),

          riskScore:
            normalizeNumber(
              item.threat_score
              ??
              item.risk_score
              ??
              item.score
            ),

          inKev:
            Boolean(
              item.in_kev
              ??
              item.kev
              ??
              item.cisa_kev
            ),

          exploitAvailable:
            Boolean(
              item.exploit
              ??
              item.exploit_available
              ??
              item.has_exploit
            )
        })
      );
    }, [vulnerabilities]);


  const statistics =
    useMemo(() => {
      const stats = {
        total: normalizedVulnerabilities.length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        kev: 0,
        exploitable: 0,
        cvssTotal: 0,
        cvssCount: 0
      };

      normalizedVulnerabilities.forEach(
        item => {
          if (
            Object.prototype.hasOwnProperty.call(
              stats,
              item.severity
            )
          ) {
            stats[item.severity] += 1;
          }

          if (item.inKev) {
            stats.kev += 1;
          }

          if (item.exploitAvailable) {
            stats.exploitable += 1;
          }

          if (item.cvss !== null) {
            stats.cvssTotal += item.cvss;
            stats.cvssCount += 1;
          }
        }
      );

      return {
        ...stats,

        averageCvss:
          stats.cvssCount > 0
            ? (
                stats.cvssTotal
                /
                stats.cvssCount
              ).toFixed(1)
            : "0.0"
      };
    }, [normalizedVulnerabilities]);


  const filteredVulnerabilities =
    useMemo(() => {
      const searchValue =
        search.trim().toLowerCase();

      return normalizedVulnerabilities
        .filter(item => {
          if (
            severityFilter !== "all"
            &&
            item.severity !== severityFilter
          ) {
            return false;
          }

          if (
            exploitOnly
            &&
            !item.exploitAvailable
          ) {
            return false;
          }

          if (!searchValue) {
            return true;
          }

          const searchableText = [
            item.host,
            item.port,
            item.cve,
            item.vulnerability,
            item.service,
            item.product,
            item.severity
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();

          return searchableText.includes(
            searchValue
          );
        })
        .sort(
          (first, second) =>
            severityRank(first.severity)
            -
            severityRank(second.severity)
            ||
            (second.riskScore || 0)
            -
            (first.riskScore || 0)
        );
    }, [
      normalizedVulnerabilities,
      search,
      severityFilter,
      exploitOnly
    ]);


  return (
    <div className="vulnerabilities-page">

      {/* =====================================
          HERO
      ====================================== */}

      <section className="vuln-hero">

        <div className="vuln-hero-icon">
          <ShieldAlert size={46} />
        </div>


        <div className="vuln-hero-copy">

          <span className="vuln-eyebrow">
            Threat Intelligence
          </span>

          <h1>
            Vulnerability
            <span> Intelligence Center</span>
          </h1>

          <p>
            Review confirmed security findings,
            severity, CVSS, EPSS, CISA KEV status,
            exploit availability and prioritized risk.
          </p>


          <div className="vuln-engine-state">

            <span
              className={
                `vuln-engine-dot ${
                  loading
                    ? "loading"
                    : error
                      ? "error"
                      : "connected"
                }`
              }
            />

            <strong>
              {loading
                ? "Synchronizing vulnerability data"
                : error
                  ? "Framework connection unavailable"
                  : `${statistics.total} confirmed findings loaded`
              }
            </strong>

          </div>

        </div>


        <div className="vuln-hero-meta">

          <div>
            <span>
              Critical
            </span>

            <strong>
              {statistics.critical}
            </strong>
          </div>


          <div>
            <span>
              KEV Listed
            </span>

            <strong>
              {statistics.kev}
            </strong>
          </div>

        </div>

      </section>



      {/* =====================================
          SUMMARY
      ====================================== */}

      <section className="vuln-summary-grid">

        <VulnerabilityMetric
          title="Total Findings"
          value={statistics.total}
          hint="Confirmed vulnerabilities"
          icon={Bug}
          type="default"
        />


        <VulnerabilityMetric
          title="Critical"
          value={statistics.critical}
          hint="Immediate remediation"
          icon={Skull}
          type="critical"
        />


        <VulnerabilityMetric
          title="High"
          value={statistics.high}
          hint="High-priority findings"
          icon={Flame}
          type="high"
        />


        <VulnerabilityMetric
          title="KEV Listed"
          value={statistics.kev}
          hint="Known exploited vulnerabilities"
          icon={Target}
          type="kev"
        />


        <VulnerabilityMetric
          title="Average CVSS"
          value={statistics.averageCvss}
          hint="Across scored findings"
          icon={Gauge}
          type="cvss"
        />

      </section>



      {/* =====================================
          FILTER BAR
      ====================================== */}

      <section className="vuln-panel vuln-filter-panel">

        <div className="vuln-filter-header">

          <div className="vuln-panel-heading">

            <div className="vuln-panel-icon">
              <Radar size={21} />
            </div>

            <div>
              <h2>
                Findings Explorer
              </h2>

              <p>
                Search and filter confirmed vulnerabilities
              </p>
            </div>

          </div>


          <span className="vuln-result-count">
            {filteredVulnerabilities.length}
            {" "}
            results
          </span>

        </div>


        <div className="vuln-filter-controls">

          <div className="vuln-search-box">

            <Search size={18} />

            <input
              value={search}
              onChange={
                event =>
                  setSearch(
                    event.target.value
                  )
              }
              placeholder="Search CVE, host, port or service..."
            />

          </div>


          <div className="vuln-select-shell">

            <ShieldAlert size={17} />

            <select
              value={severityFilter}
              onChange={
                event =>
                  setSeverityFilter(
                    event.target.value
                  )
              }
            >

              {SEVERITY_OPTIONS.map(
                option => (
                  <option
                    key={option}
                    value={option}
                  >
                    {option === "all"
                      ? "All Severities"
                      : capitalize(option)
                    }
                  </option>
                )
              )}

            </select>

            <ChevronDown size={16} />

          </div>


          <label className="vuln-exploit-toggle">

            <input
              type="checkbox"
              checked={exploitOnly}
              onChange={
                event =>
                  setExploitOnly(
                    event.target.checked
                  )
              }
            />

            <span className="vuln-toggle-track">
              <i />
            </span>

            Exploit available only

          </label>

        </div>

      </section>



      {/* =====================================
          TABLE
      ====================================== */}

      <section className="vuln-panel vuln-table-panel">

        <div className="vuln-table-heading">

          <div className="vuln-panel-heading">

            <div className="vuln-panel-icon">
              <AlertTriangle size={21} />
            </div>

            <div>
              <h2>
                Confirmed Vulnerabilities
              </h2>

              <p>
                Ranked by severity and risk score
              </p>
            </div>

          </div>


          <div className="vuln-table-legend">

            <span>
              <i className="critical" />
              Critical
            </span>

            <span>
              <i className="high" />
              High
            </span>

            <span>
              <i className="medium" />
              Medium
            </span>

            <span>
              <i className="low" />
              Low
            </span>

          </div>

        </div>


        {loading ? (

          <VulnerabilityLoading />

        ) : error ? (

          <div className="vuln-error-state">

            <XCircle size={38} />

            <h3>
              Unable to Load Findings
            </h3>

            <p>
              {error}
            </p>

            <button
              type="button"
              onClick={loadVulnerabilities}
            >
              Retry Connection
            </button>

          </div>

        ) : filteredVulnerabilities.length === 0 ? (

          <div className="vuln-empty-state">

            <ShieldCheck size={42} />

            <h3>
              No Matching Vulnerabilities
            </h3>

            <p>
              Change the current filters or run a new
              security assessment.
            </p>

          </div>

        ) : (

          <div className="vuln-table-wrap">

            <table className="vuln-security-table">

              <thead>
                <tr>
                  <th>
                    Asset
                  </th>

                  <th>
                    Vulnerability
                  </th>

                  <th>
                    Severity
                  </th>

                  <th>
                    CVSS
                  </th>

                  <th>
                    EPSS
                  </th>

                  <th>
                    KEV
                  </th>

                  <th>
                    Risk
                  </th>

                  <th>
                    Exploit
                  </th>
                </tr>
              </thead>


              <tbody>

                {filteredVulnerabilities.map(
                  item => (
                    <VulnerabilityRow
                      key={item.id}
                      item={item}
                    />
                  )
                )}

              </tbody>

            </table>

          </div>

        )}

      </section>

    </div>
  );
}



function VulnerabilityMetric({
  title,
  value,
  hint,
  icon: Icon,
  type
}) {
  return (
    <article
      className={
        `vuln-metric-card ${type}`
      }
    >

      <div className="vuln-metric-top">

        <div className="vuln-metric-icon">
          <Icon size={24} />
        </div>

        <TrendingUp size={17} />

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



function VulnerabilityRow({
  item
}) {
  const cve =
    item.cve
    ||
    item.vulnerability
    ||
    "Unassigned";

  const host =
    item.host
    ||
    "Unknown asset";

  const service =
    item.service
    ||
    item.product
    ||
    "Unknown service";

  return (
    <tr>

      <td>

        <div className="vuln-asset-cell">

          <strong>
            {host}
          </strong>

          <span>
            {item.port
              ? `${service} · port ${item.port}`
              : service
            }
          </span>

        </div>

      </td>


      <td>

        <div className="vuln-cve-cell">

          <strong>
            {cve}
          </strong>

          <span>
            {item.title
              ||
              item.description
              ||
              "Confirmed security weakness"
            }
          </span>

        </div>

      </td>


      <td>

        <span
          className={
            `severity ${
              item.severity
            }`
          }
        >
          {capitalize(
            item.severity
          )}
        </span>

      </td>


      <td>

        <span
          className={
            `vuln-score-badge ${
              scoreClass(
                item.cvss
              )
            }`
          }
        >
          {formatScore(
            item.cvss
          )}
        </span>

      </td>


      <td>

        <div className="vuln-epss-cell">

          <span>
            {item.epss !== null
              ? `${item.epss}%`
              : "-"
            }
          </span>

          <div>
            <i
              style={{
                width:
                  `${item.epss || 0}%`
              }}
            />
          </div>

        </div>

      </td>


      <td>

        {item.inKev ? (

          <span className="vuln-kev-badge active">
            <AlertTriangle size={13} />
            Listed
          </span>

        ) : (

          <span className="vuln-kev-badge">
            Not Listed
          </span>

        )}

      </td>


      <td>

        <div className="vuln-risk-cell">

          <span>
            {formatScore(
              item.riskScore
            )}
          </span>

          <div>
            <i
              style={{
                width:
                  `${Math.min(
                    100,
                    item.riskScore || 0
                  )}%`
              }}
            />
          </div>

        </div>

      </td>


      <td>

        {item.exploitAvailable ? (

          <span className="vuln-exploit-badge available">
            <AlertTriangle size={13} />
            Available
          </span>

        ) : (

          <span className="vuln-exploit-badge">
            <CheckCircle2 size={13} />
            None
          </span>

        )}

      </td>

    </tr>
  );
}



function VulnerabilityLoading() {
  return (
    <div className="vuln-loading-state">

      <div className="vuln-loading-spinner" />

      <h3>
        Loading Vulnerability Intelligence
      </h3>

      <p>
        Retrieving confirmed findings from the
        framework engine.
      </p>

    </div>
  );
}



function normalizeNumber(value) {
  if (
    value === null
    ||
    value === undefined
    ||
    value === ""
  ) {
    return null;
  }

  const number =
    Number(value);

  return Number.isNaN(number)
    ? null
    : number;
}



function normalizeEpss(value) {
  const number =
    normalizeNumber(value);

  if (number === null) {
    return null;
  }

  if (number <= 1) {
    return Math.round(
      number * 100
    );
  }

  return Math.min(
    100,
    Math.round(number)
  );
}



function severityRank(severity) {
  const rank = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    unknown: 4
  };

  return rank[severity] ?? 5;
}



function scoreClass(score) {
  if (score === null) {
    return "unknown";
  }

  if (score >= 9) {
    return "critical";
  }

  if (score >= 7) {
    return "high";
  }

  if (score >= 4) {
    return "medium";
  }

  return "low";
}



function formatScore(value) {
  if (
    value === null
    ||
    value === undefined
  ) {
    return "-";
  }

  return Number(value).toFixed(1);
}



function capitalize(value) {
  if (!value) {
    return "Unknown";
  }

  return (
    value.charAt(0).toUpperCase()
    +
    value.slice(1)
  );
}


export default Vulnerabilities;
