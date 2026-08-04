import {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  ChevronRight,
  GitBranch,
  ShieldAlert,
  ShieldCheck,
  Target
} from "lucide-react";

import StatCard from "../components/StatCard";
import ActivityFeed from "../components/ActivityFeed";


const API_BASE =
  "http://127.0.0.1:8000";


function Dashboard() {
  const [
    vulnerabilities,
    setVulnerabilities
  ] = useState([]);

  const [
    techniques,
    setTechniques
  ] = useState([]);

  const [
    chain,
    setChain
  ] = useState({});

  const [
    activities,
    setActivities
  ] = useState([]);

  const [
    loading,
    setLoading
  ] = useState(true);


  useEffect(() => {
    loadDashboard();
  }, []);


  async function loadDashboard() {
    try {
      setLoading(true);

      const [
        vulnResponse,
        mitreResponse,
        chainResponse,
        activityResponse
      ] = await Promise.allSettled([
        fetch(
          `${API_BASE}/api/vulnerabilities/`
        ),
        fetch(
          `${API_BASE}/api/mitre/techniques`
        ),
        fetch(
          `${API_BASE}/api/attack-chain/`
        ),
        fetch(
          `${API_BASE}/api/activity/`
        )
      ]);


      if (
        vulnResponse.status === "fulfilled"
        &&
        vulnResponse.value.ok
      ) {
        const vulnData =
          await vulnResponse.value.json();

        setVulnerabilities(
          vulnData.vulnerabilities || []
        );
      }


      if (
        mitreResponse.status === "fulfilled"
        &&
        mitreResponse.value.ok
      ) {
        const mitreData =
          await mitreResponse.value.json();

        setTechniques(
          mitreData.techniques || []
        );
      }


      if (
        chainResponse.status === "fulfilled"
        &&
        chainResponse.value.ok
      ) {
        const chainData =
          await chainResponse.value.json();

        setChain(
          chainData || {}
        );
      }


      if (
        activityResponse.status === "fulfilled"
        &&
        activityResponse.value.ok
      ) {
        const activityData =
          await activityResponse.value.json();

        setActivities(
          activityData.activities || []
        );
      }

    } catch (error) {
      console.error(
        "Dashboard Error:",
        error
      );

    } finally {
      setLoading(false);
    }
  }


  const severityStats = useMemo(() => {
    const result = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    vulnerabilities.forEach((item) => {
      const severity =
        String(
          item.severity || ""
        ).toLowerCase();

      if (
        Object.prototype.hasOwnProperty.call(
          result,
          severity
        )
      ) {
        result[severity] += 1;
      }
    });

    return result;
  }, [vulnerabilities]);


  const riskScore = useMemo(() => {
    const weightedScore =
      severityStats.critical * 25
      +
      severityStats.high * 14
      +
      severityStats.medium * 7
      +
      severityStats.low * 2;

    return Math.min(
      100,
      weightedScore
    );
  }, [severityStats]);


  const riskLevel =
    riskScore >= 85
      ? "CRITICAL"
      : riskScore >= 65
        ? "HIGH"
        : riskScore >= 40
          ? "MEDIUM"
          : "LOW";


  const attackPhaseCount =
    chain.phase_count
    ||
    chain.phases?.length
    ||
    0;


  const latestVulnerabilities =
    vulnerabilities.slice(0, 6);


  const latestTechniques =
    techniques.slice(0, 6);


  return (
    <div className="dashboard">

      {/* =====================================
          HERO
      ====================================== */}

      <section className="dashboard-hero">

        <div className="dashboard-hero-icon">
          <ShieldAlert size={42} />
        </div>


        <div className="dashboard-hero-copy">

          <span className="dashboard-eyebrow">
            Offensive Security Platform
          </span>

          <h1>
            Hybrid AI
            <span> Red Team </span>
          </h1>

          <p>
            Automated reconnaissance, vulnerability
            assessment, MITRE ATT&amp;CK mapping,
            AI-assisted analysis and professional reporting.
          </p>


          <div className="dashboard-live-status">

            <span
              className={
                `live-dot ${
                  loading
                    ? "pending"
                    : "active"
                }`
              }
            />

            {loading
              ? "Synchronizing with framework engine..."
              : "Framework engine connected and operational"
            }

          </div>

        </div>

      </section>



      {/* =====================================
          STATISTICS
      ====================================== */}

      <section className="stats-grid">

        <StatCard
          icon={
            <ShieldAlert size={27} />
          }
          title="Vulnerabilities"
          value={vulnerabilities.length}
          hint="Detected findings"
        />


        <StatCard
          icon={
            <Target size={27} />
          }
          title="MITRE Techniques"
          value={techniques.length}
          hint="Mapped techniques"
        />


        <StatCard
          icon={
            <GitBranch size={27} />
          }
          title="Attack Phases"
          value={attackPhaseCount}
          hint="Observed attack stages"
        />


        <StatCard
          icon={
            <AlertTriangle size={27} />
          }
          title="Critical Threats"
          value={severityStats.critical}
          hint="Immediate attention"
          variant="critical"
        />

      </section>



      {/* =====================================
          MAIN GRID
      ====================================== */}

      <section className="dashboard-main-grid">

        {/* ACTIVITY */}

        <article className="panel activity-panel">

          <div className="panel-header">

            <div className="panel-title">

              <div className="panel-title-icon">
                <Activity size={21} />
              </div>

              <div>
                <h2>
                  Framework Activity
                </h2>

                <p>
                  Latest pipeline and engine events
                </p>
              </div>

            </div>


            <span className="panel-badge">
              {activities.length} events
            </span>

          </div>


          <ActivityFeed
            activities={activities}
          />

        </article>



        {/* RISK OVERVIEW */}

        <article className="panel risk-overview-panel">

          <div className="panel-header">

            <div className="panel-title">

              <div className="panel-title-icon">
                <ShieldCheck size={21} />
              </div>

              <div>
                <h2>
                  Risk Overview
                </h2>

                <p>
                  Overall security posture
                </p>
              </div>

            </div>


            <span
              className={
                `risk-level-badge ${
                  riskLevel.toLowerCase()
                }`
              }
            >
              {riskLevel}
            </span>

          </div>


          <div className="risk-overview-content">

            <div
              className="risk-score-ring"
              style={{
                "--risk-angle":
                  `${riskScore * 3.6}deg`
              }}
            >

              <div className="risk-score-inner">

                <strong>
                  {riskScore}
                </strong>

                <span>
                  Risk Score
                </span>

              </div>

            </div>


            <div className="risk-severity-list">

              <SeverityRow
                label="Critical"
                value={severityStats.critical}
                total={vulnerabilities.length}
                type="critical"
              />

              <SeverityRow
                label="High"
                value={severityStats.high}
                total={vulnerabilities.length}
                type="high"
              />

              <SeverityRow
                label="Medium"
                value={severityStats.medium}
                total={vulnerabilities.length}
                type="medium"
              />

              <SeverityRow
                label="Low"
                value={severityStats.low}
                total={vulnerabilities.length}
                type="low"
              />

            </div>

          </div>

        </article>

      </section>



      {/* =====================================
          VULNERABILITIES
      ====================================== */}

      <section className="panel dashboard-table-panel">

        <div className="panel-header">

          <div className="panel-title">

            <div className="panel-title-icon">
              <ShieldAlert size={21} />
            </div>

            <div>
              <h2>
                Latest Vulnerabilities
              </h2>

              <p>
                Most recent confirmed findings
              </p>
            </div>

          </div>


          <button
            type="button"
            className="panel-action"
          >
            View All
            <ChevronRight size={16} />
          </button>

        </div>


        <div className="table-wrap">

          <table className="security-table">

            <thead>
              <tr>
                <th>
                  Host
                </th>

                <th>
                  CVE
                </th>

                <th>
                  Severity
                </th>

                <th>
                  CVSS
                </th>
              </tr>
            </thead>


            <tbody>

              {
                latestVulnerabilities.length === 0
                  ? (
                    <tr className="table-empty-row">

                      <td colSpan={4}>
                        No vulnerability data available.
                        Run a security assessment first.
                      </td>

                    </tr>
                  )
                  : (
                    latestVulnerabilities.map(
                      (item, index) => (

                        <tr
                          key={
                            item.cve
                            ||
                            `${item.host}-${index}`
                          }
                        >

                          <td className="mono">
                            {item.host || "N/A"}
                          </td>


                          <td className="mono table-primary-text">
                            {
                              item.cve
                              ||
                              item.vulnerability
                              ||
                              "-"
                            }
                          </td>


                          <td>

                            <span
                              className={
                                `severity ${
                                  String(
                                    item.severity
                                    ||
                                    "unknown"
                                  ).toLowerCase()
                                }`
                              }
                            >
                              {
                                item.severity
                                ||
                                "Unknown"
                              }
                            </span>

                          </td>


                          <td className="mono cvss-value">
                            {
                              item.cvss_live
                              ??
                              item.cvss
                              ??
                              "-"
                            }
                          </td>

                        </tr>

                      )
                    )
                  )
              }

            </tbody>

          </table>

        </div>

      </section>



      {/* =====================================
          MITRE
      ====================================== */}

      <section className="panel dashboard-table-panel">

        <div className="panel-header">

          <div className="panel-title">

            <div className="panel-title-icon">
              <Target size={21} />
            </div>

            <div>
              <h2>
                MITRE ATT&amp;CK Coverage
              </h2>

              <p>
                Techniques mapped by the framework
              </p>
            </div>

          </div>


          <span className="panel-badge">
            {techniques.length} techniques
          </span>

        </div>


        <div className="table-wrap">

          <table className="security-table">

            <thead>
              <tr>

                <th>
                  ID
                </th>

                <th>
                  Technique
                </th>

                <th>
                  Tactic
                </th>

                <th>
                  Confidence
                </th>

              </tr>
            </thead>


            <tbody>

              {
                latestTechniques.length === 0
                  ? (
                    <tr className="table-empty-row">

                      <td colSpan={4}>
                        No MITRE ATT&amp;CK techniques
                        are available yet.
                      </td>

                    </tr>
                  )
                  : (
                    latestTechniques.map(
                      (technique, index) => {

                        const confidence =
                          normalizeConfidence(
                            technique.confidence
                          );

                        return (
                          <tr
                            key={
                              technique.technique_id
                              ||
                              index
                            }
                          >

                            <td className="mono table-primary-text">
                              {
                                technique.technique_id
                                ||
                                technique.techniqueID
                                ||
                                "-"
                              }
                            </td>


                            <td>
                              {
                                technique.technique_name
                                ||
                                technique.name
                                ||
                                "-"
                              }
                            </td>


                            <td>

                              {
                                technique.tactic
                                  ? (
                                    <span className="tactic-pill">
                                      {technique.tactic}
                                    </span>
                                  )
                                  : "-"
                              }

                            </td>


                            <td className="mono">

                              <div className="confidence-value">

                                <span>
                                  {confidence}%
                                </span>

                                <div className="confidence-bar">

                                  <i
                                    style={{
                                      width:
                                        `${confidence}%`
                                    }}
                                  />

                                </div>

                              </div>

                            </td>

                          </tr>
                        );

                      }
                    )
                  )
              }

            </tbody>

          </table>

        </div>

      </section>

    </div>
  );
}



function SeverityRow({
  label,
  value,
  total,
  type
}) {
  const percentage =
    total > 0
      ? Math.round(
          (value / total) * 100
        )
      : 0;

  return (
    <div
      className={
        `severity-overview-row ${type}`
      }
    >

      <div className="severity-overview-label">

        <span />

        {label}

      </div>


      <div className="severity-overview-track">

        <i
          style={{
            width: `${percentage}%`
          }}
        />

      </div>


      <strong>
        {value}
      </strong>

    </div>
  );
}



function normalizeConfidence(value) {
  const number = Number(value);

  if (
    Number.isNaN(number)
    ||
    value === null
    ||
    value === undefined
  ) {
    return 0;
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


export default Dashboard;
