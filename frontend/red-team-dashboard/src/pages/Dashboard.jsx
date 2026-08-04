import {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  Activity,
  AlertTriangle,
  GitBranch,
  ShieldAlert,
  ShieldCheck,
  Target
} from "lucide-react";

import StatCard from "../components/StatCard";
import ActivityFeed from "../components/ActivityFeed";


const API =
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
  ] = useState(false);

  const [
    engineStatus,
    setEngineStatus
  ] = useState("idle");

  const [
    error,
    setError
  ] = useState("");


  useEffect(() => {
    let cancelled = false;
    let timer;


    function resetDashboard() {
      setVulnerabilities([]);
      setTechniques([]);
      setChain({});
      setActivities([]);
      setError("");
    }


    async function synchronizeDashboard() {
      const scanStarted =
        sessionStorage.getItem(
          "currentScanStarted"
        ) === "true";


      /*
       * عند فتح الموقع في Tab جديد:
       * لا نعرض نتائج قديمة من قاعدة البيانات.
       */
      if (!scanStarted) {
        resetDashboard();
        setLoading(false);
        setEngineStatus("idle");
        return;
      }


      try {
        const progressResponse =
          await fetch(
            `${API}/api/progress?_=${Date.now()}`,
            {
              cache: "no-store",
              headers: {
                "Cache-Control":
                  "no-cache, no-store, must-revalidate"
              }
            }
          );


        if (!progressResponse.ok) {
          throw new Error(
            `Progress request failed: ${progressResponse.status}`
          );
        }


        const progressData =
          await progressResponse.json();


        if (cancelled) {
          return;
        }


        const phase =
          Number(
            progressData?.phase || 0
          );


        const status =
          String(
            progressData?.status || "idle"
          )
            .trim()
            .toLowerCase();


        setEngineStatus(status);


        const fullyCompleted =
          status === "completed"
          &&
          phase >= 12;


        const currentlyRunning =
          status === "running"
          ||
          status === "started";


        if (currentlyRunning) {
          resetDashboard();
          setLoading(true);

          sessionStorage.removeItem(
            "currentScanCompleted"
          );

          return;
        }


        if (status === "failed") {
          resetDashboard();
          setLoading(false);

          setError(
            progressData?.message
            ||
            "The latest security assessment failed."
          );

          return;
        }


        if (fullyCompleted) {
          sessionStorage.setItem(
            "currentScanCompleted",
            "true"
          );

          await loadDashboardData(
            cancelled
          );

          setLoading(false);
          return;
        }


        /*
         * لو الحالة idle لكن تم بدء Scan في هذا الـTab،
         * لا نعرض نتائج قاعدة البيانات القديمة.
         */
        resetDashboard();
        setLoading(false);

      } catch (requestError) {
        console.error(
          "Dashboard synchronization error:",
          requestError
        );

        if (!cancelled) {
          resetDashboard();
          setLoading(false);
          setEngineStatus("error");

          setError(
            "Unable to synchronize with the framework engine."
          );
        }
      }
    }


    async function loadDashboardData() {
      const [
        vulnerabilityData,
        mitreData,
        chainData,
        activityData
      ] = await Promise.all([
        fetchJsonOrDefault(
          `${API}/api/vulnerabilities/?_=${Date.now()}`,
          {
            vulnerabilities: []
          }
        ),

        fetchJsonOrDefault(
          `${API}/api/mitre/techniques?_=${Date.now()}`,
          {
            techniques: []
          }
        ),

        fetchJsonOrDefault(
          `${API}/api/attack-chain/?_=${Date.now()}`,
          {}
        ),

        fetchJsonOrDefault(
          `${API}/api/activity/?_=${Date.now()}`,
          {
            activities: []
          }
        )
      ]);


      if (cancelled) {
        return;
      }


      setVulnerabilities(
        Array.isArray(
          vulnerabilityData?.vulnerabilities
        )
          ? vulnerabilityData.vulnerabilities
          : []
      );


      setTechniques(
        Array.isArray(
          mitreData?.techniques
        )
          ? mitreData.techniques
          : []
      );


      setChain(
        chainData
        &&
        typeof chainData === "object"
          ? chainData
          : {}
      );


      setActivities(
        Array.isArray(
          activityData?.activities
        )
          ? activityData.activities
          : []
      );


      setError("");
    }


    function handleScanStarted() {
      resetDashboard();
      setLoading(true);
      setEngineStatus("running");
    }


    function handleScanCompleted() {
      synchronizeDashboard();
    }


    /*
     * التهيئة الأولى.
     */
    synchronizeDashboard();


    /*
     * فحص حالة الـBackend كل ثانيتين.
     */
    timer = window.setInterval(
      synchronizeDashboard,
      2000
    );


    window.addEventListener(
      "scanStarted",
      handleScanStarted
    );


    window.addEventListener(
      "scanCompleted",
      handleScanCompleted
    );


    return () => {
      cancelled = true;

      if (timer) {
        window.clearInterval(timer);
      }

      window.removeEventListener(
        "scanStarted",
        handleScanStarted
      );

      window.removeEventListener(
        "scanCompleted",
        handleScanCompleted
      );
    };
  }, []);


  const criticalCount =
    useMemo(() => {
      return vulnerabilities.filter(
        vulnerability =>
          String(
            vulnerability?.severity || ""
          ).toLowerCase() === "critical"
      ).length;
    }, [vulnerabilities]);


  const phaseCount =
    Number(
      chain?.phase_count
      ??
      (
        Array.isArray(chain?.phases)
          ? chain.phases.length
          : chain?.phases
            ? Object.keys(
                chain.phases
              ).length
            : 0
      )
    ) || 0;


  const dashboardStatus =
    getDashboardStatus({
      loading,
      engineStatus,
      error
    });


  return (
    <div className="dashboard">

      <div className="dashboard-header">

        <div className="dashboard-title">

          <div className="dashboard-logo">
            <ShieldCheck size={30} />
          </div>


          <div>

            <h1>
              Hybrid AI Red Team Framework
            </h1>


            <p className="dashboard-subtitle">

              <span
                className={
                  `live-dot ${
                    dashboardStatus.className
                  }`
                }
              />

              {dashboardStatus.text}

            </p>

          </div>

        </div>

      </div>



      {error && (
        <div className="dashboard-error-message">

          <AlertTriangle size={18} />

          <span>
            {error}
          </span>

        </div>
      )}



      <div className="stats-grid">

        <StatCard
          icon={
            <ShieldAlert size={26} />
          }
          title="Vulnerabilities"
          value={vulnerabilities.length}
          hint={
            loading
              ? "Assessment in progress"
              : "Confirmed findings"
          }
        />


        <StatCard
          icon={
            <Target size={26} />
          }
          title="MITRE Techniques"
          value={techniques.length}
          hint={
            loading
              ? "Waiting for mapping"
              : "Mapped techniques"
          }
        />


        <StatCard
          icon={
            <GitBranch size={26} />
          }
          title="Attack Phases"
          value={phaseCount}
          hint={
            loading
              ? "Building attack chain"
              : "Generated phases"
          }
        />


        <StatCard
          icon={
            <AlertTriangle size={26} />
          }
          title="Critical Threats"
          value={criticalCount}
          hint={
            loading
              ? "Risk analysis pending"
              : "Immediate attention"
          }
        />

      </div>



      <div className="panel">

        <div className="panel-header">

          <h2>
            <Activity size={20} />
            Activity Feed
          </h2>

          <span className="panel-badge">
            {activities.length} events
          </span>

        </div>


        {loading ? (
          <DashboardWaitingState
            title="Assessment in Progress"
            description={
              "Live findings will appear after the current assessment is completed."
            }
          />
        ) : (
          <ActivityFeed
            activities={activities}
          />
        )}

      </div>



      <div className="panel">

        <div className="panel-header">

          <h2>
            <ShieldAlert size={20} />
            Latest Vulnerabilities
          </h2>

          <span className="panel-badge">
            {vulnerabilities.length} total
          </span>

        </div>


        <div className="table-wrap">

          <table>

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

              {vulnerabilities.length === 0 ? (

                <tr className="table-empty-row">

                  <td colSpan={4}>

                    {loading
                      ? "The assessment is running. New findings will appear after completion."
                      : "No vulnerabilities available. Start a new security assessment."
                    }

                  </td>

                </tr>

              ) : (

                vulnerabilities
                  .slice(0, 8)
                  .map(
                    (
                      vulnerability,
                      index
                    ) => (

                      <tr
                        key={
                          vulnerability.id
                          ||
                          vulnerability.cve
                          ||
                          index
                        }
                      >

                        <td className="mono">
                          {vulnerability.host || "N/A"}
                        </td>


                        <td className="mono">
                          {
                            vulnerability.cve
                            ||
                            vulnerability.vulnerability
                            ||
                            "-"
                          }
                        </td>


                        <td>

                          <span
                            className={
                              `severity ${
                                String(
                                  vulnerability.severity
                                  ||
                                  "unknown"
                                ).toLowerCase()
                              }`
                            }
                          >
                            {
                              vulnerability.severity
                              ||
                              "Unknown"
                            }
                          </span>

                        </td>


                        <td className="mono">
                          {
                            vulnerability.cvss_live
                            ??
                            vulnerability.cvss
                            ??
                            "-"
                          }
                        </td>

                      </tr>

                    )
                  )

              )}

            </tbody>

          </table>

        </div>

      </div>



      <div className="panel">

        <div className="panel-header">

          <h2>
            <Target size={20} />
            MITRE ATT&amp;CK Coverage
          </h2>

          <span className="panel-badge">
            {techniques.length} techniques
          </span>

        </div>


        <div className="table-wrap">

          <table>

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

              {techniques.length === 0 ? (

                <tr className="table-empty-row">

                  <td colSpan={4}>

                    {loading
                      ? "MITRE mapping will appear after the current assessment is completed."
                      : "No MITRE techniques available. Start a new security assessment."
                    }

                  </td>

                </tr>

              ) : (

                techniques
                  .slice(0, 8)
                  .map(
                    (
                      technique,
                      index
                    ) => {

                      const confidence =
                        normalizeConfidence(
                          technique.confidence
                        );


                      return (
                        <tr
                          key={
                            technique.technique_id
                            ||
                            technique.techniqueID
                            ||
                            index
                          }
                        >

                          <td className="mono">
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

                            {technique.tactic ? (

                              <span className="tactic-pill">
                                {technique.tactic}
                              </span>

                            ) : (
                              "-"
                            )}

                          </td>


                          <td className="mono">
                            {
                              confidence !== null
                                ? `${confidence}%`
                                : "-"
                            }
                          </td>

                        </tr>
                      );
                    }
                  )

              )}

            </tbody>

          </table>

        </div>

      </div>

    </div>
  );
}


async function fetchJsonOrDefault(
  url,
  fallback
) {
  try {
    const response = await fetch(
      url,
      {
        cache: "no-store",
        headers: {
          "Cache-Control":
            "no-cache, no-store, must-revalidate",
          "Pragma":
            "no-cache"
        }
      }
    );


    /*
     * بعض الـEndpoints ترجع 404 عندما
     * لا توجد بيانات بعد. نعتبرها قائمة فارغة.
     */
    if (response.status === 404) {
      return fallback;
    }


    if (!response.ok) {
      throw new Error(
        `Request failed: ${response.status}`
      );
    }


    return await response.json();

  } catch (error) {
    console.warn(
      `Dashboard request failed for ${url}:`,
      error
    );

    return fallback;
  }
}


function normalizeConfidence(value) {
  if (
    value === null
    ||
    value === undefined
    ||
    value === ""
  ) {
    return null;
  }


  const number = Number(
    String(value)
      .replace("%", "")
      .trim()
  );


  if (Number.isNaN(number)) {
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


function getDashboardStatus({
  loading,
  engineStatus,
  error
}) {
  if (error) {
    return {
      className: "pending",
      text: "Engine synchronization unavailable"
    };
  }


  if (
    loading
    ||
    engineStatus === "running"
    ||
    engineStatus === "started"
  ) {
    return {
      className: "pending",
      text: "Live · assessment in progress"
    };
  }


  if (engineStatus === "completed") {
    return {
      className: "active",
      text: "Live · latest assessment loaded"
    };
  }


  return {
    className: "active",
    text: "Ready · waiting for a new assessment"
  };
}


function DashboardWaitingState({
  title,
  description
}) {
  return (
    <div className="dashboard-waiting-state">

      <div className="dashboard-waiting-spinner" />

      <strong>
        {title}
      </strong>

      <p>
        {description}
      </p>

    </div>
  );
}


export default Dashboard;
