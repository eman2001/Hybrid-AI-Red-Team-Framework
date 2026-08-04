import {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Check,
  CheckCircle2,
  Circle,
  Clock3,
  Crosshair,
  Database,
  FileText,
  Fingerprint,
  GitBranch,
  Globe2,
  LoaderCircle,
  Monitor,
  Network,
  Radar,
  Rocket,
  ScanLine,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  TerminalSquare,
  Users
} from "lucide-react";

import {
  startScan,
  getProgress
} from "../api/apiClient";


const PIPELINE_STAGES = [
  {
    id: 1,
    short: "Recon",
    title: "Reconnaissance",
    description: "Host discovery and asset identification",
    icon: Radar
  },
  {
    id: 2,
    short: "Scan",
    title: "Scanning",
    description: "Ports, services and OWASP assessment",
    icon: ScanLine
  },
  {
    id: 3,
    short: "Vulns",
    title: "Vulnerability Mapping",
    description: "CVE identification and service correlation",
    icon: ShieldAlert
  },
  {
    id: 4,
    short: "Threat",
    title: "Threat Intelligence",
    description: "CVSS, EPSS, KEV and vendor enrichment",
    icon: Globe2
  },
  {
    id: 5,
    short: "Risk",
    title: "Risk Engine",
    description: "Deterministic risk scoring and prioritization",
    icon: Crosshair
  },
  {
    id: 6,
    short: "Exploit",
    title: "Exploitation",
    description: "Controlled exploit validation and simulation",
    icon: TerminalSquare
  },
  {
    id: 7,
    short: "Post",
    title: "Post-Exploitation",
    description: "Discovery, privilege and credential analysis",
    icon: Fingerprint
  },
  {
    id: 8,
    short: "MITRE",
    title: "MITRE ATT&CK",
    description: "Technique mapping and confidence fusion",
    icon: Target
  },
  {
    id: 9,
    short: "AI",
    title: "AI Enrichment",
    description: "Analysis, explanation and recommendations",
    icon: BrainCircuit
  },
  {
    id: 10,
    short: "Graph",
    title: "Attack Graph",
    description: "Nodes, edges and attack-path analysis",
    icon: GitBranch
  },
  {
    id: 11,
    short: "Social",
    title: "Social Engineering",
    description: "Controlled campaign and pretext simulation",
    icon: Users
  },
  {
    id: 12,
    short: "Report",
    title: "Reporting",
    description: "JSON, AI narrative and PDF generation",
    icon: FileText
  }
];


function Scan() {
  const [target, setTarget] = useState("");
  const [lhost, setLhost] = useState("10.0.2.4");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [progress, setProgress] = useState({
    phase: 0,
    title: "Waiting for assessment",
    progress: 0,
    status: "idle"
  });


  useEffect(() => {
    if (!loading) {
      return undefined;
    }

    let cancelled = false;

    async function pollProgress() {
      try {
        const data = await getProgress();

        if (cancelled) {
          return;
        }

        setProgress({
          phase: Number(data.phase || 0),
          title:
            data.title ||
            data.message ||
            "Security assessment running",
          progress: normalizeProgress(
            data.progress
          ),
          status:
            String(
              data.status || "running"
            ).toLowerCase()
        });

        if (
          data.status === "completed"
          ||
          data.status === "failed"
        ) {
          setLoading(false);

          if (data.status === "failed") {
            setError(
              data.error ||
              data.message ||
              "The security assessment failed."
            );
          }
        }
      } catch (requestError) {
        console.error(
          "Progress polling error:",
          requestError
        );

        if (!cancelled) {
          setError(
            "Unable to retrieve progress from the framework engine."
          );
        }
      }
    }

    pollProgress();

    const timer = window.setInterval(
      pollProgress,
      2000
    );

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [loading]);


  async function runAssessment() {
    const cleanTarget = target.trim();
    const cleanLhost = lhost.trim();

    if (!cleanTarget) {
      setError(
        "Enter a target IP address or URL before starting the assessment."
      );

      return;
    }

    if (!cleanLhost) {
      setError(
        "Enter the Kali LHOST address before starting the assessment."
      );

      return;
    }

    setError("");
    setLoading(true);

    setProgress({
      phase: 0,
      title: "Initializing assessment engine",
      progress: 0,
      status: "running"
    });

    try {
      await startScan(
        cleanTarget,
        cleanLhost
      );
    } catch (requestError) {
      console.error(
        "Scan start error:",
        requestError
      );

      setLoading(false);

      setProgress({
        phase: 0,
        title: "Assessment could not be started",
        progress: 0,
        status: "failed"
      });

      setError(
        requestError?.message ||
        "The framework engine could not start the assessment."
      );
    }
  }


  const activeStage = useMemo(() => {
    return (
      PIPELINE_STAGES.find(
        stage => stage.id === progress.phase
      )
      ||
      null
    );
  }, [progress.phase]);


  const statusLabel = formatStatus(
    progress.status
  );


  const completedStages = Math.max(
    0,
    Math.min(
      PIPELINE_STAGES.length,
      progress.status === "completed"
        ? PIPELINE_STAGES.length
        : progress.phase - 1
    )
  );


  return (
    <div className="scan-page">

      {/* =====================================
          HERO
      ====================================== */}

      <section className="scan-hero">

        <div className="scan-hero-icon">
          <ShieldCheck size={46} />
        </div>


        <div className="scan-hero-copy">

          <span className="scan-eyebrow">
            Automated Security Assessment
          </span>

          <h1>
            Red Team
            <span> Scan Engine</span>
          </h1>

          <p>
            Launch the complete Hybrid AI Red Team
            pipeline against an authorized laboratory
            target, from reconnaissance through
            professional reporting.
          </p>


          <div className="scan-engine-state">

            <span
              className={
                `scan-engine-dot ${
                  loading
                    ? "running"
                    : progress.status
                }`
              }
            />

            <strong>
              {loading
                ? "Assessment engine active"
                : progress.status === "completed"
                  ? "Assessment completed"
                  : progress.status === "failed"
                    ? "Assessment interrupted"
                    : "Engine ready"
              }
            </strong>

          </div>

        </div>


        <div className="scan-hero-meta">

          <div>
            <span>
              Pipeline
            </span>

            <strong>
              12 Stages
            </strong>
          </div>


          <div>
            <span>
              Mode
            </span>

            <strong>
              Authorized Lab
            </strong>
          </div>

        </div>

      </section>



      {/* =====================================
          CONTROL PANEL
      ====================================== */}

      <section className="scan-control-grid">

        <article className="scan-panel scan-launch-panel">

          <div className="scan-panel-header">

            <div className="scan-panel-heading">

              <div className="scan-panel-icon">
                <Rocket size={21} />
              </div>

              <div>
                <h2>
                  Launch Assessment
                </h2>

                <p>
                  Configure the target and attacker host
                </p>
              </div>

            </div>


            <span className="scan-ready-badge">
              <i />
              Ready
            </span>

          </div>


          <div className="scan-form">

            <div className="input-group">

              <label htmlFor="scan-target">
                <Target size={18} />
                Target IP or URL
              </label>

              <div className="scan-input-shell">

                <Crosshair size={18} />

                <input
                  id="scan-target"
                  value={target}
                  onChange={
                    event => {
                      setTarget(
                        event.target.value
                      );

                      if (error) {
                        setError("");
                      }
                    }
                  }
                  placeholder="10.0.2.3 or http://target.local"
                  disabled={loading}
                  autoComplete="off"
                />

              </div>

              <small>
                Use only systems you are authorized to test.
              </small>

            </div>


            <div className="input-group">

              <label htmlFor="scan-lhost">
                <Monitor size={18} />
                Kali LHOST
              </label>

              <div className="scan-input-shell">

                <Network size={18} />

                <input
                  id="scan-lhost"
                  value={lhost}
                  onChange={
                    event =>
                      setLhost(
                        event.target.value
                      )
                  }
                  placeholder="10.0.2.4"
                  disabled={loading}
                  autoComplete="off"
                />

              </div>

              <small>
                Callback address used by the controlled lab.
              </small>

            </div>


            {error && (
              <div className="scan-error-message">

                <AlertTriangle size={18} />

                <span>
                  {error}
                </span>

              </div>
            )}


            <button
              type="button"
              className={
                `scan-btn ${
                  loading
                    ? "scan-btn-running"
                    : ""
                }`
              }
              onClick={runAssessment}
              disabled={loading}
            >

              {loading ? (
                <>
                  <LoaderCircle
                    className="scan-spinner"
                    size={21}
                  />

                  Assessment Running
                </>
              ) : (
                <>
                  <Rocket size={21} />

                  Start Security Assessment
                </>
              )}

            </button>

          </div>

        </article>



        {/* =====================================
            LIVE STATUS
        ====================================== */}

        <article className="scan-panel scan-status-panel">

          <div className="scan-panel-header">

            <div className="scan-panel-heading">

              <div className="scan-panel-icon">
                <Activity size={21} />
              </div>

              <div>
                <h2>
                  Live Engine Status
                </h2>

                <p>
                  Current pipeline execution state
                </p>
              </div>

            </div>


            <span
              className={
                `scan-status-badge ${
                  progress.status
                }`
              }
            >
              {statusLabel}
            </span>

          </div>


          <div className="scan-current-stage">

            <div className="scan-current-stage-icon">

              {activeStage ? (
                <activeStage.icon size={28} />
              ) : (
                <ServerCog size={28} />
              )}

            </div>


            <div>

              <span>
                Current Operation
              </span>

              <strong>
                {progress.title}
              </strong>

              <p>
                {activeStage?.description
                  ||
                  "The framework is waiting for a new authorized assessment."
                }
              </p>

            </div>

          </div>


          <div className="scan-progress-summary">

            <div>

              <span>
                Overall Progress
              </span>

              <strong>
                {progress.progress}%
              </strong>

            </div>


            <div>

              <span>
                Current Phase
              </span>

              <strong>
                {progress.phase || 0}/12
              </strong>

            </div>


            <div>

              <span>
                Completed
              </span>

              <strong>
                {completedStages}
              </strong>

            </div>

          </div>


          <div className="scan-progress-track">

            <div
              className="scan-progress-fill"
              style={{
                width:
                  `${progress.progress}%`
              }}
            />

          </div>


          <div className="scan-progress-footer">

            <span>
              <Clock3 size={15} />
              Polling every 2 seconds
            </span>

            <span>
              <Database size={15} />
              Engine data synchronized
            </span>

          </div>

        </article>

      </section>



      {/* =====================================
          PIPELINE
      ====================================== */}

      <section className="scan-panel scan-pipeline-panel">

        <div className="scan-panel-header">

          <div className="scan-panel-heading">

            <div className="scan-panel-icon">
              <GitBranch size={21} />
            </div>

            <div>
              <h2>
                Assessment Pipeline
              </h2>

              <p>
                Full-scope Hybrid AI Red Team workflow
              </p>
            </div>

          </div>


          <span className="scan-pipeline-count">
            {completedStages}/12 complete
          </span>

        </div>


        <div className="scan-pipeline-grid">

          {PIPELINE_STAGES.map(
            stage => {

              const state =
                getStageState(
                  stage.id,
                  progress.phase,
                  progress.status
                );

              const StageIcon =
                stage.icon;

              return (
                <article
                  key={stage.id}
                  className={
                    `scan-stage-card ${state}`
                  }
                >

                  <div className="scan-stage-top">

                    <div className="scan-stage-number">

                      {state === "completed" ? (
                        <Check size={17} />
                      ) : state === "active" ? (
                        <LoaderCircle
                          className="scan-stage-spinner"
                          size={17}
                        />
                      ) : state === "failed" ? (
                        <AlertTriangle size={17} />
                      ) : (
                        stage.id
                      )}

                    </div>


                    <StageIcon size={21} />

                  </div>


                  <div className="scan-stage-copy">

                    <span>
                      {stage.short}
                    </span>

                    <strong>
                      {stage.title}
                    </strong>

                    <p>
                      {stage.description}
                    </p>

                  </div>


                  <div className="scan-stage-state">

                    {state === "completed" && (
                      <>
                        <CheckCircle2 size={14} />
                        Complete
                      </>
                    )}

                    {state === "active" && (
                      <>
                        <Activity size={14} />
                        Running
                      </>
                    )}

                    {state === "failed" && (
                      <>
                        <AlertTriangle size={14} />
                        Failed
                      </>
                    )}

                    {state === "pending" && (
                      <>
                        <Circle size={14} />
                        Pending
                      </>
                    )}

                  </div>

                </article>
              );
            }
          )}

        </div>

      </section>

    </div>
  );
}


function normalizeProgress(value) {
  const number = Number(value);

  if (Number.isNaN(number)) {
    return 0;
  }

  return Math.max(
    0,
    Math.min(
      100,
      Math.round(number)
    )
  );
}


function formatStatus(status) {
  const value = String(
    status || "idle"
  ).toLowerCase();

  if (value === "running") {
    return "Running";
  }

  if (value === "completed") {
    return "Completed";
  }

  if (value === "failed") {
    return "Failed";
  }

  return "Idle";
}


function getStageState(
  stageId,
  currentPhase,
  status
) {
  const normalizedStatus =
    String(
      status || "idle"
    ).toLowerCase();

  if (
    normalizedStatus === "completed"
  ) {
    return "completed";
  }

  if (
    normalizedStatus === "failed"
    &&
    stageId === currentPhase
  ) {
    return "failed";
  }

  if (
    stageId < currentPhase
  ) {
    return "completed";
  }

  if (
    stageId === currentPhase
    &&
    normalizedStatus === "running"
  ) {
    return "active";
  }

  return "pending";
}


export default Scan;
