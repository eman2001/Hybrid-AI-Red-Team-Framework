import {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  CircleDot,
  Crosshair,
  GitBranch,
  Network,
  Route,
  ShieldAlert,
  Target,
  TrendingUp
} from "lucide-react";

import {
  getAttackChain,
  getAttackGraph
} from "../api/apiClient";

import AttackGraphViz from "../components/AttackGraphViz";


function AttackChain() {
  const [chain, setChain] = useState(null);
  const [graph, setGraph] = useState(null);

  const [loading, setLoading] = useState(true);
  const [graphLoading, setGraphLoading] = useState(true);

  const [error, setError] = useState("");
  const [graphError, setGraphError] = useState("");


  useEffect(() => {
    loadAttackData();
  }, []);


  async function loadAttackData() {
    setLoading(true);
    setGraphLoading(true);

    setError("");
    setGraphError("");

    try {
      const data =
        await getAttackChain();

      setChain(
        data || null
      );

    } catch (requestError) {
      console.error(
        "Attack chain error:",
        requestError
      );

      setError(
        "Unable to retrieve the attack chain from the framework engine."
      );

    } finally {
      setLoading(false);
    }


    try {
      const graphData =
        await getAttackGraph();

      setGraph(
        graphData || null
      );

    } catch (requestError) {
      console.error(
        "Attack graph error:",
        requestError
      );

      setGraphError(
        "Unable to build the attack graph."
      );

    } finally {
      setGraphLoading(false);
    }
  }


  const phases = useMemo(() => {
    if (!chain?.phases) {
      return [];
    }

    const rawPhases =
      Array.isArray(chain.phases)
        ? chain.phases
        : Object.values(chain.phases);

    return rawPhases.map(
      (phase, index) => ({
        ...phase,

        id:
          phase.id
          ||
          phase.phase_id
          ||
          `phase-${index}`,

        phaseName:
          phase.phase_name
          ||
          phase.phase
          ||
          phase.name
          ||
          `Phase ${index + 1}`,

        tactic:
          phase.tactic
          ||
          phase.mitre_tactic
          ||
          "Unknown tactic",

        techniques:
          normalizeTechniques(
            phase.techniques
          ),

        confidence:
          normalizePercentage(
            phase.confidence
            ??
            phase.avg_confidence
          ),

        host:
          phase.host
          ||
          phase.target
          ||
          "N/A",

        status:
          normalizePhaseStatus(
            phase.status
            ||
            phase.state
            ||
            "completed"
          )
      })
    );
  }, [chain]);


  const statistics = useMemo(() => {
    const techniqueCount =
      chain?.tech_count
      ??
      phases.reduce(
        (total, phase) =>
          total + phase.techniques.length,
        0
      );

    const averageConfidence =
      normalizePercentage(
        chain?.avg_confidence
      )
      ||
      calculateAverageConfidence(
        phases
      );

    return {
      phases:
        chain?.phase_count
        ??
        phases.length,

      techniques:
        techniqueCount,

      confidence:
        averageConfidence,

      nodes:
        graph?.node_count
        ??
        graph?.nodes?.length
        ??
        0,

      edges:
        graph?.edge_count
        ??
        graph?.edges?.length
        ??
        0,

      criticalPath:
        graph?.critical_path?.length
        ??
        0
    };
  }, [chain, graph, phases]);


  return (
    <div className="attack-chain-page">

      {/* =====================================
          HERO
      ====================================== */}

      <section className="attack-chain-hero">

        <div className="attack-chain-hero-icon">
          <GitBranch size={46} />
        </div>


        <div className="attack-chain-hero-copy">

          <span className="attack-chain-eyebrow">
            Attack Path Analysis
          </span>

          <h1>
            AI Attack
            <span> Chain</span>
          </h1>

          <p>
            Visualize the complete adversary path,
            mapped phases, MITRE ATT&amp;CK tactics,
            techniques and graph relationships generated
            by the framework.
          </p>


          <div className="attack-chain-engine-state">

            <span
              className={
                `attack-chain-engine-dot ${
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
                ? "Building attack chain"
                : error
                  ? "Attack-chain engine unavailable"
                  : `${statistics.phases} attack phases mapped`
              }
            </strong>

          </div>

        </div>


        <div className="attack-chain-hero-meta">

          <div>
            <span>
              Analysis Mode
            </span>

            <strong>
              Hybrid Graph
            </strong>
          </div>


          <div>
            <span>
              Framework
            </span>

            <strong>
              ATT&amp;CK Mapped
            </strong>
          </div>

        </div>

      </section>



      {/* =====================================
          SUMMARY
      ====================================== */}

      <section className="attack-chain-summary-grid">

        <AttackMetric
          icon={GitBranch}
          title="Attack Phases"
          value={statistics.phases}
          hint="Observed attack stages"
          type="default"
        />


        <AttackMetric
          icon={Target}
          title="Techniques"
          value={statistics.techniques}
          hint="Mapped ATT&CK techniques"
          type="techniques"
        />


        <AttackMetric
          icon={TrendingUp}
          title="Confidence"
          value={`${statistics.confidence}%`}
          hint="Average mapping confidence"
          type="confidence"
        />


        <AttackMetric
          icon={Network}
          title="Graph Nodes"
          value={statistics.nodes}
          hint="Attack entities"
          type="nodes"
        />


        <AttackMetric
          icon={Route}
          title="Critical Path"
          value={statistics.criticalPath}
          hint="Priority path elements"
          type="critical"
        />

      </section>



      {/* =====================================
          ATTACK GRAPH
      ====================================== */}

      <section className="attack-chain-panel attack-graph-panel">

        <div className="attack-chain-panel-header">

          <div className="attack-chain-panel-heading">

            <div className="attack-chain-panel-icon">
              <Network size={21} />
            </div>

            <div>
              <h2>
                Attack Graph
              </h2>

              <p>
                Nodes, edges and critical-path relationships
              </p>
            </div>

          </div>


          <div className="attack-graph-meta">

            <span>
              {statistics.nodes} nodes
            </span>

            <span>
              {statistics.edges} edges
            </span>

          </div>

        </div>


        {graphLoading ? (

          <AttackChainLoading
            title="Building Attack Graph"
            description="Analyzing nodes, edges and attack-path relationships."
          />

        ) : graphError ? (

          <div className="attack-chain-error-state">

            <AlertTriangle size={40} />

            <h3>
              Attack Graph Unavailable
            </h3>

            <p>
              {graphError}
            </p>

            <button
              type="button"
              onClick={loadAttackData}
            >
              Retry Connection
            </button>

          </div>

        ) : graph ? (

          <div className="attack-graph-container">

            <AttackGraphViz
              nodes={graph.nodes || []}
              edges={graph.edges || []}
              criticalPath={
                graph.critical_path || []
              }
            />

          </div>

        ) : (

          <div className="attack-chain-empty-state">

            <Network size={40} />

            <h3>
              No Attack Graph Available
            </h3>

            <p>
              Run a complete security assessment to
              generate graph relationships.
            </p>

          </div>

        )}

      </section>



      {/* =====================================
          PHASE TIMELINE
      ====================================== */}

      <section className="attack-chain-panel attack-phases-panel">

        <div className="attack-chain-panel-header">

          <div className="attack-chain-panel-heading">

            <div className="attack-chain-panel-icon">
              <Route size={21} />
            </div>

            <div>
              <h2>
                Attack Phase Timeline
              </h2>

              <p>
                Ordered adversary activity across the assessment
              </p>
            </div>

          </div>


          <span className="attack-chain-panel-badge">
            {phases.length} phases
          </span>

        </div>


        {loading ? (

          <AttackChainLoading
            title="Loading Attack Chain"
            description="Retrieving mapped phases from the framework engine."
          />

        ) : error ? (

          <div className="attack-chain-error-state">

            <AlertTriangle size={40} />

            <h3>
              Attack Chain Unavailable
            </h3>

            <p>
              {error}
            </p>

            <button
              type="button"
              onClick={loadAttackData}
            >
              Retry Connection
            </button>

          </div>

        ) : phases.length === 0 ? (

          <div className="attack-chain-empty-state">

            <ShieldAlert size={40} />

            <h3>
              No Attack Chain Generated
            </h3>

            <p>
              Run an assessment to generate ordered
              adversary phases and techniques.
            </p>

          </div>

        ) : (

          <div className="attack-phase-timeline">

            {phases.map(
              (phase, index) => (

                <AttackPhase
                  key={phase.id}
                  phase={phase}
                  index={index}
                  isLast={
                    index === phases.length - 1
                  }
                />

              )
            )}

          </div>

        )}

      </section>

    </div>
  );
}



function AttackMetric({
  icon: Icon,
  title,
  value,
  hint,
  type
}) {
  return (
    <article
      className={
        `attack-metric-card ${type}`
      }
    >

      <div className="attack-metric-top">

        <div className="attack-metric-icon">
          <Icon size={24} />
        </div>

        <Activity size={17} />

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



function AttackPhase({
  phase,
  index,
  isLast
}) {
  return (
    <article className="attack-phase-row">

      <div className="attack-phase-rail">

        <div
          className={
            `attack-phase-node ${phase.status}`
          }
        >
          {phase.status === "completed" ? (
            <CheckCircle2 size={20} />
          ) : phase.status === "active" ? (
            <Activity size={20} />
          ) : (
            <CircleDot size={20} />
          )}
        </div>


        {!isLast && (
          <span className="attack-phase-line" />
        )}

      </div>


      <div className="attack-phase-card">

        <div className="attack-phase-card-header">

          <div>

            <span className="attack-phase-number">
              Phase {index + 1}
            </span>

            <h3>
              {phase.phaseName}
            </h3>

          </div>


          <span
            className={
              `attack-phase-status ${phase.status}`
            }
          >
            {phase.status}
          </span>

        </div>


        <div className="attack-phase-details">

          <div>

            <span>
              MITRE Tactic
            </span>

            <strong>
              {formatValue(
                phase.tactic
              )}
            </strong>

          </div>


          <div>

            <span>
              Techniques
            </span>

            <strong>
              {phase.techniques.length}
            </strong>

          </div>


          <div>

            <span>
              Confidence
            </span>

            <strong>
              {phase.confidence}%
            </strong>

          </div>


          <div>

            <span>
              Target
            </span>

            <strong className="attack-phase-host">
              {phase.host}
            </strong>

          </div>

        </div>


        <div className="attack-phase-techniques">

          {phase.techniques.length > 0 ? (

            phase.techniques.map(
              (technique, techniqueIndex) => (

                <span
                  key={
                    technique.id
                    ||
                    techniqueIndex
                  }
                >
                  <Crosshair size={13} />

                  {technique.id}

                  {technique.name && (
                    <small>
                      {technique.name}
                    </small>
                  )}
                </span>

              )
            )

          ) : (

            <span className="attack-phase-no-techniques">
              No techniques recorded
            </span>

          )}

        </div>

      </div>

    </article>
  );
}



function AttackChainLoading({
  title,
  description
}) {
  return (
    <div className="attack-chain-loading-state">

      <div className="attack-chain-spinner" />

      <h3>
        {title}
      </h3>

      <p>
        {description}
      </p>

    </div>
  );
}



function normalizeTechniques(value) {
  if (!value) {
    return [];
  }

  const techniques =
    Array.isArray(value)
      ? value
      : Object.values(value);

  return techniques.map(
    (technique, index) => {

      if (
        typeof technique === "string"
      ) {
        return {
          id: technique,
          name: ""
        };
      }

      return {
        ...technique,

        id:
          technique.technique_id
          ||
          technique.techniqueID
          ||
          technique.id
          ||
          `T-${index + 1}`,

        name:
          technique.technique_name
          ||
          technique.name
          ||
          ""
      };
    }
  );
}



function normalizePercentage(value) {
  if (
    value === null
    ||
    value === undefined
    ||
    value === ""
  ) {
    return 0;
  }

  const parsed =
    Number(
      String(value)
        .replace("%", "")
        .trim()
    );

  if (Number.isNaN(parsed)) {
    return 0;
  }

  if (parsed <= 1) {
    return Math.round(
      parsed * 100
    );
  }

  return Math.min(
    100,
    Math.round(parsed)
  );
}



function calculateAverageConfidence(
  phases
) {
  const values =
    phases
      .map(
        phase => phase.confidence
      )
      .filter(
        value => value > 0
      );

  if (!values.length) {
    return 0;
  }

  return Math.round(
    values.reduce(
      (total, value) =>
        total + value,
      0
    )
    /
    values.length
  );
}



function normalizePhaseStatus(value) {
  const status =
    String(
      value || ""
    ).toLowerCase();

  if (
    status === "running"
    ||
    status === "active"
  ) {
    return "active";
  }

  if (
    status === "failed"
    ||
    status === "error"
  ) {
    return "failed";
  }

  if (
    status === "pending"
    ||
    status === "waiting"
  ) {
    return "pending";
  }

  return "completed";
}



function formatValue(value) {
  return String(
    value || "Unknown"
  )
    .replaceAll("_", " ")
    .replaceAll("-", " ");
}


export default AttackChain;
