import {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  ChevronDown,
  Crosshair,
  Database,
  Filter,
  Flame,
  Layers3,
  Radar,
  Search,
  ShieldCheck,
  Target,
  TrendingUp
} from "lucide-react";

import {
  getMitre,
  getMitreHeatmap
} from "../api/apiClient";


const SOURCE_OPTIONS = [
  "all",
  "rule_exact",
  "rule_service",
  "stix",
  "ml",
  "post_exploit"
];


function Mitre() {
  const [data, setData] = useState({
    techniques: [],
    tactics_covered: 0,
    total_techniques: 0
  });

  const [heatmap, setHeatmap] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");


  useEffect(() => {
    loadMitre();
  }, []);


  async function loadMitre() {
    try {
      setLoading(true);
      setError("");

      const [
        result,
        map
      ] = await Promise.all([
        getMitre(),
        getMitreHeatmap()
      ]);

      setData({
        techniques:
          result?.techniques || [],

        tactics_covered:
          result?.tactics_covered || 0,

        total_techniques:
          result?.total_techniques
          ||
          result?.techniques?.length
          ||
          0
      });

      setHeatmap(
        map?.techniques || []
      );

    } catch (requestError) {
      console.error(
        "MITRE Error:",
        requestError
      );

      setError(
        "Unable to retrieve MITRE ATT&CK data from the framework engine."
      );

    } finally {
      setLoading(false);
    }
  }


  const normalizedTechniques =
    useMemo(() => {
      return data.techniques.map(
        (technique, index) => ({
          ...technique,

          id:
            technique.technique_id
            ||
            technique.techniqueID
            ||
            `technique-${index}`,

          techniqueId:
            technique.technique_id
            ||
            technique.techniqueID
            ||
            "-",

          techniqueName:
            technique.technique_name
            ||
            technique.name
            ||
            "Unknown technique",

          tactic:
            technique.tactic
            ||
            "unknown",

          confidence:
            normalizePercentage(
              technique.confidence
            ),

          score:
            normalizeScore(
              technique.score
              ??
              technique.confidence
            ),

          source:
            normalizeSource(
              technique.source
              ||
              extractCommentField(
                technique.comment,
                "Source"
              )
            )
        })
      );
    }, [data.techniques]);


  const normalizedHeatmap =
    useMemo(() => {
      return heatmap.map(
        (technique, index) => ({
          ...technique,

          id:
            technique.techniqueID
            ||
            technique.technique_id
            ||
            `heatmap-${index}`,

          techniqueId:
            technique.techniqueID
            ||
            technique.technique_id
            ||
            "-",

          score:
            normalizeScore(
              technique.score
            ),

          confidence:
            normalizePercentage(
              technique.confidence
              ??
              extractCommentField(
                technique.comment,
                "Confidence"
              )
            ),

          source:
            normalizeSource(
              technique.source
              ||
              extractCommentField(
                technique.comment,
                "Source"
              )
            ),

          host:
            technique.host
            ||
            extractCommentField(
              technique.comment,
              "Host"
            )
            ||
            "N/A"
        })
      );
    }, [heatmap]);


  const filteredTechniques =
    useMemo(() => {
      const searchValue =
        search.trim().toLowerCase();

      return normalizedTechniques
        .filter(technique => {
          if (
            sourceFilter !== "all"
            &&
            technique.source !== sourceFilter
          ) {
            return false;
          }

          if (!searchValue) {
            return true;
          }

          const searchable = [
            technique.techniqueId,
            technique.techniqueName,
            technique.tactic,
            technique.source
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();

          return searchable.includes(
            searchValue
          );
        })
        .sort(
          (first, second) =>
            second.score - first.score
        );
    }, [
      normalizedTechniques,
      search,
      sourceFilter
    ]);


  const topHeatmap =
    useMemo(() => {
      return [...normalizedHeatmap]
        .sort(
          (first, second) =>
            second.score - first.score
        )
        .slice(0, 10);
    }, [normalizedHeatmap]);


  const statistics =
    useMemo(() => {
      const sources = {
        rule: 0,
        stix: 0,
        ml: 0,
        post: 0
      };

      let totalConfidence = 0;
      let confidenceCount = 0;

      normalizedTechniques.forEach(
        technique => {
          if (
            technique.source.startsWith("rule")
          ) {
            sources.rule += 1;
          } else if (
            technique.source === "stix"
          ) {
            sources.stix += 1;
          } else if (
            technique.source === "ml"
          ) {
            sources.ml += 1;
          } else if (
            technique.source === "post_exploit"
          ) {
            sources.post += 1;
          }

          if (
            technique.confidence > 0
          ) {
            totalConfidence +=
              technique.confidence;

            confidenceCount += 1;
          }
        }
      );

      return {
        total:
          data.total_techniques
          ||
          normalizedTechniques.length,

        tactics:
          data.tactics_covered || 0,

        averageConfidence:
          confidenceCount > 0
            ? Math.round(
                totalConfidence
                /
                confidenceCount
              )
            : 0,

        sources
      };
    }, [
      normalizedTechniques,
      data.total_techniques,
      data.tactics_covered
    ]);


  return (
    <div className="mitre-page">

      {/* =====================================
          HERO
      ====================================== */}

      <section className="mitre-hero">

        <div className="mitre-hero-icon">
          <Target size={46} />
        </div>


        <div className="mitre-hero-copy">

          <span className="mitre-eyebrow">
            Adversary Intelligence
          </span>

          <h1>
            MITRE ATT&amp;CK
            <span> Intelligence</span>
          </h1>

          <p>
            Explore adversary techniques mapped by the
            framework using rule-based detection, STIX
            enrichment, machine learning and
            post-exploitation evidence.
          </p>


          <div className="mitre-engine-state">

            <span
              className={
                `mitre-engine-dot ${
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
                ? "Loading MITRE intelligence"
                : error
                  ? "MITRE engine unavailable"
                  : `${statistics.total} mapped techniques available`
              }
            </strong>

          </div>

        </div>


        <div className="mitre-hero-meta">

          <div>
            <span>
              ATT&amp;CK Domain
            </span>

            <strong>
              Enterprise
            </strong>
          </div>


          <div>
            <span>
              Mapping Mode
            </span>

            <strong>
              Hybrid Fusion
            </strong>
          </div>

        </div>

      </section>



      {/* =====================================
          METRICS
      ====================================== */}

      <section className="mitre-summary-grid">

        <MitreMetric
          icon={Target}
          title="Techniques"
          value={statistics.total}
          hint="Mapped ATT&CK techniques"
          type="default"
        />


        <MitreMetric
          icon={Layers3}
          title="Tactics Covered"
          value={statistics.tactics}
          hint="Observed ATT&CK tactics"
          type="tactics"
        />


        <MitreMetric
          icon={TrendingUp}
          title="Avg Confidence"
          value={`${statistics.averageConfidence}%`}
          hint="Detection confidence"
          type="confidence"
        />


        <MitreMetric
          icon={Crosshair}
          title="Rule-Based"
          value={statistics.sources.rule}
          hint="Deterministic mappings"
          type="rule"
        />


        <MitreMetric
          icon={Database}
          title="STIX / AI"
          value={
            statistics.sources.stix
            +
            statistics.sources.ml
          }
          hint="Enriched mappings"
          type="ai"
        />

      </section>



      {/* =====================================
          FILTERS
      ====================================== */}

      <section className="mitre-panel mitre-filter-panel">

        <div className="mitre-panel-header">

          <div className="mitre-panel-heading">

            <div className="mitre-panel-icon">
              <Radar size={21} />
            </div>

            <div>
              <h2>
                Technique Explorer
              </h2>

              <p>
                Search and filter mapped techniques
              </p>
            </div>

          </div>


          <span className="mitre-result-count">
            {filteredTechniques.length}
            {" "}
            results
          </span>

        </div>


        <div className="mitre-filter-controls">

          <div className="mitre-search-box">

            <Search size={18} />

            <input
              value={search}
              onChange={
                event =>
                  setSearch(
                    event.target.value
                  )
              }
              placeholder="Search technique ID, name or tactic..."
            />

          </div>


          <div className="mitre-select-shell">

            <Filter size={17} />

            <select
              value={sourceFilter}
              onChange={
                event =>
                  setSourceFilter(
                    event.target.value
                  )
              }
            >

              {SOURCE_OPTIONS.map(
                source => (
                  <option
                    key={source}
                    value={source}
                  >
                    {sourceLabel(source)}
                  </option>
                )
              )}

            </select>

            <ChevronDown size={16} />

          </div>

        </div>

      </section>



      {/* =====================================
          MAIN GRID
      ====================================== */}

      <section className="mitre-main-grid">

        {/* HEATMAP */}

        <article className="mitre-panel mitre-heatmap-panel">

          <div className="mitre-panel-header">

            <div className="mitre-panel-heading">

              <div className="mitre-panel-icon">
                <Flame size={21} />
              </div>

              <div>
                <h2>
                  Technique Heatmap
                </h2>

                <p>
                  Highest-scored ATT&amp;CK techniques
                </p>
              </div>

            </div>


            <span className="mitre-panel-badge">
              Top 10
            </span>

          </div>


          {loading ? (

            <MitreLoading />

          ) : topHeatmap.length === 0 ? (

            <div className="mitre-empty-state">

              <ShieldCheck size={38} />

              <h3>
                No Heatmap Data
              </h3>

              <p>
                Run an assessment to generate
                MITRE heatmap information.
              </p>

            </div>

          ) : (

            <div className="mitre-heatmap-list">

              {topHeatmap.map(
                (technique, index) => (

                  <div
                    className="mitre-heatmap-row"
                    key={technique.id}
                  >

                    <div className="mitre-heatmap-rank">
                      {String(
                        index + 1
                      ).padStart(2, "0")}
                    </div>


                    <div className="mitre-heatmap-info">

                      <div>

                        <strong>
                          {technique.techniqueId}
                        </strong>

                        <span>
                          {sourceLabel(
                            technique.source
                          )}
                        </span>

                      </div>


                      <div className="mitre-heatmap-track">

                        <i
                          style={{
                            width:
                              `${Math.min(
                                100,
                                technique.score
                              )}%`
                          }}
                        />

                      </div>

                    </div>


                    <div className="mitre-heatmap-score">

                      <strong>
                        {Math.round(
                          technique.score
                        )}
                      </strong>

                      <span>
                        score
                      </span>

                    </div>

                  </div>

                )
              )}

            </div>

          )}

        </article>



        {/* SOURCE DISTRIBUTION */}

        <article className="mitre-panel mitre-source-panel">

          <div className="mitre-panel-header">

            <div className="mitre-panel-heading">

              <div className="mitre-panel-icon">
                <BrainCircuit size={21} />
              </div>

              <div>
                <h2>
                  Mapping Sources
                </h2>

                <p>
                  Detection and enrichment distribution
                </p>
              </div>

            </div>

          </div>


          <div className="mitre-source-list">

            <SourceRow
              label="Rule-Based"
              value={statistics.sources.rule}
              total={statistics.total}
              type="rule"
            />


            <SourceRow
              label="STIX"
              value={statistics.sources.stix}
              total={statistics.total}
              type="stix"
            />


            <SourceRow
              label="Machine Learning"
              value={statistics.sources.ml}
              total={statistics.total}
              type="ml"
            />


            <SourceRow
              label="Post-Exploitation"
              value={statistics.sources.post}
              total={statistics.total}
              type="post"
            />

          </div>


          <div className="mitre-source-note">

            <Activity size={18} />

            <div>

              <strong>
                Confidence Fusion Active
              </strong>

              <p>
                Multiple mapping sources are combined
                while deterministic findings remain
                authoritative.
              </p>

            </div>

          </div>

        </article>

      </section>



      {/* =====================================
          TABLE
      ====================================== */}

      <section className="mitre-panel mitre-table-panel">

        <div className="mitre-panel-header">

          <div className="mitre-panel-heading">

            <div className="mitre-panel-icon">
              <Target size={21} />
            </div>

            <div>
              <h2>
                Detected Techniques
              </h2>

              <p>
                Techniques confirmed by the framework
              </p>
            </div>

          </div>


          <span className="mitre-panel-badge">
            {filteredTechniques.length}
            {" "}
            techniques
          </span>

        </div>


        {error ? (

          <div className="mitre-error-state">

            <AlertTriangle size={38} />

            <h3>
              Unable to Load MITRE Data
            </h3>

            <p>
              {error}
            </p>

            <button
              type="button"
              onClick={loadMitre}
            >
              Retry Connection
            </button>

          </div>

        ) : loading ? (

          <MitreLoading />

        ) : filteredTechniques.length === 0 ? (

          <div className="mitre-empty-state">

            <ShieldCheck size={38} />

            <h3>
              No Matching Techniques
            </h3>

            <p>
              Change the current filters or run
              another assessment.
            </p>

          </div>

        ) : (

          <div className="mitre-table-wrap">

            <table className="mitre-security-table">

              <thead>
                <tr>
                  <th>
                    Technique ID
                  </th>

                  <th>
                    Technique
                  </th>

                  <th>
                    Tactic
                  </th>

                  <th>
                    Source
                  </th>

                  <th>
                    Score
                  </th>

                  <th>
                    Confidence
                  </th>
                </tr>
              </thead>


              <tbody>

                {filteredTechniques.map(
                  technique => (

                    <tr key={technique.id}>

                      <td>
                        <span className="mitre-id">
                          {technique.techniqueId}
                        </span>
                      </td>


                      <td>

                        <div className="mitre-technique-cell">

                          <strong>
                            {technique.techniqueName}
                          </strong>

                          <span>
                            Enterprise ATT&amp;CK technique
                          </span>

                        </div>

                      </td>


                      <td>

                        <span className="mitre-tactic-badge">
                          {formatTactic(
                            technique.tactic
                          )}
                        </span>

                      </td>


                      <td>

                        <span
                          className={
                            `mitre-source-badge ${
                              sourceClass(
                                technique.source
                              )
                            }`
                          }
                        >
                          {sourceLabel(
                            technique.source
                          )}
                        </span>

                      </td>


                      <td>

                        <span
                          className={
                            `mitre-score-badge ${
                              scoreClass(
                                technique.score
                              )
                            }`
                          }
                        >
                          {Math.round(
                            technique.score
                          )}
                        </span>

                      </td>


                      <td>

                        <div className="mitre-confidence-cell">

                          <span>
                            {technique.confidence}%
                          </span>

                          <div>
                            <i
                              style={{
                                width:
                                  `${technique.confidence}%`
                              }}
                            />
                          </div>

                        </div>

                      </td>

                    </tr>

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



function MitreMetric({
  icon: Icon,
  title,
  value,
  hint,
  type
}) {
  return (
    <article
      className={
        `mitre-metric-card ${type}`
      }
    >

      <div className="mitre-metric-top">

        <div className="mitre-metric-icon">
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



function SourceRow({
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
        `mitre-source-row ${type}`
      }
    >

      <div className="mitre-source-row-label">

        <span />

        <strong>
          {label}
        </strong>

      </div>


      <div className="mitre-source-track">

        <i
          style={{
            width: `${percentage}%`
          }}
        />

      </div>


      <div className="mitre-source-value">

        <strong>
          {value}
        </strong>

        <span>
          {percentage}%
        </span>

      </div>

    </div>
  );
}



function MitreLoading() {
  return (
    <div className="mitre-loading-state">

      <div className="mitre-loading-spinner" />

      <h3>
        Loading MITRE Intelligence
      </h3>

      <p>
        Retrieving mapped techniques and
        heatmap information.
      </p>

    </div>
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



function normalizeScore(value) {
  const parsed =
    Number(value);

  if (Number.isNaN(parsed)) {
    return 0;
  }

  if (
    parsed <= 1
    &&
    parsed > 0
  ) {
    return Math.round(
      parsed * 100
    );
  }

  return Math.min(
    100,
    Math.max(
      0,
      parsed
    )
  );
}



function extractCommentField(
  comment,
  field
) {
  if (!comment) {
    return "";
  }

  const pattern =
    new RegExp(
      `${field}:\\s*([^|]+)`,
      "i"
    );

  const match =
    String(comment).match(pattern);

  return match
    ? match[1].trim()
    : "";
}



function normalizeSource(value) {
  const source =
    String(
      value || "unknown"
    )
      .toLowerCase()
      .trim();

  if (
    source.includes("post")
  ) {
    return "post_exploit";
  }

  if (
    source.includes("stix")
  ) {
    return "stix";
  }

  if (
    source.includes("ml")
    ||
    source.includes("classifier")
  ) {
    return "ml";
  }

  if (
    source.includes("rule_exact")
  ) {
    return "rule_exact";
  }

  if (
    source.includes("rule_service")
  ) {
    return "rule_service";
  }

  if (
    source.includes("rule")
  ) {
    return "rule_exact";
  }

  return source;
}



function sourceLabel(source) {
  const labels = {
    all: "All Sources",
    rule_exact: "Rule Exact",
    rule_service: "Rule Service",
    stix: "STIX",
    ml: "Machine Learning",
    post_exploit: "Post-Exploitation",
    unknown: "Unknown"
  };

  return labels[source] || source;
}



function sourceClass(source) {
  if (
    source.startsWith("rule")
  ) {
    return "rule";
  }

  if (source === "stix") {
    return "stix";
  }

  if (source === "ml") {
    return "ml";
  }

  if (source === "post_exploit") {
    return "post";
  }

  return "unknown";
}



function scoreClass(score) {
  if (score >= 90) {
    return "critical";
  }

  if (score >= 70) {
    return "high";
  }

  if (score >= 50) {
    return "medium";
  }

  return "low";
}



function formatTactic(value) {
  return String(
    value || "Unknown"
  )
    .replaceAll("-", " ")
    .replaceAll("_", " ");
}


export default Mitre;
