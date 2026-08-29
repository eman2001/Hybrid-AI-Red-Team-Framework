import { useMemo } from "react";


/* =========================================================
   HELPERS
========================================================= */

function getNodeType(node) {
  const type = String(node?.type || "").toLowerCase();

  if (type === "attacker") return "attacker";

  if (
    type === "host" ||
    type === "target"
  ) {
    return "host";
  }

  return "service";
}


function getNodeLabel(node) {
  const type = getNodeType(node);

  if (type === "attacker") {
    return "ATTACKER";
  }

  if (type === "host") {
    return (
      node.host ||
      node.label ||
      node.name ||
      node.id ||
      "Target Host"
    );
  }

  if (node.port) {
    return `${node.port}`;
  }

  return (
    node.service ||
    node.label ||
    node.name ||
    node.id ||
    "Service"
  );
}


function getServiceName(node) {
  return (
    node.service ||
    node.name ||
    node.label ||
    "Service"
  );
}


function getRisk(node) {
  const value = Number(
    node?.risk ??
    node?.risk_score ??
    node?.score ??
    0
  );

  if (Number.isNaN(value)) {
    return 0;
  }

  return Math.round(value);
}


/* =========================================================
   LAYOUT
========================================================= */

function buildLayout(nodes, width) {
  const attackerNodes = [];
  const hostNodes = [];
  const serviceNodes = [];

  nodes.forEach((node) => {
    const type = getNodeType(node);

    if (type === "attacker") {
      attackerNodes.push(node);
    } else if (type === "host") {
      hostNodes.push(node);
    } else {
      serviceNodes.push(node);
    }
  });


  const positions = {};

  const centerX = width / 2;

  const attackerY = 80;
  const hostY = 220;

  const serviceStartY = 370;

  const serviceColumns = 4;
  const serviceGapX = 190;
  const serviceGapY = 115;


  /* -------------------------
     Attacker
  ------------------------- */

  attackerNodes.forEach((node, index) => {
    const offset =
      (index - (attackerNodes.length - 1) / 2) * 150;

    positions[node.id] = {
      x: centerX + offset,
      y: attackerY,
      node
    };
  });


  /* -------------------------
     Hosts
  ------------------------- */

  hostNodes.forEach((node, index) => {
    const gap =
      Math.min(
        280,
        width / Math.max(hostNodes.length + 1, 2)
      );

    const totalWidth =
      (hostNodes.length - 1) * gap;

    positions[node.id] = {
      x:
        centerX -
        totalWidth / 2 +
        index * gap,

      y: hostY,
      node
    };
  });


  /* -------------------------
     Services
  ------------------------- */

  serviceNodes.forEach((node, index) => {
    const row =
      Math.floor(index / serviceColumns);

    const column =
      index % serviceColumns;

    const itemsInRow =
      Math.min(
        serviceColumns,
        serviceNodes.length -
        row * serviceColumns
      );

    const rowWidth =
      (itemsInRow - 1) * serviceGapX;

    positions[node.id] = {
      x:
        centerX -
        rowWidth / 2 +
        column * serviceGapX,

      y:
        serviceStartY +
        row * serviceGapY,

      node
    };
  });


  const serviceRows =
    Math.max(
      1,
      Math.ceil(
        serviceNodes.length /
        serviceColumns
      )
    );

  const height =
    serviceStartY +
    serviceRows * serviceGapY +
    80;


  return {
    positions,
    height
  };
}


/* =========================================================
   EDGE PATH
========================================================= */

function buildEdgePath(from, to) {
  const middleY =
    from.y +
    (to.y - from.y) * 0.5;

  return `
    M ${from.x} ${from.y}
    C ${from.x} ${middleY},
      ${to.x} ${middleY},
      ${to.x} ${to.y}
  `;
}


/* =========================================================
   MAIN COMPONENT
========================================================= */

export default function AttackGraphViz({
  nodes = [],
  edges = [],
  criticalPath = []
}) {

  const width = 980;


  const {
    positions,
    height
  } = useMemo(
    () =>
      buildLayout(
        nodes,
        width
      ),
    [nodes]
  );


  /* =====================================================
     CRITICAL PATH
  ===================================================== */

  const criticalNodeSet =
    useMemo(
      () =>
        new Set(
          criticalPath || []
        ),
      [criticalPath]
    );


  const criticalEdgeSet =
    useMemo(() => {

      const set =
        new Set();

      for (
        let i = 0;
        i < criticalPath.length - 1;
        i += 1
      ) {
        set.add(
          `${criticalPath[i]}->${criticalPath[i + 1]}`
        );
      }

      return set;

    }, [criticalPath]);


  /* =====================================================
     EMPTY STATE
  ===================================================== */

  if (!nodes.length) {
    return (
      <div className="graph-empty">

        <p>
          No attack graph available yet.
        </p>

        <span>
          Run a full scan to build the attack path.
        </span>

      </div>
    );
  }


  return (
    <div className="graph-canvas-wrap">

      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="graph-canvas"
        preserveAspectRatio="xMidYMin meet"
      >

        {/* =========================================
            ARROW DEFINITIONS
        ========================================== */}

        <defs>

          <marker
            id="graph-arrow"
            markerWidth="10"
            markerHeight="10"
            refX="8"
            refY="3"
            orient="auto"
            markerUnits="strokeWidth"
          >
            <path
              d="M0,0 L0,6 L9,3 z"
              className="graph-arrow"
            />
          </marker>


          <marker
            id="graph-arrow-critical"
            markerWidth="10"
            markerHeight="10"
            refX="8"
            refY="3"
            orient="auto"
            markerUnits="strokeWidth"
          >
            <path
              d="M0,0 L0,6 L9,3 z"
              className="graph-arrow-critical"
            />
          </marker>

        </defs>



        {/* =========================================
            EDGES
        ========================================== */}

        {edges.map(
          (edge, index) => {

            const fromId =
              edge.from ??
              edge.source ??
              edge.from_node;

            const toId =
              edge.to ??
              edge.target ??
              edge.to_node;


            const from =
              positions[fromId];

            const to =
              positions[toId];


            if (!from || !to) {
              return null;
            }


            const isCritical =
              criticalEdgeSet.has(
                `${fromId}->${toId}`
              );


            const technique =
              edge.technique ??
              edge.technique_id ??
              edge.label ??
              "";


            return (
              <g
                key={
                  `${fromId}-${toId}-${index}`
                }
              >

                <path
                  d={
                    buildEdgePath(
                      from,
                      to
                    )
                  }
                  className={
                    isCritical
                      ? "graph-edge critical"
                      : "graph-edge"
                  }
                  markerEnd={
                    isCritical
                      ? "url(#graph-arrow-critical)"
                      : "url(#graph-arrow)"
                  }
                />


                {technique && (

                  <g
                    className="graph-technique-badge"
                    transform={
                      `translate(
                        ${(from.x + to.x) / 2},
                        ${(from.y + to.y) / 2}
                      )`
                    }
                  >

                    <rect
                      x="-43"
                      y="-11"
                      width="86"
                      height="22"
                      rx="11"
                    />

                    <text
                      textAnchor="middle"
                      dominantBaseline="middle"
                    >
                      {technique}
                    </text>

                  </g>

                )}

              </g>
            );
          }
        )}



        {/* =========================================
            NODES
        ========================================== */}

        {Object.values(
          positions
        ).map(
          ({
            x,
            y,
            node
          }) => {

            const type =
              getNodeType(node);

            const risk =
              getRisk(node);

            const isCritical =
              criticalNodeSet.has(
                node.id
              );


            /* -------------------------
               ATTACKER
            ------------------------- */

            if (
              type === "attacker"
            ) {
              return (
                <g
                  key={node.id}
                  className="graph-node"
                >

                  {isCritical && (
                    <circle
                      cx={x}
                      cy={y}
                      r="40"
                      className="graph-critical-glow"
                    />
                  )}


                  <circle
                    cx={x}
                    cy={y}
                    r="29"
                    className={
                      `graph-node-circle node-attacker ${
                        isCritical
                          ? "critical"
                          : ""
                      }`
                    }
                  />


                  <text
                    x={x}
                    y={y + 7}
                    textAnchor="middle"
                    className="graph-node-icon"
                  >
                    ⚔
                  </text>


                  <text
                    x={x}
                    y={y + 51}
                    textAnchor="middle"
                    className="graph-node-label"
                  >
                    ATTACKER
                  </text>

                </g>
              );
            }


            /* -------------------------
               HOST
            ------------------------- */

            if (
              type === "host"
            ) {
              return (
                <g
                  key={node.id}
                  className="graph-node"
                >

                  {isCritical && (
                    <circle
                      cx={x}
                      cy={y}
                      r="43"
                      className="graph-critical-glow"
                    />
                  )}


                  <circle
                    cx={x}
                    cy={y}
                    r="31"
                    className={
                      `graph-node-circle node-host ${
                        isCritical
                          ? "critical"
                          : ""
                      }`
                    }
                  />


                  <circle
                    cx={x}
                    cy={y}
                    r="8"
                    className="graph-host-inner"
                  />


                  {risk > 0 && (

                    <g
                      className="graph-risk-badge"
                      transform={
                        `translate(
                          ${x + 27},
                          ${y - 27}
                        )`
                      }
                    >

                      <circle
                        r="13"
                      />

                      <text
                        textAnchor="middle"
                        dominantBaseline="middle"
                      >
                        {risk}
                      </text>

                    </g>

                  )}


                  <text
                    x={x}
                    y={y + 53}
                    textAnchor="middle"
                    className="graph-node-label"
                  >
                    {getNodeLabel(node)}
                  </text>


                  <text
                    x={x}
                    y={y + 69}
                    textAnchor="middle"
                    className="graph-node-subtitle"
                  >
                    Target Host
                  </text>

                </g>
              );
            }


            /* -------------------------
               SERVICE
            ------------------------- */

            return (
              <g
                key={node.id}
                className="graph-node"
              >

                {isCritical && (

                  <rect
                    x={x - 66}
                    y={y - 31}
                    width="132"
                    height="62"
                    rx="16"
                    className="graph-critical-glow"
                  />

                )}


                <rect
                  x={x - 58}
                  y={y - 25}
                  width="116"
                  height="50"
                  rx="12"
                  className={
                    `graph-service-card ${
                      isCritical
                        ? "critical"
                        : ""
                    }`
                  }
                />


                <circle
                  cx={x - 40}
                  cy={y}
                  r="4"
                  className="graph-service-dot"
                />


                <text
                  x={x - 27}
                  y={y - 2}
                  className="graph-service-port"
                >
                  {getNodeLabel(node)}
                </text>


                <text
                  x={x - 27}
                  y={y + 13}
                  className="graph-service-name"
                >
                  {getServiceName(node)}
                </text>


                {risk > 0 && (

                  <g
                    className="graph-risk-badge"
                    transform={
                      `translate(
                        ${x + 54},
                        ${y - 22}
                      )`
                    }
                  >

                    <circle
                      r="12"
                    />

                    <text
                      textAnchor="middle"
                      dominantBaseline="middle"
                    >
                      {risk}
                    </text>

                  </g>

                )}

              </g>
            );
          }
        )}

      </svg>



      {/* =========================================
          LEGEND
      ========================================== */}

      <div className="graph-legend">

        <span>
          <i className="dot attacker" />
          Attacker
        </span>

        <span>
          <i className="dot host" />
          Host
        </span>

        <span>
          <i className="dot service" />
          Service
        </span>

        <span>
          <i className="dot critical-line" />
          Critical path
        </span>

      </div>

    </div>
  );
}
