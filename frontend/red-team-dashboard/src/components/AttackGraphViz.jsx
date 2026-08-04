import { useMemo } from "react";

// Column order — attacker on the left, drilling down to services on the right.
// Any unrecognized node "type" falls into the last column automatically.
const COLUMN_ORDER = ["attacker", "target", "host", "service"];

const NODE_STYLE = {
  attacker: { r: 22, fill: "var(--accent-crimson)", label: "ATTACKER" },
  target:   { r: 18, fill: "var(--accent-indigo)",  label: null },
  host:     { r: 18, fill: "var(--accent-indigo)",  label: null },
  service:  { r: 13, fill: "var(--primary)",    label: null },
};

function nodeLabel(node) {
  if (node.type === "attacker") return "ATTACKER";
  if (node.service && node.port) return `${node.host}:${node.port}`;
  if (node.port) return `:${node.port}`;
  return node.host || node.id;
}

function buildLayout(nodes, width, height) {
  const columns = {};
  COLUMN_ORDER.forEach((t) => (columns[t] = []));

  nodes.forEach((n) => {
    const col = COLUMN_ORDER.includes(n.type) ? n.type : "service";
    columns[col].push(n);
  });

  const activeCols = COLUMN_ORDER.filter((c) => columns[c].length > 0);
  const colGap = width / (activeCols.length + 1);

  const positions = {};
  activeCols.forEach((col, colIdx) => {
    const items = columns[col];
    const rowGap = height / (items.length + 1);
    items.forEach((n, rowIdx) => {
      positions[n.id] = {
        x: colGap * (colIdx + 1),
        y: rowGap * (rowIdx + 1),
        node: n,
      };
    });
  });

  return positions;
}

export default function AttackGraphViz({ nodes = [], edges = [], criticalPath = [] }) {
  const width = 760;
  const height = Math.max(260, Math.max(...COLUMN_ORDER.map((t) =>
    nodes.filter((n) => (COLUMN_ORDER.includes(n.type) ? n.type : "service") === t).length
  ), 1) * 70);

  const positions = useMemo(() => buildLayout(nodes, width, height), [nodes, width, height]);

  const criticalEdgeSet = useMemo(() => {
    const set = new Set();
    for (let i = 0; i < criticalPath.length - 1; i++) {
      set.add(`${criticalPath[i]}->${criticalPath[i + 1]}`);
    }
    return set;
  }, [criticalPath]);

  if (!nodes.length) {
    return (
      <div className="graph-empty">
        <p>No attack graph available yet.</p>
        <span>Run a full scan to build the attack path.</span>
      </div>
    );
  }

  return (
    <div className="graph-canvas-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} className="graph-canvas">
        {/* Edges drawn first, so nodes sit on top */}
        {edges.map((e, i) => {
          const from = e.from ?? e.source ?? e.from_node;
          const to = e.to ?? e.target ?? e.to_node;
          const a = positions[from];
          const b = positions[to];
          if (!a || !b) return null;

          const isCritical = criticalEdgeSet.has(`${from}->${to}`);

          return (
            <g key={i}>
              <line
                x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                className={isCritical ? "graph-edge critical" : "graph-edge"}
              />
              {e.technique && (
                <text
                  x={(a.x + b.x) / 2}
                  y={(a.y + b.y) / 2 - 6}
                  className="graph-edge-label"
                  textAnchor="middle"
                >
                  {e.technique}
                </text>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {Object.values(positions).map(({ x, y, node }) => {
          const style = NODE_STYLE[node.type] || NODE_STYLE.service;
          const isCritical = criticalPath.includes(node.id);

          return (
            <g key={node.id} className="graph-node">
              <circle
                cx={x} cy={y} r={style.r}
                fill={style.fill}
                className={isCritical ? "graph-node-circle critical" : "graph-node-circle"}
              />
              {node.type !== "attacker" && node.risk > 0 && (
                <text x={x} y={y + 4} textAnchor="middle" className="graph-node-risk">
                  {Math.round(node.risk)}
                </text>
              )}
              {node.type === "attacker" && (
                <text x={x} y={y + 4} textAnchor="middle" className="graph-node-icon">⚔</text>
              )}
              <text x={x} y={y + style.r + 14} textAnchor="middle" className="graph-node-label">
                {nodeLabel(node)}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="graph-legend">
        <span><i className="dot attacker" /> Attacker</span>
        <span><i className="dot host" /> Host</span>
        <span><i className="dot service" /> Service</span>
        <span><i className="dot critical-line" /> Critical path</span>
      </div>
    </div>
  );
}
