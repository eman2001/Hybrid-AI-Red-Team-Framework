import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

const COLORS = [
  "#dc2626",
  "#f97316",
  "#eab308",
  "#22c55e",
];

function SeverityChart({ vulnerabilities }) {

  const data = [
    {
      name: "Critical",
      value: vulnerabilities.filter(v => v.severity === "Critical").length,
    },
    {
      name: "High",
      value: vulnerabilities.filter(v => v.severity === "High").length,
    },
    {
      name: "Medium",
      value: vulnerabilities.filter(v => v.severity === "Medium").length,
    },
    {
      name: "Low",
      value: vulnerabilities.filter(v => v.severity === "Low").length,
    },
  ];

  const total = vulnerabilities.length;

  return (

    <div className="panel">

      <h2>🛡 Vulnerability Distribution</h2>

      <ResponsiveContainer width="100%" height={320}>

        <PieChart>

          <Pie
            data={data}
            dataKey="value"
            innerRadius={75}
            outerRadius={110}
            paddingAngle={4}
            stroke="none"
          >

            {data.map((entry, index) => (

              <Cell
                key={index}
                fill={COLORS[index]}
              />

            ))}

          </Pie>

          <Tooltip />

          <text
            x="50%"
            y="47%"
            textAnchor="middle"
            className="chart-total-number"
          >
            {total}
          </text>

          <text
            x="50%"
            y="56%"
            textAnchor="middle"
            className="chart-total-text"
          >
            Vulnerabilities
          </text>

        </PieChart>

      </ResponsiveContainer>

    </div>

  );

}

export default SeverityChart;
