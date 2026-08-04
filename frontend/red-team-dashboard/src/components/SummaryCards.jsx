import {
  AlertTriangle,
  ShieldAlert,
  Target
} from "lucide-react";

import StatCard from "./StatCard";


function SummaryCards({
  vulnerabilities = [],
  techniques = []
}) {
  const severityCount = (
    severity
  ) => vulnerabilities.filter(
    (item) =>
      String(
        item.severity || ""
      ).toLowerCase() === severity
  ).length;


  const critical =
    severityCount("critical");

  const high =
    severityCount("high");


  return (
    <div className="summary-grid">

      <StatCard
        icon={
          <ShieldAlert size={27} />
        }
        title="Total Vulnerabilities"
        value={vulnerabilities.length}
        hint="Detected findings"
      />


      <StatCard
        icon={
          <AlertTriangle size={27} />
        }
        title="Critical"
        value={critical}
        hint="Immediate remediation"
        variant="critical"
      />


      <StatCard
        icon={
          <AlertTriangle size={27} />
        }
        title="High"
        value={high}
        hint="High-priority findings"
        variant="high"
      />


      <StatCard
        icon={
          <Target size={27} />
        }
        title="MITRE Techniques"
        value={techniques.length}
        hint="Mapped techniques"
      />

    </div>
  );
}


export default SummaryCards;
