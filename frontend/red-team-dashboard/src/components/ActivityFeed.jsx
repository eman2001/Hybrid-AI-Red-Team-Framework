import {
  Search,
  Shield,
  Target,
  FileText,
  Activity,
  AlertTriangle
} from "lucide-react";

function ActivityFeed({ activities = [] }) {
  const icons = {
    search: <Search size={20} />,
    scan: <Search size={20} />,
    shield: <Shield size={20} />,
    target: <Target size={20} />,
    file: <FileText size={20} />,
    activity: <Activity size={20} />,
    alert: <AlertTriangle size={20} />
  };

  if (activities.length === 0) {
    return (
      <div className="activity-empty">
        <Activity size={22} />
        <p>No recent activity</p>
        <span>Run a scan to start streaming engine events here.</span>
      </div>
    );
  }

  return (
    <div className="activity-feed">
      {activities.map((item, index) => (
        <div className="activity-item" key={index}>
          <div className={`activity-icon ${item.type || "info"}`}>
            {icons[item.icon] || <Activity size={20} />}
          </div>
          <div className="activity-content">
            <h4>{item.title}</h4>
            <p>{item.description}</p>
            <span>{item.time}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

export default ActivityFeed;
