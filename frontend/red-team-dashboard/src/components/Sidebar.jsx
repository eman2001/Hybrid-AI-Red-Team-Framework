import {
  Activity,
  FileText,
  GitBranch,
  LayoutDashboard,
  Network,
  Radar,
  Settings,
  ShieldAlert,
  Target,
  X
} from "lucide-react";

import {
  NavLink
} from "react-router-dom";


const navigationItems = [
  {
    label: "Dashboard",
    path: "/",
    icon: LayoutDashboard
  },
  {
    label: "Start Scan",
    path: "/scan",
    icon: Radar
  },
  {
    label: "Vulnerabilities",
    path: "/vulnerabilities",
    icon: ShieldAlert
  },
  {
    label: "MITRE ATT&CK",
    path: "/mitre",
    icon: Target
  },
  {
    label: "Attack Chain",
    path: "/attack-chain",
    icon: GitBranch
  },
  {
    label: "Reports",
    path: "/reports",
    icon: FileText
  }
];


function Sidebar({
  open,
  close
}) {
  return (
    <>

      <aside
        className={
          `red-sidebar ${open ? "red-sidebar-open" : ""}`
        }
      >

        {/* HEADER */}
        <div className="red-sidebar-header">

          <div className="red-sidebar-brand">

            <div className="red-sidebar-logo">
              <ShieldAlert size={30} />
            </div>

            <div className="red-sidebar-brand-text">

              <strong>
                HYBRID AI
              </strong>

              <span>
                RED TEAM
              </span>

            </div>

          </div>


          <button
            type="button"
            className="red-sidebar-close"
            onClick={close}
            aria-label="Close sidebar"
          >
            <X size={20} />
          </button>

        </div>


        {/* NAVIGATION */}
        <nav className="red-sidebar-nav">

          <span className="red-sidebar-section-title">
            OPERATIONS
          </span>


          {navigationItems.map(
            ({
              label,
              path,
              icon: Icon
            }) => (

              <NavLink
                key={path}
                to={path}
                end={path === "/"}
                onClick={close}
                className={
                  ({ isActive }) =>
                    isActive
                      ? "red-sidebar-link active"
                      : "red-sidebar-link"
                }
              >

                <span className="red-sidebar-link-icon">
                  <Icon size={20} />
                </span>

                <span className="red-sidebar-link-label">
                  {label}
                </span>

              </NavLink>

            )
          )}

        </nav>


        {/* ENGINE STATUS */}
        <div className="red-sidebar-status">

          <div className="red-sidebar-status-header">

            <div>

              <span className="red-sidebar-status-label">
                SYSTEM STATUS
              </span>

              <strong>
                Engine Online
              </strong>

            </div>


            <span className="red-sidebar-status-dot" />

          </div>


          <div className="red-sidebar-wave">

            <Activity size={16} />

            <span />
            <span />
            <span />
            <span />
            <span />

          </div>


          <div className="red-sidebar-status-meta">

            <span>
              <Network size={14} />
              API Connected
            </span>

            <small>
              All systems operational
            </small>

          </div>

        </div>


        {/* FOOTER */}
        <div className="red-sidebar-footer">

          <div className="red-sidebar-version">

            <Settings size={15} />

            <div>
              <strong>
                Framework v2.1
              </strong>

              <span>
                Hybrid AI Security Platform
              </span>
            </div>

          </div>

        </div>

      </aside>


      <button
        type="button"
        className={
          `red-sidebar-overlay ${
            open
              ? "red-sidebar-overlay-show"
              : ""
          }`
        }
        onClick={close}
        aria-label="Close navigation overlay"
      />

    </>
  );
}


export default Sidebar;
