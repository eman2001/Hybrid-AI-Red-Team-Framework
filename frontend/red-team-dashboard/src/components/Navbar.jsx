import {
  Bell,
  Menu,
  Moon,
  ShieldAlert,
  Sun
} from "lucide-react";



function Navbar({
  toggleSidebar,
  darkMode,
  toggleDarkMode
}) {
  return (
    <header className="top-navbar">

      {/* LEFT SIDE */}
      <div className="navbar-left">

     <button
  type="button"
  className="navbar-icon-btn navbar-menu-btn"
  onClick={toggleSidebar}
  aria-label="Toggle navigation menu"
>
  <Menu size={22} />
</button>


        <div className="navbar-brand">

          <div className="navbar-brand-icon">
            <ShieldAlert size={27} />
          </div>


          <div className="navbar-brand-copy">

            <h2>
              Hybrid
              <span> AI Red Team</span>
            </h2>

            <p>
              Offensive Security Operations Center
            </p>

          </div>

        </div>

      </div>


      {/* RIGHT SIDE */}
      <div className="navbar-actions">

        <div className="navbar-engine-status">

          <span className="engine-status-dot" />

          <div>
            <strong>System Online</strong>
            <small>Engine connected</small>
          </div>

        </div>


        <button
          type="button"
          className="navbar-icon-btn"
          onClick={toggleDarkMode}
          aria-label={
            darkMode
              ? "Switch to light mode"
              : "Switch to dark mode"
          }
          title={
            darkMode
              ? "Light mode"
              : "Dark mode"
          }
        >
          {darkMode ? (
            <Sun size={20} />
          ) : (
            <Moon size={20} />
          )}
        </button>


        <button
          type="button"
          className="navbar-icon-btn notification-button"
          aria-label="Notifications"
        >
          <Bell size={20} />

          <span className="notification-badge">
            3
          </span>
        </button>

      </div>

    </header>
  );
}


export default Navbar;
