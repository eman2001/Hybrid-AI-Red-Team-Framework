import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
/* Temporary legacy CSS — سنحذفه بعد نقل جميع الأقسام */
import "./index.css";
import App from "./App.jsx";



/* Design system */
import "./styles/variables.css";
import "./styles/globals.css";
import "./styles/layout.css";

/* Layout components */
import "./styles/Navbar.css";
import "./styles/Sidebar.css";

/* Pages */
import "./styles/Dashboard.css";
import "./styles/Scan.css";
import "./styles/Vulnerabilities.css";
import "./styles/Mitre.css";
import "./styles/AttackChain.css";
import "./styles/Reports.css";

/* Shared components */
import "./styles/components.css";
import "./styles/responsive.css";



createRoot(
  document.getElementById("root")
).render(
  <StrictMode>
    <App />
  </StrictMode>
);
