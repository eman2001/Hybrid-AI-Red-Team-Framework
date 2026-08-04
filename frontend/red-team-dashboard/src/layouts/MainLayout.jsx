import { Outlet } from "react-router-dom";
import { useState } from "react";

import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";


function MainLayout({
  dark,
  setDark
}) {
  const [open, setOpen] = useState(true);

  function toggleSidebar() {
    setOpen((current) => !current);
  }

  function closeSidebar() {
    setOpen(false);
  }

  return (
    <div
      className={
        open
          ? "app-layout sidebar-visible"
          : "app-layout sidebar-hidden"
      }
    >

      <Navbar
        toggleSidebar={toggleSidebar}
        darkMode={dark}
        toggleDarkMode={() =>
          setDark((current) => !current)
        }
      />

      <Sidebar
        open={open}
        close={closeSidebar}
      />

      <main className="content">
        <Outlet />
      </main>

    </div>
  );
}


export default MainLayout;
