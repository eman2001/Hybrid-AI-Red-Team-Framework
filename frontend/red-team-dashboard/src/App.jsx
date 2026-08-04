import { useEffect, useState } from "react";
import AppRoutes from "./routes/AppRoutes";

function App() {
  const [dark, setDark] = useState(
    localStorage.getItem("theme") !== "light"
  );

  useEffect(() => {
    document.body.classList.toggle("dark", dark);

    localStorage.setItem(
      "theme",
      dark ? "dark" : "light"
    );
  }, [dark]);

  return (
    <AppRoutes
      dark={dark}
      setDark={setDark}
    />
  );
}

export default App;
