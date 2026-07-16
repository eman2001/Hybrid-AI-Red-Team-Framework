import {
    BrowserRouter,
    Routes,
    Route
} from "react-router-dom";


import MainLayout from "../layouts/MainLayout";

import Dashboard from "../pages/Dashboard";
import Scan from "../pages/Scan";
import Vulnerabilities from "../pages/Vulnerabilities";
import AttackChain from "../pages/AttackChain";
import Mitre from "../pages/Mitre";
import Reports from "../pages/Reports";



function AppRoutes(){


return (


<BrowserRouter>


<Routes>


<Route element={<MainLayout/>}>


<Route

path="/"

element={<Dashboard/>}

/>



<Route

path="/scan"

element={<Scan/>}

/>



<Route

path="/vulnerabilities"

element={<Vulnerabilities/>}

/>



<Route

path="/attack-chain"

element={<AttackChain/>}

/>



<Route

path="/mitre"

element={<Mitre/>}

/>



<Route

path="/reports"

element={<Reports/>}

/>



</Route>


</Routes>


</BrowserRouter>


)


}


export default AppRoutes;
