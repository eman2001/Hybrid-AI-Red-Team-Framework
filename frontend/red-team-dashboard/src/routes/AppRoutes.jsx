import {
BrowserRouter,
Routes,
Route
} from "react-router-dom";


import MainLayout from "../layouts/MainLayout";
import Dashboard from "../pages/Dashboard";
import Scan from "../pages/Scan";

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
</Route>

</Routes>

</BrowserRouter>

)

}


export default AppRoutes;
