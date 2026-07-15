import { Link } from "react-router-dom";


function Sidebar(){

return (

<aside className="sidebar">

    <div className="logo">

        <h2>
            ⚔ Red Team AI
        </h2>

        <p>
            Hybrid Security Platform
        </p>

    </div>


    <nav>


        <Link to="/">
            🏠 Dashboard
        </Link>


        <Link to="/scan">
            🔍 Start Scan
        </Link>


        <Link to="/vulnerabilities">
            ⚠ Vulnerabilities
        </Link>


        <Link to="/mitre">
            🎯 MITRE ATT&CK
        </Link>


        <Link to="/attack-chain">
            🔗 Attack Chain
        </Link>


        <Link to="/reports">
            📄 Reports
        </Link>


    </nav>


</aside>


)

}


export default Sidebar;
