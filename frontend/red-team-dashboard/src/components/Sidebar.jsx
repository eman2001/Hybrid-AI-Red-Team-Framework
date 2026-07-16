import { Link } from "react-router-dom";


function Sidebar({open, close}) {


return (

<>

<div
className={`overlay ${open ? "show":""}`}
onClick={close}
/>


<aside className={`sidebar ${open ? "active":""}`}>


<div className="sidebar-header">

<h2>
⚔ Red Team AI
</h2>


<button
className="close-btn"
onClick={close}
>
✕
</button>

</div>



<nav>


<Link to="/" onClick={close}>
🏠 Dashboard
</Link>


<Link to="/scan" onClick={close}>
🔍 Start Scan
</Link>


<Link to="/vulnerabilities" onClick={close}>
🛡 Vulnerabilities
</Link>


<Link to="/mitre" onClick={close}>
🎯 MITRE ATT&CK
</Link>


<Link to="/attack-chain" onClick={close}>
🔗 Attack Chain
</Link>


<Link to="/reports" onClick={close}>
📊 Reports
</Link>


</nav>



<div className="sidebar-footer">

<span>
Hybrid AI Framework
</span>

<br/>

<small>
v2.0.0
</small>

</div>



</aside>


</>

)


}


export default Sidebar;
