import { NavLink } from "react-router-dom";

import {
  LayoutDashboard,
  Search,
  ShieldAlert,
  Crosshair,
  GitBranch,
  FileText,
  Settings,
  X,
  ShieldCheck
} from "lucide-react";


function Sidebar({ open, close }) {


const menuItems = [

{
name:"Dashboard",
path:"/",
icon:<LayoutDashboard size={20}/>
},

{
name:"Start Scan",
path:"/scan",
icon:<Search size={20}/>
},

{
name:"Vulnerabilities",
path:"/vulnerabilities",
icon:<ShieldAlert size={20}/>
},

{
name:"MITRE ATT&CK",
path:"/mitre",
icon:<Crosshair size={20}/>
},

{
name:"Attack Chain",
path:"/attack-chain",
icon:<GitBranch size={20}/>
},

{
name:"Reports",
path:"/reports",
icon:<FileText size={20}/>
},


{
name:"Settings",
path:"/settings",
icon:<Settings size={20}/>
}

];



return (

<>


<div
className={`overlay ${open ? "show":""}`}
onClick={close}
/>



<aside className={`sidebar ${open ? "active":""}`}>


<div className="sidebar-header">


<div className="brand">


<div className="brand-icon">
<ShieldCheck size={28}/>
</div>


<div>

<h2>
Hybrid AI
</h2>

<span>
Red Team
</span>

</div>


</div>



<button
className="close-btn"
onClick={close}
>
<X size={22}/>
</button>


</div>



<nav>


{
menuItems.map((item)=>(

<NavLink
key={item.name}
to={item.path}
onClick={close}
className={({isActive}) =>
isActive ? "active-link" : ""
}
>


{item.icon}

<span>
{item.name}
</span>


</NavLink>

))
}


</nav>



<div className="sidebar-footer">


<strong>
Hybrid AI Framework
</strong>


<small>
Version 2.1.0
</small>


</div>



</aside>


</>

)

}


export default Sidebar;
