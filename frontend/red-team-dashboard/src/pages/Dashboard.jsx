import { useEffect, useState } from "react";

import {
  ShieldCheck,
  ShieldAlert,
  Target,
  Activity,
  AlertTriangle,
  GitBranch
} from "lucide-react";


import StatCard from "../components/StatCard";
import ActivityFeed from "../components/ActivityFeed";



function Dashboard(){


const [vulnerabilities,setVulnerabilities]=useState([]);

const [techniques,setTechniques]=useState([]);

const [chain,setChain]=useState({});

const [activities,setActivities]=useState([]);




useEffect(()=>{

loadDashboard();

},[]);





async function loadDashboard(){


try{



// Vulnerabilities

const vulnRes =
await fetch(
"http://127.0.0.1:8000/api/vulnerabilities/"
);


const vulnData =
await vulnRes.json();


setVulnerabilities(
vulnData.vulnerabilities || []
);





// MITRE Techniques

const mitreRes =
await fetch(
"http://127.0.0.1:8000/api/mitre/techniques"
);


const mitreData =
await mitreRes.json();


setTechniques(
mitreData.techniques || []
);






// Attack Chain

const chainRes =
await fetch(
"http://127.0.0.1:8000/api/attack-chain/"
);


const chainData =
await chainRes.json();


setChain(chainData);






// Activity Feed (Real Engine Data)

const activityRes =
await fetch(
"http://127.0.0.1:8000/api/activity/"
);


const activityData =
await activityRes.json();



setActivities(
activityData.activities || []
);



}

catch(error){

console.log(
"Dashboard Error:",
error
);


}


}






return(


<div className="dashboard">





<div className="dashboard-header">


<div className="dashboard-title">



<div className="dashboard-logo">

<ShieldCheck size={35}/>

</div>



<div>

<h1>
Hybrid AI Red Team SOC
</h1>


</div>



</div>



</div>







<div className="stats-grid">





<StatCard

icon={<ShieldAlert size={30}/>}

title="Vulnerabilities"

value={vulnerabilities.length}

/>







<StatCard

icon={<Target size={30}/>}

title="MITRE Techniques"

value={techniques.length}

/>







<StatCard

icon={<GitBranch size={30}/>}

title="Attack Phases"

value={chain.phase_count || 0}

/>








<StatCard

icon={<AlertTriangle size={30}/>}

title="Critical Threats"

value={
vulnerabilities.filter(
v =>
v.severity?.toLowerCase()==="critical"
).length
}

/>





</div>








<div className="panel">


<h2>

<Activity size={22}/>

 Activity Feed

</h2>




<ActivityFeed

activities={activities}

/>



</div>








<div className="panel">


<h2>

<ShieldAlert size={22}/>

 Latest Vulnerabilities

</h2>





<table>


<thead>

<tr>

<th>
Host
</th>


<th>
CVE
</th>


<th>
Severity
</th>


<th>
CVSS
</th>


</tr>


</thead>






<tbody>



{

vulnerabilities
.slice(0,8)
.map((v,i)=>(



<tr key={i}>


<td>
{v.host || "N/A"}
</td>



<td>
{v.cve || "-"}
</td>





<td>


<span 
className={`severity ${v.severity?.toLowerCase()}`}
>

{v.severity || "Unknown"}

</span>


</td>





<td>

{v.cvss || "-"}

</td>




</tr>



))


}



</tbody>



</table>




</div>









<div className="panel">


<h2>

<Target size={22}/>

 MITRE ATT&CK Coverage

</h2>






<table>


<thead>


<tr>


<th>
ID
</th>


<th>
Technique
</th>


<th>
Tactic
</th>


<th>
Confidence
</th>


</tr>



</thead>






<tbody>




{

techniques
.slice(0,8)
.map((t,i)=>(



<tr key={i}>


<td>
{t.technique_id || "-"}
</td>



<td>
{t.technique_name || "-"}
</td>



<td>
{t.tactic || "-"}
</td>



<td>
{t.confidence || "-"}
</td>



</tr>



))


}




</tbody>



</table>





</div>








</div>


)


}



export default Dashboard;
