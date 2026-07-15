import { useEffect, useState } from "react";


function Dashboard(){


const [vulnerabilities,setVulnerabilities]=useState([]);
const [techniques,setTechniques]=useState([]);
const [chain,setChain]=useState({});


useEffect(()=>{

loadDashboard();

},[]);



async function loadDashboard(){


try{


const vulnRes =
await fetch(
"http://127.0.0.1:8000/api/vulnerabilities/"
);


const vulnData =
await vulnRes.json();



setVulnerabilities(
    vulnData.vulnerabilities || []
);



const mitreRes =
await fetch(
"http://127.0.0.1:8000/api/mitre/techniques"
);


const mitreData =
await mitreRes.json();



setTechniques(
    mitreData.techniques || []
);



const chainRes =
await fetch(
"http://127.0.0.1:8000/api/attack-chain/"
);


const chainData =
await chainRes.json();


setChain(chainData);



}
catch(error){

console.log(
"Dashboard Error:",
error
)

}


}



return (

<div>


<h1>
Hybrid AI Red Team Dashboard
</h1>



<div className="cards">


<div className="card">

<h3>
Vulnerabilities
</h3>

<p>
{
vulnerabilities.length
}
</p>

</div>



<div className="card">

<h3>
MITRE Techniques
</h3>

<p>
{
techniques.length
}
</p>

</div>



<div className="card">

<h3>
Attack Phases
</h3>

<p>
{
chain.phase_count || 0
}
</p>

</div>


</div>





<h2>
Latest Vulnerabilities
</h2>


<table border="1">


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
vulnerabilities.map(
(v,i)=>(

<tr key={i}>

<td>
{v.host}
</td>


<td>
{v.cve}
</td>


<td>
{v.severity}
</td>


<td>
{v.cvss}
</td>


</tr>


)

)

}


</tbody>


</table>





<h2>
MITRE ATT&CK Techniques
</h2>



<table border="1">


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
techniques.map(
(t,i)=>(

<tr key={i}>


<td>
{t.technique_id}
</td>


<td>
{t.technique_name}
</td>


<td>
{t.tactic}
</td>


<td>
{t.confidence}
</td>


</tr>

)

)

}



</tbody>


</table>



</div>


)


}


export default Dashboard;
