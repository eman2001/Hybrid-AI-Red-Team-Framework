import {useEffect,useState} from "react";

import {
    getMitre,
    getMitreHeatmap
} from "../api/apiClient";


function Mitre(){


const [data,setData]=useState({

techniques:[],
tactics_covered:0,
total_techniques:0

});


const [heatmap,setHeatmap]=useState([]);



useEffect(()=>{

loadMitre();

},[]);



async function loadMitre(){

try{


const result = await getMitre();

setData(result);



const map = await getMitreHeatmap();

setHeatmap(
map.techniques || []
);



}
catch(err){

console.log(
"MITRE Error:",
err
);

}


}




return (

<div className="page">


<div className="page-header">

<h1>
🎯 MITRE ATT&CK Intelligence
</h1>

<p>
AI mapped adversary techniques
</p>


</div>



<div className="dashboard-grid">


<div className="stat-card">

<div>

<p>
Techniques
</p>

<h2>
{data.total_techniques}
</h2>

</div>

</div>



<div className="stat-card">

<div>

<p>
Tactics Covered
</p>

<h2>
{data.tactics_covered}
</h2>

</div>

</div>


</div>




<div className="table-card">


<h2>
Detected Techniques
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

data.techniques.map(
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
{Math.round(t.confidence*100)}%
</td>


</tr>


)

)

}



</tbody>


</table>



</div>


</div>

)


}


export default Mitre;
