import {useEffect,useState} from "react";

import {
getAttackChain
} from "../api/apiClient";


function AttackChain(){


const [chain,setChain]=useState(null);



useEffect(()=>{

load();

},[]);



async function load(){

try{

const data =
await getAttackChain();


setChain(data);


}

catch(err){

console.log(
err
);

}


}




return (

<div className="page">


<div className="page-header">

<h1>
🔗 AI Attack Chain
</h1>

<p>
Generated attack path from simulation
</p>

</div>




<div className="dashboard-grid">


<div className="stat-card">

<p>
Phases
</p>

<h2>
{chain?.phase_count || 0}
</h2>


</div>



<div className="stat-card">

<p>
Techniques
</p>

<h2>
{chain?.tech_count || 0}
</h2>


</div>



<div className="stat-card">

<p>
Confidence
</p>

<h2>
{chain?
Math.round(chain.avg_confidence*100)
:0}%

</h2>


</div>


</div>





<div className="table-card">


<h2>
Attack Phases
</h2>



{

chain?.phases ?

Object.values(chain.phases).map(
(p,i)=>(


<div className="phase-card" key={i}>


<h3>
{p.phase_name}
</h3>


<p>
Tactic:
{p.tactic}
</p>


<p>
Techniques:
{p.techniques.length}
</p>


</div>


)

)

:

<p>
No attack chain generated yet
</p>

}



</div>


</div>

)


}


export default AttackChain;
