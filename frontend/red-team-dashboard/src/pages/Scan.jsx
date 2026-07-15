import {useState,useEffect} from "react";

import {
startScan,
getProgress
} from "../api/apiClient";


function Scan(){


const [target,setTarget]=useState("");

const [lhost,setLhost]=useState(
"10.0.2.4"
);


const [loading,setLoading]=useState(false);


const [progress,setProgress]=useState({
phase:0,
title:"Waiting",
progress:0
});



useEffect(()=>{


let timer;


if(loading){


timer=setInterval(async()=>{

const data =
await getProgress();


setProgress(data);



if(data.status==="completed"){

setLoading(false);

}


},2000);


}



return ()=>clearInterval(timer);


},[loading]);





async function run(){


setLoading(true);


await startScan(
target,
lhost
);


}




return (

<div>


<h1>
Hybrid AI Red Team Scan
</h1>



<div>


<label>
Target
</label>

<input

value={target}

onChange={
e=>setTarget(e.target.value)
}

placeholder="192.168.1.100"

/>



<label>
LHOST
</label>


<input

value={lhost}

onChange={
e=>setLhost(e.target.value)
}

/>


<button
onClick={run}
disabled={loading}
>

{
loading?
"Scanning...":
"Start Scan"
}

</button>


</div>




<div className="progress">


<h2>
Phase {progress.phase}/12
</h2>


<h3>
{progress.title}
</h3>



<div
style={{
width:"500px",
height:"25px",
border:"1px solid gray"
}}
>


<div

style={{

width:`${progress.progress}%`,
height:"100%",
background:"green"

}}

>


</div>


</div>


<p>
{progress.progress}%
</p>


</div>



</div>


)


}


export default Scan;
