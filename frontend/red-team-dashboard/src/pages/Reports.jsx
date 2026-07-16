import {useEffect,useState} from "react";

import {
getDashboardAnalytics
} from "../api/apiClient";


function Reports(){


const [report,setReport]=useState(null);



useEffect(()=>{

load();

},[]);



async function load(){

const data =
await getDashboardAnalytics();

setReport(data);

}



return (

<div className="page">


<h1>
📊 Security Assessment Report
</h1>



<div className="report-card">


<h2>
Assessment Summary
</h2>


<p>
Hosts:
{report?.host_count || 0}
</p>


<p>
Vulnerabilities:
{report?.vuln_count || 0}
</p>


<p>
MITRE Techniques:
{report?.technique_count || 0}
</p>


<p>
Critical Findings:
{report?.kev_count || 0}
</p>



<button>
Export Report
</button>


</div>


</div>


)

}


export default Reports;
