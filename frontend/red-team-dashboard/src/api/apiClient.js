const API =
"http://127.0.0.1:8000";



export async function startScan(target,lhost){


const response = await fetch(
`${API}/api/scan/run`,
{
method:"POST",
headers:{
"Content-Type":"application/json"
},
body:JSON.stringify({

target,
lhost,
dry_run:true,
threshold:30

})
}
);


return await response.json();

}



export async function getProgress(){


const response = await fetch(
`${API}/api/progress`
);


return await response.json();

}



export async function getSession(id){


const response = await fetch(
`${API}/api/session/${id}`
);


return await response.json();

}



export async function getVulnerabilities(){


const response = await fetch(
`${API}/api/vulnerabilities/`
);


return await response.json();

}



export async function getMitre(){


const response = await fetch(
`${API}/api/mitre/techniques`
);


return await response.json();

}
