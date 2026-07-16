import { useState, useEffect } from "react";

import {
    startScan,
    getProgress
} from "../api/apiClient";


function Scan(){


    const [target,setTarget] = useState("");

    const [lhost,setLhost] = useState(
        "10.0.2.4"
    );


    const [loading,setLoading] = useState(false);


    const [progress,setProgress] = useState({

        phase:0,
        title:"Waiting",
        progress:0,
        status:"idle"

    });



    // ===============================
    // Progress Polling
    // ===============================

    useEffect(()=>{


        let timer;


        if(loading){


            timer = setInterval(async()=>{


                try{


                    const data = await getProgress();


                    setProgress(data);



                    if(
                        data.status === "completed"
                        ||
                        data.status === "failed"
                    ){

                        setLoading(false);

                    }



                }
                catch(err){

                    console.log(err);

                }


            },2000);



        }



        return ()=>clearInterval(timer);



    },[loading]);






    // ===============================
    // Start Scan
    // ===============================

    async function run(){


        if(!target){

            alert("Please enter target IP");

            return;

        }


        setLoading(true);


        setProgress({

            phase:0,
            title:"Starting Scan",
            progress:0,
            status:"running"

        });



        await startScan(
            target,
            lhost
        );


    }






    return (

    <div className="scan-page">


        {/* HEADER */}

        <div className="scan-header">


            <h1>
                🔥 Hybrid AI Red Team Scan
            </h1>


            <p>
                Automated reconnaissance, vulnerability analysis
                and MITRE ATT&CK mapping
            </p>


        </div>






        {/* SCAN CARD */}

        <div className="scan-card">


            <div className="input-group">


                <label>
                    🎯 Target
                </label>


                <input

                    value={target}

                    onChange={
                        e=>setTarget(e.target.value)
                    }

                    placeholder="192.168.1.100"

                />


            </div>





            <div className="input-group">


                <label>
                    🖥 LHOST
                </label>


                <input

                    value={lhost}

                    onChange={
                        e=>setLhost(e.target.value)
                    }

                />


            </div>





            <button

                className="scan-btn"

                onClick={run}

                disabled={loading}

            >

                {

                    loading ?

                    "⚡ Scanning..."

                    :

                    "🚀 Start Scan"

                }


            </button>



        </div>








        {/* PROGRESS */}

        <div className="progress-card">


            <div className="progress-title">


                <h2>
                    Scan Progress
                </h2>


                <span>

                    Phase {progress.phase}/12

                </span>


            </div>





            <h3>

                {progress.title}

            </h3>





            <div className="progress-bar">


                <div

                className="progress-fill"

                style={{

                    width:`${progress.progress}%`

                }}

                >

                </div>


            </div>





            <div className="progress-info">


                <strong>
                    {progress.progress}%
                </strong>


                <span>

                    Status:
                    {" "}

                    {progress.status}

                </span>


            </div>



        </div>







        {/* PHASES */}

        <div className="phase-card">


            <h2>
                Pipeline Stages
            </h2>



            <div className="phases">


            {
            [
                "Reconnaissance",
                "Network Scanning",
                "Service Detection",
                "Vulnerability Analysis",
                "Threat Intelligence",
                "Exploit Mapping",
                "MITRE ATT&CK",
                "Attack Chain",
                "Risk Analysis",
                "AI Reasoning",
                "Report Generation",
                "Completed"

            ].map((item,index)=>(


                <div

                key={index}

                className={
                    progress.phase > index
                    ?
                    "phase done"
                    :
                    "phase"
                }

                >

                    <span>
                        {index+1}
                    </span>

                    {item}

                </div>


            ))

            }


            </div>


        </div>




    </div>


    )


}


export default Scan;
