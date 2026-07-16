import { useEffect, useState } from "react";


function Vulnerabilities(){


    const [vulns,setVulns] = useState([]);

    const [loading,setLoading] = useState(true);



    useEffect(()=>{

        loadVulnerabilities();

    },[]);





    async function loadVulnerabilities(){


        try{


            const res = await fetch(
                "http://127.0.0.1:8000/api/vulnerabilities/"
            );


            const data = await res.json();


            setVulns(
                data.vulnerabilities || []
            );


        }
        catch(err){

            console.log(
                "Vulnerability Error:",
                err
            );

        }
        finally{

            setLoading(false);

        }


    }





    function severityClass(level){


        if(!level)
            return "severity";


        return (
            "severity " +
            level.toLowerCase()
        );


    }





    const critical =
        vulns.filter(
            v=>v.severity==="Critical"
        ).length;



    const high =
        vulns.filter(
            v=>v.severity==="High"
        ).length;



    const medium =
        vulns.filter(
            v=>v.severity==="Medium"
        ).length;



    const low =
        vulns.filter(
            v=>v.severity==="Low"
        ).length;






    return (

    <div className="vuln-page">



        <div className="page-header">


            <h1>
                🛡 Vulnerability Intelligence Center
            </h1>


            <p>
                Detected security weaknesses from the latest
                Red Team simulation
            </p>


        </div>





        {/* SUMMARY */}


        <div className="vuln-summary">


            <div className="v-card">

                <h3>
                    Total
                </h3>

                <strong>
                    {vulns.length}
                </strong>

            </div>



            <div className="v-card critical">

                <h3>
                    Critical
                </h3>

                <strong>
                    {critical}
                </strong>

            </div>




            <div className="v-card high">

                <h3>
                    High
                </h3>

                <strong>
                    {high}
                </strong>

            </div>




            <div className="v-card medium">

                <h3>
                    Medium
                </h3>

                <strong>
                    {medium}
                </strong>

            </div>



            <div className="v-card low">

                <h3>
                    Low
                </h3>

                <strong>
                    {low}
                </strong>

            </div>



        </div>







        {/* TABLE */}


        <div className="table-card">


        {

        loading ?

        <h2>
            Loading vulnerabilities...
        </h2>


        :


        vulns.length===0 ?


        <div className="empty">

            <h2>
                ✅ No Vulnerabilities Found
            </h2>


            <p>
                Run a scan to generate security findings.
            </p>

        </div>


        :


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


                    <th>
                        Risk Score
                    </th>


                    <th>
                        Exploit
                    </th>


                </tr>

            </thead>



            <tbody>


            {

            vulns.map(
                (v,index)=>(


                <tr key={index}>


                    <td>
                        {v.host}
                    </td>


                    <td className="cve">

                        {v.cve}

                    </td>



                    <td>

                    <span
                    className={
                        severityClass(
                            v.severity
                        )
                    }
                    >

                        {v.severity}

                    </span>


                    </td>



                    <td>
                        {v.cvss}
                    </td>



                    <td>
                        {v.risk_score}
                    </td>



                    <td>

                        {
                            v.exploit
                            ?
                            "⚠ Available"
                            :
                            "None"
                        }

                    </td>



                </tr>


                )

            )

            }



            </tbody>


        </table>


        }


        </div>



    </div>


    )

}



export default Vulnerabilities;
