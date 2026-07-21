import { useState, useEffect } from "react";
import {
  Target,
  Monitor,
  Rocket,
  ShieldCheck,
  Activity,
  CheckCircle,
  Clock,
  ScanLine
} from "lucide-react";

import { startScan, getProgress } from "../api/apiClient";

function Scan() {

  const [target, setTarget] = useState("");
  const [lhost, setLhost] = useState("10.0.2.4");
  const [loading, setLoading] = useState(false);

  const [progress, setProgress] = useState({
    phase: 0,
    title: "Waiting",
    progress: 0,
    status: "idle"
  });

  useEffect(() => {

    let timer;

    if (loading) {

      timer = setInterval(async () => {

        try {

          const data = await getProgress();

          setProgress(data);

          if (
            data.status === "completed" ||
            data.status === "failed"
          ) {
            setLoading(false);
          }

        } catch (err) {
          console.log(err);
        }

      }, 2000);

    }

    return () => clearInterval(timer);

  }, [loading]);



  async function run() {

    if (!target) {
      alert("Please enter target IP");
      return;
    }

    setLoading(true);

    setProgress({
      phase: 0,
      title: "Starting Scan",
      progress: 0,
      status: "running"
    });

    await startScan(target, lhost);

  }


  const stages = [
    "Recon",
    "Scan",
    "Vulns",
    "Threat",
    "Risk",
    "Exploit",
    "MITRE",
    "AI",
    "Graph",
    "Report"
  ];


  return (

    <div className="scan-page">

      <div className="scan-header">

        <h1 className="scan-title">
          <ShieldCheck size={38} />
          <span>Hybrid AI Security Assessment</span>
        </h1>

        <p>
          Automated Red Team Pipeline • Reconnaissance • MITRE ATT&CK • AI Risk Engine
        </p>

      </div>



      <div className="scan-card">

        <div className="input-group">

          <label>
            <Target size={18} />
            Target IP / URL
          </label>

          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.100"
          />

        </div>



        <div className="input-group">

          <label>
            <Monitor size={18} />
            Kali LHOST
          </label>

          <input
            value={lhost}
            onChange={(e) => setLhost(e.target.value)}
          />

        </div>



        <button
          className="scan-btn"
          onClick={run}
          disabled={loading}
        >

          {
            loading
              ?
              <>
                <Activity size={20} />
                Running Scan...
              </>
              :
              <>
                <Rocket size={20} />
                Start Security Scan
              </>
          }

        </button>

      </div>




      <div className="progress-card">

        <div className="progress-title">

          <h2>
            <ScanLine size={22} />
            Scan Progress
          </h2>

          <span>
            Phase {progress.phase}/12
          </span>

        </div>

        <h3>{progress.title}</h3>

        <div className="progress-bar">

          <div
            className="progress-fill"
            style={{
              width: `${progress.progress}%`
            }}
          />

        </div>

        <div className="progress-info">

          <strong>{progress.progress}%</strong>

          <span className="progress-status">
            <Clock size={16} />
            {progress.status}
          </span>

        </div>

      </div>




      <div className="phase-card">

        <h2>
          <Activity size={22} />
          Pipeline Stages
        </h2>

        <div className="pipeline-horizontal">

          {stages.map((item, index) => (

            <div className="pipeline-step" key={index}>

              <div
                className={
                  progress.phase > index + 1
                    ? "pipeline-circle done"
                    : progress.phase === index + 1
                      ? "pipeline-circle active"
                      : "pipeline-circle"
                }
              >

                {
                  progress.phase > index + 1
                    ? <CheckCircle size={18} />
                    : index + 1
                }

              </div>

              <span>{item}</span>

              {
                index !== stages.length - 1 &&
                <div
                  className={
                    progress.phase > index + 1
                      ? "pipeline-line done"
                      : "pipeline-line"
                  }
                />
              }

            </div>

          ))}

        </div>

      </div>

    </div>

  );

}

export default Scan;
