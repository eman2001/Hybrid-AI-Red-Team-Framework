function SummaryCards({ vulnerabilities, techniques }) {

    const critical =
        vulnerabilities.filter(
            v => v.severity === "critical"
        ).length;

    const high =
        vulnerabilities.filter(
            v => v.severity === "high"
        ).length;

    return (

        <div className="summary-grid">

            <div className="card">
                <h3>Total Vulnerabilities</h3>
                <h1>{vulnerabilities.length}</h1>
            </div>

            <div className="card">
                <h3>Critical</h3>
                <h1>{critical}</h1>
            </div>

            <div className="card">
                <h3>High</h3>
                <h1>{high}</h1>
            </div>

            <div className="card">
                <h3>MITRE Techniques</h3>
                <h1>{techniques.length}</h1>
            </div>

        </div>

    );

}

export default SummaryCards;
