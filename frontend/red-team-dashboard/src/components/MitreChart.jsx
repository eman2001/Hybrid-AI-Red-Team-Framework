import {
    ResponsiveContainer,
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    CartesianGrid,
} from "recharts";

function MitreChart({ techniques }) {

    const grouped = {};

    techniques.forEach((t) => {

        const tactic = t.tactic || "Unknown";

        grouped[tactic] = (grouped[tactic] || 0) + 1;

    });

    const data = Object.keys(grouped).map((key) => ({
        tactic: key,
        count: grouped[key],
    }));

    return (

        <div className="panel">

            <h2>🎯 MITRE ATT&CK Coverage</h2>

            <ResponsiveContainer
                width="100%"
                height={300}
            >

                <BarChart data={data}>

                    <CartesianGrid strokeDasharray="3 3"/>

                    <XAxis
                        dataKey="tactic"
                    />

                    <YAxis/>

                    <Tooltip/>

                    <Bar
                        dataKey="count"
                        fill="#2563eb"
                        radius={[8,8,0,0]}
                    />

                </BarChart>

            </ResponsiveContainer>

        </div>

    );

}

export default MitreChart;
