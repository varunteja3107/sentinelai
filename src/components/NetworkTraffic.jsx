import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const data = [
  { time: "00:00", traffic: 32 },
  { time: "04:00", traffic: 45 },
  { time: "08:00", traffic: 38 },
  { time: "12:00", traffic: 62 },
  { time: "16:00", traffic: 51 },
  { time: "20:00", traffic: 74 },
  { time: "24:00", traffic: 58 },
];

function NetworkTraffic() {
  return (
    <section className="network-card">

      <div className="network-card-header">

        <div>
          <h2>Network Traffic</h2>

          <p>
            Traffic activity over the last 24 hours
          </p>
        </div>

        <div className="traffic-status">
          LIVE
        </div>

      </div>

      <div className="network-chart">

        <ResponsiveContainer
          width="100%"
          height="100%"
        >

          <LineChart data={data}>

            <CartesianGrid
              stroke="#1a2e46"
              vertical={false}
            />

            <XAxis
              dataKey="time"
              stroke="#64748b"
              tick={{
                fontSize: 11,
              }}
              axisLine={false}
              tickLine={false}
            />

            <YAxis
              stroke="#64748b"
              tick={{
                fontSize: 11,
              }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip
              contentStyle={{
                background: "#0c1b2d",
                border: "1px solid #263b55",
                borderRadius: "8px",
                color: "#e2e8f0",
              }}
            />

            <Line
              type="monotone"
              dataKey="traffic"
              stroke="#38bdf8"
              strokeWidth={3}
              dot={false}
              activeDot={{
                r: 5,
              }}
            />

          </LineChart>

        </ResponsiveContainer>

      </div>

    </section>
  );
}

export default NetworkTraffic;
