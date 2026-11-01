import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

const CHART_TOOLTIP = {
  background: "#102238",
  border: "1px solid #29435f",
  borderRadius: "10px",
  color: "#e5edf7",
};

export function SeverityChartCard({ data }) {
  return (
    <section className="monitor-card">
      <div className="monitor-card-header">
        <div>
          <h2>Threat Severity</h2>
          <p>Distribution of recorded threat events</p>
        </div>
      </div>

      {data.length > 0 ? (
        <>
          <div className="severity-chart">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={62}
                  outerRadius={88}
                  paddingAngle={4}
                  stroke="none"
                >
                  {data.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={CHART_TOOLTIP} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="severity-legend">
            {data.map((item) => (
              <div key={item.name}>
                <span>
                  <i style={{ background: item.color }} />
                  {item.name}
                </span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </>
      ) : (
        <div className="monitor-empty">
          <p>Waiting for threat analytics data.</p>
        </div>
      )}
    </section>
  );
}

export function ThreatCategoryChartCard({ data }) {
  return (
    <section className="monitor-card">
      <div className="monitor-card-header">
        <div>
          <h2>Threat Category Analysis</h2>
          <p>Recorded events grouped by threat type</p>
        </div>
      </div>

      {data.length > 0 ? (
        <div className="threat-category-chart">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 5, right: 24, left: 18, bottom: 5 }}
            >
              <CartesianGrid
                stroke="#20354a"
                strokeDasharray="3 3"
                horizontal={false}
              />
              <XAxis
                type="number"
                allowDecimals={false}
                stroke="#8297af"
                tick={{ fill: "#8297af", fontSize: 11 }}
              />
              <YAxis
                type="category"
                dataKey="name"
                width={150}
                stroke="#8297af"
                tick={{ fill: "#b9c8d9", fontSize: 11 }}
              />
              <Tooltip contentStyle={CHART_TOOLTIP} />
              <Bar
                dataKey="value"
                name="Recorded events"
                fill="#48a8ed"
                radius={[0, 6, 6, 0]}
                maxBarSize={22}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="monitor-empty">
          <p>Waiting for threat category data.</p>
        </div>
      )}
    </section>
  );
}
