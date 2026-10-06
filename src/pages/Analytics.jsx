import { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from "recharts";

import PageLayout from "../components/PageLayout";

const API = "http://localhost:8000";

function Analytics() {
  const [data, setData] = useState(null);

  const loadAnalytics = async () => {
    try {
      const response = await fetch(`${API}/api/analytics`);
      const result = await response.json();
      setData(result);
    } catch (error) {
      console.error("Analytics error:", error);
    }
  };

  useEffect(() => {
    loadAnalytics();

    const interval = setInterval(loadAnalytics, 5000);

    return () => clearInterval(interval);
  }, []);

  if (!data) {
    return (
      <PageLayout>
        <div className="page">
          <div className="loading-box">
            Loading security analytics...
          </div>
        </div>
      </PageLayout>
    );
  }

  const severityData = [
    { name: "Critical", value: data.severity.critical },
    { name: "High", value: data.severity.high },
    { name: "Medium", value: data.severity.medium },
    { name: "Low", value: data.severity.low }
  ];

  const actionData = [
    { name: "Blocked", value: data.actions.blocked },
    { name: "MFA", value: data.actions.mfa },
    { name: "Allowed", value: data.actions.allowed }
  ];

  return (
    <PageLayout>
      <div className="page analytics-page">

        <div className="analytics-header">
          <div>
            <h1>Security Analytics</h1>
            <p>
              AI-powered security intelligence and threat statistics
            </p>
          </div>

          <div className="analytics-live">
            <span></span>
            LIVE ANALYTICS
          </div>
        </div>

        <div className="analytics-kpis">

          <div className="analytics-card">
            <div className="analytics-icon threat-icon">🚨</div>
            <div className="analytics-card-content">
              <span>Total Threats</span>
              <strong>{data.total_threats}</strong>
            </div>
          </div>

          <div className="analytics-card">
            <div className="analytics-icon risk-icon">⚠️</div>
            <div className="analytics-card-content">
              <span>Average Risk</span>
              <strong>{data.average_risk}</strong>
            </div>
          </div>

          <div className="analytics-card">
            <div className="analytics-icon ai-icon">🤖</div>
            <div className="analytics-card-content">
              <span>AI Anomaly Score</span>
              <strong>{data.average_anomaly}</strong>
            </div>
          </div>

          <div className="analytics-card">
            <div className="analytics-icon block-icon">🛡️</div>
            <div className="analytics-card-content">
              <span>Blocked Attacks</span>
              <strong>{data.actions.blocked}</strong>
            </div>
          </div>

        </div>

        <div className="analytics-grid">

          <div className="analytics-panel">

            <div className="analytics-panel-header">
              <div>
                <h2>Threat Severity</h2>
                <p>Distribution of detected threats</p>
              </div>
            </div>

            <div className="analytics-chart">
              <ResponsiveContainer width="100%" height={320}>
                <BarChart data={severityData}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1d2c45"
                  />

                  <XAxis
                    dataKey="name"
                    stroke="#8fa3bf"
                  />

                  <YAxis
                    stroke="#8fa3bf"
                  />

                  <Tooltip
                    contentStyle={{
                      background: "#0f1a2e",
                      border: "1px solid #263b5d",
                      borderRadius: "10px",
                      color: "#ffffff"
                    }}
                  />

                  <Bar
                    dataKey="value"
                    fill="#3b82f6"
                    radius={[8, 8, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>

          </div>

          <div className="analytics-panel">

            <div className="analytics-panel-header">
              <div>
                <h2>Security Actions</h2>
                <p>AI and firewall response decisions</p>
              </div>
            </div>

            <div className="analytics-chart">
              <ResponsiveContainer width="100%" height={320}>
                <PieChart>

                  <Pie
                    data={actionData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={105}
                    label
                  >

                    {actionData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          index === 0
                            ? "#ef4444"
                            : index === 1
                            ? "#f59e0b"
                            : "#22c55e"
                        }
                      />
                    ))}

                  </Pie>

                  <Tooltip
                    contentStyle={{
                      background: "#0f1a2e",
                      border: "1px solid #263b5d",
                      borderRadius: "10px",
                      color: "#ffffff"
                    }}
                  />

                </PieChart>
              </ResponsiveContainer>
            </div>

          </div>

        </div>

        <div className="analytics-panel">

          <div className="analytics-panel-header">
            <div>
              <h2>Threat Intelligence</h2>
              <p>Detected attack categories</p>
            </div>
          </div>

          {data.threat_types.length === 0 ? (

            <div className="analytics-empty">
              No threats detected yet.
            </div>

          ) : (

            <div className="threat-type-list">

              {data.threat_types.map((threat) => (

                <div
                  className="threat-type-row"
                  key={threat.name}
                >

                  <div className="threat-type-name">
                    <span className="threat-dot"></span>
                    <span>{threat.name}</span>
                  </div>

                  <div className="threat-count">
                    {threat.count}
                  </div>

                </div>

              ))}

            </div>

          )}

        </div>

      </div>
    </PageLayout>
  );
}

export default Analytics;
