import { useEffect, useState } from "react";

const API = "https://sentinelai-wnno.onrender.com";

function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadDashboard = async () => {
    try {
      const response = await fetch(`${API}/api/dashboard`);
      const result = await response.json();
      setData(result);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  if (loading) {
    return (
      <div style={{ padding: 40, color: "#f8fafc", background: "#0b1120", minHeight: "100vh" }}>
        Loading SecureX AI...
      </div>
    );
  }

  return (
    <div style={{ padding: 32, color: "#f8fafc" }}>
      <h1>SecureX AI</h1>
      <p>AI-Powered Threat Detection & Zero Trust Security</p>

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(4, 1fr)",
        gap: 20,
        marginTop: 30
      }}>
        <Card title="Active Threats" value={data?.active_threats ?? 0} />
        <Card title="Blocked Attacks" value={data?.blocked_attacks ?? 0} />
        <Card title="Security Alerts" value={data?.security_alerts ?? 0} />
        <Card title="Security Score" value={`${data?.security_score ?? 100}%`} />
      </div>

      <div style={{
        marginTop: 30,
        padding: 24,
        background: "#111827",
        borderRadius: 16
      }}>
        <h2>Security Status</h2>
        <p>AI Engine: Online</p>
        <p>Threat Detection: Active</p>
        <p>Zero Trust: Enabled</p>
        <p>Backend: Connected</p>

        <button
          onClick={loadDashboard}
          style={{
            marginTop: 15,
            padding: "12px 20px",
            borderRadius: 8,
            border: 0,
            cursor: "pointer"
          }}
        >
          Refresh
        </button>
      </div>
    </div>
  );
}

function Card({ title, value }) {
  return (
    <div style={{
      background: "#111827",
      padding: 24,
      borderRadius: 16
    }}>
      <p>{title}</p>
      <h2>{value}</h2>
    </div>
  );
}

export default Dashboard;
