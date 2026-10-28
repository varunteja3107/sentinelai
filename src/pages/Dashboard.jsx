import { API_BASE as API } from "../api";
import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  Server,
  RefreshCw,
  Wifi,
  AlertTriangle,
} from "lucide-react";
import PageLayout from "../components/PageLayout";

function Dashboard() {
  const [data, setData] = useState(null);
  const [network, setNetwork] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);

  const loadDashboard = useCallback(async () => {
    try {
      const [dashboardResponse, networkResponse] = await Promise.all([
        fetch(`${API}/api/dashboard`),
        fetch(`${API}/api/network/summary`),
      ]);

      if (!dashboardResponse.ok || !networkResponse.ok) {
        throw new Error("The backend did not return all dashboard data.");
      }

      const [dashboardData, networkData] = await Promise.all([
        dashboardResponse.json(),
        networkResponse.json(),
      ]);

      setData(dashboardData);
      setNetwork(networkData);
      setUpdatedAt(new Date());
      setError("");
    } catch (err) {
      setError(
        "Cannot connect to the backend. Keep the FastAPI server running on port 8000."
      );
      console.error("Dashboard request failed:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
    const timer = setInterval(loadDashboard, 5000);
    return () => clearInterval(timer);
  }, [loadDashboard]);

  const metrics = [
    {
      title: "Recorded Threats",
      value: data?.active_threats,
      icon: ShieldAlert,
      tone: "purple",
      description: "Threat records reported by the backend",
    },
    {
      title: "Blocked Attacks",
      value: data?.blocked_attacks,
      icon: ShieldCheck,
      tone: "green",
      description: "Recorded blocked attack events",
    },
    {
      title: "Registered Devices",
      value: network?.devices,
      icon: Server,
      tone: "blue",
      description: `${network?.online ?? "—"} online · ${network?.offline ?? "—"} offline`,
    },
    {
      title: "Security Alerts",
      value: data?.security_alerts,
      icon: AlertTriangle,
      tone: "orange",
      description: "Alerts reported by the backend",
    },
  ];

  return (
    <PageLayout
      title="Security Dashboard"
      subtitle="SentinelAI threat intelligence and security overview"
    >
      <div className="monitor-page">
        <div className="monitor-status-banner">
          <div>
            <Activity size={18} />
            <span>Backend data</span>
            <span className="monitor-status-muted">
              Refreshes every 5 seconds
            </span>
          </div>
          <button
            type="button"
            className="monitor-refresh-button"
            onClick={loadDashboard}
            disabled={loading}
          >
            <RefreshCw size={15} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="monitor-error" role="alert">
            {error}
          </div>
        )}

        <div className="monitor-stats">
          {metrics.map((metric) => {
            const Icon = metric.icon;
            return (
              <div className="monitor-stat" key={metric.title}>
                <div className={`monitor-icon ${metric.tone}`}>
                  <Icon size={21} />
                </div>
                <div>
                  <strong>
                    {loading && metric.value === undefined
                      ? "..."
                      : metric.value ?? "Unavailable"}
                  </strong>
                  <span>{metric.title}</span>
                  <small>{metric.description}</small>
                </div>
              </div>
            );
          })}
        </div>

        <div className="monitor-grid">
          <section className="monitor-card">
            <div className="monitor-card-header">
              <div>
                <h2>Security Score</h2>
                <p>Score returned by the backend</p>
              </div>
            </div>
            <div className="monitor-empty">
              <ShieldCheck size={32} />
              <h3>
                {data?.security_score == null
                  ? "Score unavailable"
                  : `${data.security_score}%`}
              </h3>
              <p>
                This score is backend-reported. It is not an independent
                verification that your Mac is free from threats.
              </p>
            </div>
          </section>

          <section className="monitor-card">
            <div className="monitor-card-header">
              <div>
                <h2>Network Status</h2>
                <p>Registered device and event totals</p>
              </div>
              <Wifi size={20} />
            </div>
            <div className="monitor-empty">
              <h3>
                {network ? `${network.online} registered devices online` : "Unavailable"}
              </h3>
              <p>
                {network
                  ? `${network.total_threats} recorded threats and ${network.blocked_connections} recorded blocked connections.`
                  : "Waiting for network summary data."}
              </p>
              <p>
                Live packet capture and actual network speeds are not connected
                yet.
              </p>
            </div>
          </section>
        </div>

        <section className="monitor-card">
          <div className="monitor-card-header">
            <div>
              <h2>Data Freshness</h2>
              <p>Last successful dashboard update</p>
            </div>
          </div>
          <p className="monitor-last-updated">
            {updatedAt ? updatedAt.toLocaleTimeString() : "Waiting for backend"}
          </p>
        </section>
      </div>
    </PageLayout>
  );
}

export default Dashboard;
