import { API_BASE as API } from "../api";
import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  Server,
  RefreshCw,
  Wifi,
  AlertTriangle,
  Cpu,
  HardDrive,
  MemoryStick,
  Clock3,
  Monitor,
} from "lucide-react";
import PageLayout from "../components/PageLayout";


const SeverityChartCard = lazy(() =>
  import("../components/dashboard/DashboardCharts").then((module) => ({
    default: module.SeverityChartCard,
  }))
);

const ThreatCategoryChartCard = lazy(() =>
  import("../components/dashboard/DashboardCharts").then((module) => ({
    default: module.ThreatCategoryChartCard,
  }))
);

const ThreatTimeline = lazy(() => import("../components/dashboard/ThreatTimeline"));

const SEVERITY_COLORS = {
  critical: "#fb5475",
  high: "#fb923c",
  medium: "#facc15",
  low: "#4ade80",
};


function Dashboard() {
  const [data, setData] = useState(null);
  const [network, setNetwork] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [security, setSecurity] = useState(null);
  const [threats, setThreats] = useState([]);
  const [system, setSystem] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState(null);

  const loadDashboard = useCallback(async () => {
    setRefreshing(true);

    const endpoints = [
      ["/api/dashboard", setData],
      ["/api/network/summary", setNetwork],
      ["/api/analytics/summary", setAnalytics],
      ["/api/security-score", setSecurity],
      ["/api/threats/recent?limit=8", setThreats],
      ["/api/live/system", setSystem],
    ];

    const results = await Promise.allSettled(
      endpoints.map(async ([path, setter]) => {
        const response = await fetch(`${API}${path}`);

        if (!response.ok) {
          throw new Error(`${path} returned HTTP ${response.status}`);
        }

        const result = await response.json();
        setter(result);
        return path;
      })
    );

    const failures = results
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason?.message || "Unknown API error");

    if (failures.length === endpoints.length) {
      setError("Unable to load dashboard data. Check the backend connection.");
    } else if (failures.length > 0) {
      setError(`Some dashboard sections could not update: ${failures.join("; ")}`);
    } else {
      setError("");
      setUpdatedAt(new Date());
    }

    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    loadDashboard();
    const timer = setInterval(loadDashboard, 10000);
    return () => clearInterval(timer);
  }, [loadDashboard]);

  const metrics = [
    {
      title: "Recorded Threats",
      value: data?.active_threats,
      icon: ShieldAlert,
      tone: "purple",
      description: "Threat records reported by backend",
    },
    {
      title: "Blocked Attacks",
      value: data?.blocked_attacks,
      icon: ShieldCheck,
      tone: "green",
      description: "Recorded blocked events",
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
      description: "Alerts reported by backend",
    },
  ];

  const severityData = analytics?.severity
    ? Object.entries(analytics.severity).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        color: SEVERITY_COLORS[name],
      }))
    : [];

  const threatTypeData = analytics?.threat_types
    ? Object.entries(analytics.threat_types)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value)
    : [];

  const score = security?.score;
  const scoreColor =
    score >= 80 ? "#4ade80" : score >= 60 ? "#facc15" : "#fb7185";

  const systemCards = [
    {
      title: "CPU Usage",
      value: system?.cpu_percent,
      unit: "%",
      icon: Cpu,
      tone: "blue",
    },
    {
      title: "Memory Usage",
      value: system?.memory?.percent,
      unit: "%",
      icon: MemoryStick,
      tone: "purple",
    },
    {
      title: "Disk Usage",
      value: system?.disk?.percent,
      unit: "%",
      icon: HardDrive,
      tone: "orange",
    },
    {
      title: "Running Processes",
      value: system?.process_count,
      unit: "",
      icon: Monitor,
      tone: "green",
    },
  ];

  return (
    <PageLayout
      title="Security Dashboard"
      subtitle="SentinelAI threat intelligence and security operations center"
    >
      <div className="monitor-page advanced-dashboard">
        <div className="monitor-status-banner">
          <div>
            <Activity size={18} />
            <span>Security monitoring active</span>
            <span className="monitor-status-muted">
              Automatic refresh every 10 seconds
            </span>
          </div>

          <button
            type="button"
            className="monitor-refresh-button"
            onClick={loadDashboard}
            disabled={refreshing}
          >
            <RefreshCw size={15} className={refreshing ? "spin-icon" : ""} />
            {refreshing ? "Updating..." : "Refresh"}
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
                    {metric.value == null
                      ? loading
                        ? "..."
                        : "Unavailable"
                      : metric.value}
                  </strong>
                  <span>{metric.title}</span>
                  <small>{metric.description}</small>
                </div>
              </div>
            );
          })}
        </div>

        <div className="advanced-dashboard-grid">
          <section className="monitor-card advanced-score-card">
            <div className="monitor-card-header">
              <div>
                <h2>Security Posture</h2>
                <p>Calculated by the SentinelAI backend</p>
              </div>
              <ShieldCheck size={22} />
            </div>

            <div className="score-content">
              <div
                className="score-ring"
                style={{
                  background: `conic-gradient(${scoreColor} ${
                    Number(score) || 0
                  }%, #20354a 0)`,
                }}
              >
                <div className="score-ring-inner">
                  <strong>
                    {score == null ? "--" : Number(score).toFixed(1)}
                  </strong>
                  <span>OUT OF 100</span>
                </div>
              </div>

              <div className="score-details">
                <span
                  className="score-status"
                  style={{ color: scoreColor }}
                >
                  {security?.status || "Waiting for backend"}
                </span>
                <p>
                  This score is calculated from recorded threat risk and
                  blocked-event ratios. It is not a guarantee that the
                  system is threat-free.
                </p>
                <div className="score-detail-row">
                  <span>Average risk</span>
                  <strong>{analytics?.average_risk ?? "—"}</strong>
                </div>
                <div className="score-detail-row">
                  <span>Average anomaly</span>
                  <strong>{analytics?.average_anomaly ?? "—"}</strong>
                </div>
              </div>
            </div>
          </section>

          <Suspense
            fallback={
              <section className="monitor-card">
                <div className="monitor-empty">
                  <p>Loading threat severity chart...</p>
                </div>
              </section>
            }
          >
            <SeverityChartCard data={severityData} />
          </Suspense>
        </div>

        <Suspense
          fallback={
            <section className="monitor-card">
              <div className="monitor-empty">
                <p>Loading threat category chart...</p>
              </div>
            </section>
          }
        >
          <ThreatCategoryChartCard data={threatTypeData} />
        </Suspense>

        <Suspense
          fallback={
            <section className="monitor-card">
              <div className="monitor-empty">
                <p>Loading threat activity timeline...</p>
              </div>
            </section>
          }
        >
          <ThreatTimeline />
        </Suspense>

        <section className="monitor-card threat-feed-card">
          <div className="monitor-card-header">
            <div>
              <h2>Recent Threat Intelligence</h2>
              <p>Latest recorded events from the threat database</p>
            </div>
            <span className="feed-count">
              {threats.length} recent records
            </span>
          </div>

          {threats.length > 0 ? (
            <div className="threat-table-wrap">
              <table className="threat-table">
                <thead>
                  <tr>
                    <th>Threat</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Risk</th>
                    <th>Severity</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map((threat) => (
                    <tr key={threat.id}>
                      <td>
                        <strong>{threat.threat_type}</strong>
                        <small>
                          {threat.protocol || "—"} · Port {threat.port ?? "—"}
                        </small>
                      </td>
                      <td>{threat.source_ip || "—"}</td>
                      <td>{threat.destination_ip || "—"}</td>
                      <td>
                        <strong>{threat.risk_score ?? "—"}</strong>
                      </td>
                      <td>
                        <span
                          className={`threat-severity ${
                            threat.severity?.toLowerCase() || "unknown"
                          }`}
                        >
                          {threat.severity || "UNKNOWN"}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`threat-action ${
                            threat.action?.toLowerCase() || "unknown"
                          }`}
                        >
                          {threat.action || "UNKNOWN"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="monitor-empty">
              <p>No recent threat records available.</p>
            </div>
          )}
        </section>

        <section className="monitor-card">
          <div className="monitor-card-header">
            <div>
              <h2>Local System Health</h2>
              <p>Live operating-system telemetry from this Mac</p>
            </div>
            <Monitor size={20} />
          </div>

          <div className="system-health-grid">
            {systemCards.map((item) => {
              const Icon = item.icon;
              const value = item.value;

              return (
                <div className="system-health-item" key={item.title}>
                  <div className={`monitor-icon ${item.tone}`}>
                    <Icon size={19} />
                  </div>
                  <div className="system-health-info">
                    <span>{item.title}</span>
                    <strong>
                      {value == null
                        ? "—"
                        : `${Number(value).toFixed(
                            item.unit === "%" ? 1 : 0
                          )}${item.unit}`}
                    </strong>
                    {item.unit === "%" && value != null && (
                      <div className="system-progress">
                        <span
                          style={{
                            width: `${Math.min(100, Math.max(0, Number(value)))}%`,
                          }}
                        />
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="system-note">
            <Wifi size={15} />
            <span>
              {system?.connection_access === "available"
                ? "System connection information is available."
                : "Network connection visibility is permission-limited on this Mac."}
            </span>
          </div>

          <p className="system-host">
            Host: {system?.hostname || "Waiting for system telemetry"}
          </p>
        </section>

        <section className="monitor-card data-freshness-card">
          <div>
            <h2>Data Freshness</h2>
            <p>
              <Clock3 size={15} />
              Last successful update:{" "}
              {updatedAt ? updatedAt.toLocaleTimeString() : "Waiting for backend"}
            </p>
          </div>
          <span className="feed-count">
            {refreshing ? "Updating" : "Auto refresh enabled"}
          </span>
        </section>
      </div>
    </PageLayout>
  );
}

export default Dashboard;
