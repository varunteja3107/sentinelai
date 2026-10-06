import { useEffect, useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Monitor,
  Bell,
  Zap,
  RefreshCw,
} from "lucide-react";

import PageLayout from "../components/PageLayout";

const API = "https://sentinelai-wnno.onrender.com";

function Dashboard() {
  const [dashboard, setDashboard] = useState(null);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const loadDashboard = async () => {
    try {
      const [dashboardResponse, threatsResponse] =
        await Promise.all([
          fetch(`${API}/api/dashboard`),
          fetch(`${API}/api/threats`),
        ]);

      const dashboardData = await dashboardResponse.json();
      const threatsData = await threatsResponse.json();

      setDashboard(dashboardData);
      setThreats(threatsData);
    } catch (error) {
      console.error("Dashboard error:", error);
    }
  };

  useEffect(() => {
    loadDashboard();

    const interval = setInterval(
      loadDashboard,
      5000
    );

    return () => clearInterval(interval);
  }, []);

  const simulateAttack = async () => {
    setLoading(true);
    setMessage("");

    try {
      const response = await fetch(
        `${API}/api/demo/attack`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error("Attack simulation failed");
      }

      const result = await response.json();

      setMessage(
        `${result.severity} threat detected • Risk ${result.risk_score} • ${result.action}`
      );

      await loadDashboard();

    } catch (error) {
      console.error(error);
      setMessage("Unable to connect to SentinelAI backend.");
    } finally {
      setLoading(false);
    }
  };

  const securityScore =
    dashboard?.security_score ?? 100;

  return (
    <PageLayout
      title="Security Overview"
      subtitle="AI-powered network security monitoring"
    >

      {/* ACTION BAR */}

      <div className="dashboard-actions">

        <button
          className="simulate-button"
          onClick={simulateAttack}
          disabled={loading}
        >
          <Zap size={17} />

          {loading
            ? "Analyzing..."
            : "Simulate Attack"}
        </button>

        <button
          className="refresh-button"
          onClick={loadDashboard}
        >
          <RefreshCw size={16} />
          Refresh
        </button>

      </div>

      {/* RESULT MESSAGE */}

      {message && (
        <div className="dashboard-alert">
          <ShieldAlert size={18} />
          <span>{message}</span>
        </div>
      )}

      {/* KPI CARDS */}

      <div className="dashboard-kpis">

        <div className="dashboard-kpi">

          <div className="kpi-icon danger">
            <ShieldAlert size={21} />
          </div>

          <div>
            <strong>
              {dashboard?.active_threats ?? 0}
            </strong>

            <span>Active Threats</span>
          </div>

        </div>

        <div className="dashboard-kpi">

          <div className="kpi-icon red">
            <ShieldCheck size={21} />
          </div>

          <div>
            <strong>
              {dashboard?.blocked_attacks ?? 0}
            </strong>

            <span>Blocked Attacks</span>
          </div>

        </div>

        <div className="dashboard-kpi">

          <div className="kpi-icon blue">
            <Monitor size={21} />
          </div>

          <div>
            <strong>
              {dashboard?.connected_devices ?? 0}
            </strong>

            <span>Connected Devices</span>
          </div>

        </div>

        <div className="dashboard-kpi">

          <div className="kpi-icon orange">
            <Bell size={21} />
          </div>

          <div>
            <strong>
              {dashboard?.security_alerts ?? 0}
            </strong>

            <span>Security Alerts</span>
          </div>

        </div>

      </div>

      {/* MAIN GRID */}

      <div className="dashboard-main-grid">

        {/* NETWORK TRAFFIC */}

        <section className="dashboard-panel">

          <div className="dashboard-panel-header">

            <div>
              <h2>Network Traffic</h2>
              <p>Traffic activity over the last 24 hours</p>
            </div>

            <span className="live-status">
              <i></i>
              LIVE
            </span>

          </div>

          <div className="network-chart">

            {[35, 48, 42, 65, 52, 76, 60, 84, 70, 91, 68, 78].map(
              (height, index) => (
                <div
                  className="network-column"
                  key={index}
                >
                  <div
                    style={{
                      height: `${height}%`,
                    }}
                  />
                </div>
              )
            )}

          </div>

          <div className="chart-labels">
            <span>00:00</span>
            <span>04:00</span>
            <span>08:00</span>
            <span>12:00</span>
            <span>16:00</span>
            <span>20:00</span>
            <span>24:00</span>
          </div>

        </section>

        {/* THREAT LEVEL */}

        <section className="dashboard-panel threat-level-panel">

          <div className="dashboard-panel-header">

            <div>
              <h2>Threat Level</h2>
              <p>Current network risk</p>
            </div>

          </div>

          <div className="risk-circle">

            <div className="risk-circle-inner">
              <strong>{securityScore}</strong>
              <span>SECURITY SCORE</span>
            </div>

          </div>

          <div className="risk-details">

            <div>
              <span>System Risk</span>
              <strong>
                {Math.max(
                  0,
                  100 - securityScore
                )}%
              </strong>
            </div>

            <div>
              <span>AI Confidence</span>
              <strong>94%</strong>
            </div>

          </div>

        </section>

      </div>

      {/* RECENT THREATS */}

      <section className="dashboard-panel recent-threats-panel">

        <div className="dashboard-panel-header">

          <div>
            <h2>Recent Threats</h2>
            <p>Latest AI-detected network activity</p>
          </div>

          <span className="event-count">
            {threats.length} events
          </span>

        </div>

        {threats.length === 0 ? (

          <div className="dashboard-empty">
            No threats detected yet.
          </div>

        ) : (

          <div className="threat-table">

            <div className="threat-table-header">
              <span>THREAT</span>
              <span>SOURCE</span>
              <span>RISK</span>
              <span>SEVERITY</span>
              <span>ACTION</span>
            </div>

            {threats.slice(0, 8).map((threat) => (

              <div
                className="threat-table-row"
                key={threat.id}
              >

                <div>
                  <strong>
                    {threat.threat_type}
                  </strong>

                  <small>
                    Port {threat.port}
                  </small>
                </div>

                <span>
                  {threat.source_ip}
                </span>

                <strong>
                  {threat.risk_score}
                </strong>

                <span
                  className={`severity-tag ${threat.severity.toLowerCase()}`}
                >
                  {threat.severity}
                </span>

                <span
                  className={`action-tag ${threat.action.toLowerCase()}`}
                >
                  {threat.action}
                </span>

              </div>

            ))}

          </div>

        )}

      </section>

    </PageLayout>
  );
}

export default Dashboard;
