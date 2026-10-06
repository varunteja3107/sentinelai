import { useEffect, useState } from "react";
import PageLayout from "../components/PageLayout";

const API = "https://sentinelai-wnno.onrender.com";

function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadIncidents = async () => {
    try {
      const response = await fetch(`${API}/api/incidents`);
      const data = await response.json();

      setIncidents(data);
    } catch (error) {
      console.error("Incident loading error:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();

    const interval = setInterval(loadIncidents, 5000);

    return () => clearInterval(interval);
  }, []);

  const critical = incidents.filter(
    (incident) => incident.severity === "CRITICAL"
  ).length;

  const high = incidents.filter(
    (incident) => incident.severity === "HIGH"
  ).length;

  const open = incidents.filter(
    (incident) => incident.status === "OPEN"
  ).length;

  return (
    <PageLayout>

      <div className="page incidents-page">

        <div className="incidents-header">

          <div>
            <h1>Security Incidents</h1>

            <p>
              Manage and investigate AI-detected security incidents
            </p>
          </div>

          <div className="incidents-live">
            <span></span>
            LIVE MONITORING
          </div>

        </div>

        <div className="incident-stats">

          <div className="incident-stat">
            <div className="incident-stat-icon">🚨</div>

            <div>
              <span>Total Incidents</span>
              <strong>{incidents.length}</strong>
            </div>
          </div>

          <div className="incident-stat">
            <div className="incident-stat-icon">🔴</div>

            <div>
              <span>Critical</span>
              <strong>{critical}</strong>
            </div>
          </div>

          <div className="incident-stat">
            <div className="incident-stat-icon">🟠</div>

            <div>
              <span>High Severity</span>
              <strong>{high}</strong>
            </div>
          </div>

          <div className="incident-stat">
            <div className="incident-stat-icon">🔓</div>

            <div>
              <span>Open Incidents</span>
              <strong>{open}</strong>
            </div>
          </div>

        </div>

        <div className="incidents-panel">

          <div className="incidents-panel-header">

            <div>
              <h2>Incident Queue</h2>

              <p>
                AI-generated incidents requiring security attention
              </p>
            </div>

            <button
              className="refresh-button"
              onClick={loadIncidents}
            >
              ↻ Refresh
            </button>

          </div>

          {loading ? (

            <div className="incident-empty">
              Loading incidents...
            </div>

          ) : incidents.length === 0 ? (

            <div className="incident-empty">
              <div className="empty-icon">✓</div>

              <h3>No Security Incidents</h3>

              <p>
                SecureX AI has not generated any incidents yet.
              </p>
            </div>

          ) : (

            <div className="incident-table-wrapper">

              <table className="incident-table">

                <thead>

                  <tr>
                    <th>ID</th>
                    <th>Incident</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Status</th>
                    <th>Threat ID</th>
                    <th>Created</th>
                  </tr>

                </thead>

                <tbody>

                  {incidents.map((incident) => (

                    <tr key={incident.id}>

                      <td>
                        <span className="incident-id">
                          #{incident.id}
                        </span>
                      </td>

                      <td>
                        <div className="incident-title">
                          <span className="incident-alert">
                            ⚠
                          </span>

                          <span>
                            {incident.title}
                          </span>
                        </div>
                      </td>

                      <td>

                        <span
                          className={`severity-badge ${incident.severity.toLowerCase()}`}
                        >
                          {incident.severity}
                        </span>

                      </td>

                      <td>

                        <span
                          className={
                            incident.risk_score >= 80
                              ? "risk-critical"
                              : incident.risk_score >= 60
                              ? "risk-high"
                              : "risk-medium"
                          }
                        >
                          {incident.risk_score}
                        </span>

                      </td>

                      <td>

                        <span className="status-badge">
                          <span></span>
                          {incident.status}
                        </span>

                      </td>

                      <td>
                        #{incident.threat_id}
                      </td>

                      <td>
                        {new Date(
                          incident.created_at
                        ).toLocaleString()}
                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          )}

        </div>

      </div>

    </PageLayout>
  );
}

export default Incidents;
