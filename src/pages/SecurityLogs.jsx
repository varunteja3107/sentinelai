import { useEffect, useState } from "react";
import {
  FileText,
  AlertTriangle,
  ShieldCheck,
  Ban,
  Search,
} from "lucide-react";

import PageLayout from "../components/PageLayout";

const API = "https://sentinelai-wnno.onrender.com";

function SecurityLogs() {
  const [incidents, setIncidents] = useState([]);
  const [search, setSearch] = useState("");

  const loadIncidents = async () => {
    try {
      const response = await fetch(`${API}/api/incidents`);
      const data = await response.json();
      setIncidents(data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    loadIncidents();

    const interval = setInterval(
      loadIncidents,
      5000
    );

    return () => clearInterval(interval);
  }, []);

  const filtered = incidents.filter((incident) =>
    `${incident.title} ${incident.severity} ${incident.status}`
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  return (
    <PageLayout
      title="Security Logs"
      subtitle="Security events, incidents and audit activity"
    >
      <div className="logs-page">

        <div className="logs-stats">

          <div className="log-stat">
            <FileText size={21} />
            <div>
              <strong>{incidents.length}</strong>
              <span>Total Incidents</span>
            </div>
          </div>

          <div className="log-stat red">
            <AlertTriangle size={21} />
            <div>
              <strong>
                {
                  incidents.filter(
                    (x) => x.severity === "HIGH" ||
                           x.severity === "CRITICAL"
                  ).length
                }
              </strong>
              <span>High Risk</span>
            </div>
          </div>

          <div className="log-stat green">
            <ShieldCheck size={21} />
            <div>
              <strong>
                {
                  incidents.filter(
                    (x) => x.status === "RESOLVED"
                  ).length
                }
              </strong>
              <span>Resolved</span>
            </div>
          </div>

          <div className="log-stat orange">
            <Ban size={21} />
            <div>
              <strong>{incidents.length}</strong>
              <span>Blocked Events</span>
            </div>
          </div>

        </div>

        <section className="logs-card">

          <div className="logs-header">

            <div>
              <h2>Incident Timeline</h2>
              <p>Live security events from SentinelAI</p>
            </div>

            <div className="logs-search">
              <Search size={16} />

              <input
                placeholder="Search logs..."
                value={search}
                onChange={(e) =>
                  setSearch(e.target.value)
                }
              />
            </div>

          </div>

          {filtered.length === 0 ? (

            <div className="logs-empty">
              No security incidents found.
            </div>

          ) : (

            <div className="incident-list">

              {filtered.map((incident) => (

                <div
                  className="incident-row"
                  key={incident.id}
                >

                  <div className="incident-icon">
                    <AlertTriangle size={18} />
                  </div>

                  <div className="incident-main">

                    <strong>
                      {incident.title}
                    </strong>

                    <span>
                      Incident #{incident.id}
                      {" • "}
                      Risk Score {incident.risk_score}
                    </span>

                  </div>

                  <span
                    className={`severity-badge ${incident.severity.toLowerCase()}`}
                  >
                    {incident.severity}
                  </span>

                  <span className="incident-status">
                    {incident.status}
                  </span>

                </div>

              ))}

            </div>

          )}

        </section>

      </div>
    </PageLayout>
  );
}

export default SecurityLogs;
