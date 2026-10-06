import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ShieldAlert,
  Ban,
  Search,
  Zap,
} from "lucide-react";

import PageLayout from "../components/PageLayout";

const API = "http://127.0.0.1:8000";

function ThreatDetection() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [search, setSearch] = useState("");
  const [message, setMessage] = useState("");

  const loadThreats = async () => {
    try {
      const response = await fetch(`${API}/api/threats`);

      if (!response.ok) {
        throw new Error("Failed to load threats");
      }

      const data = await response.json();

      setThreats(data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadThreats();

    const interval = setInterval(
      loadThreats,
      5000
    );

    return () => clearInterval(interval);
  }, []);

  const simulateThreat = async () => {
    setSimulating(true);
    setMessage("");

    try {
      const response = await fetch(
        `${API}/api/demo/attack`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error("Simulation failed");
      }

      const result = await response.json();

      setMessage(
        `${result.severity} threat detected • Risk ${result.risk_score} • ${result.action}`
      );

      await loadThreats();

    } catch (error) {
      console.error(error);
      setMessage("Unable to simulate threat");
    } finally {
      setSimulating(false);
    }
  };

  const filteredThreats = threats.filter((threat) => {
    const value = search.toLowerCase();

    return (
      threat.threat_type
        ?.toLowerCase()
        .includes(value) ||
      threat.source_ip
        ?.toLowerCase()
        .includes(value) ||
      threat.destination_ip
        ?.toLowerCase()
        .includes(value) ||
      threat.severity
        ?.toLowerCase()
        .includes(value)
    );
  });

  const activeThreats = threats.filter(
    (threat) => threat.status === "OPEN"
  ).length;

  const blockedThreats = threats.filter(
    (threat) => threat.action === "BLOCK"
  ).length;

  const detectedToday = threats.length;

  return (
    <PageLayout
      title="Threat Detection"
      subtitle="AI-powered network threat analysis"
    >

      <div className="threat-page">

        <div className="threat-page-header">

          <div>
            <h2>Threat Detection</h2>

            <p>
              Monitor and analyze suspicious network activity.
            </p>
          </div>

          <button
            className="threat-simulate-button"
            onClick={simulateThreat}
            disabled={simulating}
          >
            <Zap size={17} />

            {simulating
              ? "Analyzing..."
              : "Simulate Threat"}
          </button>

        </div>

        {message && (
          <div className="threat-success">
            {message}
          </div>
        )}

        <div className="threat-stats">

          <div className="threat-stat-card">

            <div className="threat-stat-icon warning">
              <AlertTriangle size={20} />
            </div>

            <div>
              <div className="threat-stat-value">
                {activeThreats}
              </div>

              <div className="threat-stat-label">
                Active Threats
              </div>
            </div>

          </div>

          <div className="threat-stat-card">

            <div className="threat-stat-icon detected">
              <ShieldAlert size={20} />
            </div>

            <div>
              <div className="threat-stat-value">
                {detectedToday}
              </div>

              <div className="threat-stat-label">
                Detected Today
              </div>
            </div>

          </div>

          <div className="threat-stat-card">

            <div className="threat-stat-icon blocked">
              <Ban size={20} />
            </div>

            <div>
              <div className="threat-stat-value">
                {blockedThreats}
              </div>

              <div className="threat-stat-label">
                Blocked
              </div>
            </div>

          </div>

        </div>

        <div className="threat-events">

          <div className="events-header">

            <div>
              <h2>Threat Events</h2>

              <p>
                AI-detected network activity
              </p>
            </div>

            <div className="threat-search">

              <Search size={17} />

              <input
                type="text"
                placeholder="Search threats..."
                value={search}
                onChange={(event) =>
                  setSearch(event.target.value)
                }
              />

            </div>

          </div>

          {loading ? (

            <div className="threat-loading">
              Loading threat events...
            </div>

          ) : filteredThreats.length === 0 ? (

            <div className="threat-empty">
              No matching threat events.
            </div>

          ) : (

            <div className="threat-table threat-detection-table">

              <div className="threat-table-header">

                <span>Threat</span>
                <span>Source</span>
                <span>Destination</span>
                <span>Risk</span>
                <span>Severity</span>
                <span>Action</span>

              </div>

              {filteredThreats.map((threat) => (

                <div
                  className="threat-row"
                  key={threat.id}
                >

                  <span>
                    <strong>
                      {threat.threat_type}
                    </strong>

                    <small>
                      {threat.protocol} • Port {threat.port}
                    </small>
                  </span>

                  <span>
                    {threat.source_ip}
                  </span>

                  <span>
                    {threat.destination_ip}
                  </span>

                  <span>
                    <strong>
                      {threat.risk_score}
                    </strong>
                  </span>

                  <span>
                    <span
                      className={`severity-badge ${threat.severity.toLowerCase()}`}
                    >
                      {threat.severity}
                    </span>
                  </span>

                  <span>
                    <span
                      className={`action-badge ${threat.action.toLowerCase()}`}
                    >
                      {threat.action}
                    </span>
                  </span>

                </div>

              ))}

            </div>

          )}

        </div>

      </div>

    </PageLayout>
  );
}

export default ThreatDetection;
