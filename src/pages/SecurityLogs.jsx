import { useCallback, useEffect, useMemo, useState } from "react";
import {
  FileText,
  AlertTriangle,
  ShieldCheck,
  Ban,
  Search,
  RefreshCw,
  Download,
  Activity,
  Filter,
  Network,
} from "lucide-react";
import PageLayout from "../components/PageLayout";
import { API_BASE as API } from "../api";

const panel = {
  background: "#111827",
  border: "1px solid #263449",
  borderRadius: 14,
  padding: 18,
  color: "#E2E8F0",
  minWidth: 0,
};

const inputStyle = {
  width: "100%",
  boxSizing: "border-box",
  padding: "10px 12px",
  background: "#0B1120",
  border: "1px solid #334155",
  borderRadius: 8,
  color: "#F8FAFC",
  outline: "none",
};

const muted = { color: "#94A3B8", fontSize: 12 };

const colors = {
  CRITICAL: "#F87171",
  HIGH: "#FB923C",
  WARNING: "#FBBF24",
  MEDIUM: "#FBBF24",
  INFO: "#38BDF8",
  LOW: "#4ADE80",
};

async function apiRequest(path) {
  const token = sessionStorage.getItem("sentinelai_admin_token");

  const response = await fetch(`${API}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.detail || `Request failed (${response.status})`);
  }

  return data;
}

function severityColor(value) {
  return colors[String(value || "INFO").toUpperCase()] || "#94A3B8";
}

function formatDate(value) {
  if (!value) return "Time unavailable";

  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString();
}

function Stat({ icon: Icon, title, value, color }) {
  return (
    <div style={panel}>
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 9,
        color,
        fontSize: 12,
        fontWeight: 700,
      }}>
        <Icon size={19} />
        {title}
      </div>
      <div style={{
        fontSize: 27,
        fontWeight: 900,
        marginTop: 12,
      }}>
        {value}
      </div>
    </div>
  );
}

function SecurityLogs() {
  const [logs, setLogs] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [eventType, setEventType] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("");
  const [view, setView] = useState("logs");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadData = useCallback(async (initial = false) => {
    if (initial) setLoading(true);
    else setRefreshing(true);

    try {
      const results = await Promise.allSettled([
        apiRequest("/api/logs"),
        apiRequest("/api/incidents"),
      ]);

      const [logsResult, incidentsResult] = results;

      if (logsResult.status === "fulfilled") {
        setLogs(Array.isArray(logsResult.value) ? logsResult.value : []);
      } else {
        throw logsResult.reason;
      }

      if (incidentsResult.status === "fulfilled") {
        setIncidents(
          Array.isArray(incidentsResult.value)
            ? incidentsResult.value
            : []
        );
      }

      setLastUpdated(new Date());
      setError(
        incidentsResult.status === "rejected"
          ? "Audit logs loaded, but incident records could not be refreshed."
          : ""
      );
    } catch (err) {
      console.error(err);
      setError(err.message || "Unable to load security logs.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData(true);
    const timer = setInterval(() => loadData(false), 5000);
    return () => clearInterval(timer);
  }, [loadData]);

  const eventTypes = useMemo(() => {
    return [...new Set(
      logs.map((log) => log.event_type || "UNKNOWN")
    )].sort();
  }, [logs]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const text = [
        log.event_type,
        log.message,
        log.severity,
        log.source_ip,
        log.action,
        log.id,
      ].join(" ").toLowerCase();

      const matchesSearch = text.includes(search.toLowerCase());
      const matchesSeverity =
        severity === "ALL" ||
        String(log.severity || "").toUpperCase() === severity;
      const matchesType =
        eventType === "ALL" || log.event_type === eventType;
      const matchesSource =
        !sourceFilter ||
        String(log.source_ip || "").toLowerCase().includes(
          sourceFilter.toLowerCase()
        );

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesType &&
        matchesSource
      );
    });
  }, [logs, search, severity, eventType, sourceFilter]);

  const suspiciousSources = useMemo(() => {
    const counts = {};

    logs.forEach((log) => {
      const ip = log.source_ip;
      if (!ip || ip === "Unknown") return;
      counts[ip] = (counts[ip] || 0) + 1;
    });

    return Object.entries(counts)
      .filter(([, count]) => count >= 3)
      .sort((a, b) => b[1] - a[1]);
  }, [logs]);

  const criticalCount = logs.filter((log) =>
    ["CRITICAL", "HIGH"].includes(
      String(log.severity || "").toUpperCase()
    )
  ).length;

  const blockedCount = logs.filter((log) =>
    String(log.action || "").toUpperCase().includes("BLOCK")
  ).length;

  const resolvedCount = incidents.filter(
    (incident) =>
      String(incident.status || "").toUpperCase() === "RESOLVED"
  ).length;

  function exportData(format) {
    const rows = filteredLogs.map((log) => ({
      id: log.id,
      timestamp: log.created_at,
      event_type: log.event_type,
      severity: log.severity,
      source_ip: log.source_ip,
      action: log.action,
      message: log.message,
    }));

    let content;
    let mime;
    let filename;

    if (format === "json") {
      content = JSON.stringify(rows, null, 2);
      mime = "application/json";
      filename = "sentinelai-security-logs.json";
    } else {
      const columns = Object.keys(
        rows[0] || {
          id: "",
          timestamp: "",
          event_type: "",
          severity: "",
          source_ip: "",
          action: "",
          message: "",
        }
      );

      const escapeCsv = (value) =>
        `"${String(value ?? "").replace(/"/g, '""')}"`;

      content = [
        columns.join(","),
        ...rows.map((row) =>
          columns.map((column) => escapeCsv(row[column])).join(",")
        ),
      ].join("\n");

      mime = "text/csv;charset=utf-8";
      filename = "sentinelai-security-logs.csv";
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <PageLayout
      title="Security Logs"
      subtitle="Live audit events, incident correlation and suspicious activity monitoring"
    >
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(155px,1fr))",
        gap: 14,
        marginBottom: 20,
      }}>
        <Stat
          icon={FileText}
          title="Audit Events"
          value={logs.length}
          color="#38BDF8"
        />
        <Stat
          icon={AlertTriangle}
          title="High / Critical"
          value={criticalCount}
          color="#F87171"
        />
        <Stat
          icon={ShieldCheck}
          title="Resolved Incidents"
          value={resolvedCount}
          color="#4ADE80"
        />
        <Stat
          icon={Ban}
          title="Blocked Actions"
          value={blockedCount}
          color="#FB923C"
        />
      </div>

      {error && (
        <div style={{
          ...panel,
          borderColor: "#7F1D1D",
          color: "#FCA5A5",
          marginBottom: 16,
        }}>
          {error}
        </div>
      )}

      <section style={{ ...panel, marginBottom: 20 }}>
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
          marginBottom: 16,
        }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 19 }}>
              <Filter size={19} color="#22D3EE" /> Advanced Log Filters
            </h2>
            <p style={muted}>
              Search and narrow down recorded security events.
            </p>
          </div>

          <button
            type="button"
            onClick={() => loadData(false)}
            disabled={refreshing}
            style={{
              ...inputStyle,
              width: "auto",
              display: "flex",
              alignItems: "center",
              gap: 8,
              cursor: "pointer",
            }}
          >
            <RefreshCw size={15} />
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))",
          gap: 12,
        }}>
          <label style={muted}>
            Search
            <div style={{ position: "relative", marginTop: 6 }}>
              <Search
                size={16}
                style={{
                  position: "absolute",
                  left: 10,
                  top: 11,
                  color: "#94A3B8",
                }}
              />
              <input
                style={{ ...inputStyle, paddingLeft: 34 }}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search messages..."
              />
            </div>
          </label>

          <label style={muted}>
            Severity
            <select
              style={{ ...inputStyle, marginTop: 6 }}
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="WARNING">Warning</option>
              <option value="MEDIUM">Medium</option>
              <option value="INFO">Info</option>
              <option value="LOW">Low</option>
            </select>
          </label>

          <label style={muted}>
            Event Type
            <select
              style={{ ...inputStyle, marginTop: 6 }}
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
            >
              <option value="ALL">All event types</option>
              {eventTypes.map((type) => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
          </label>

          <label style={muted}>
            Source IP
            <input
              style={{ ...inputStyle, marginTop: 6 }}
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              placeholder="Filter by IP..."
            />
          </label>
        </div>

        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 10,
          marginTop: 15,
        }}>
          <span style={muted}>
            Showing {filteredLogs.length} of {logs.length} loaded events
          </span>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              onClick={() => exportData("csv")}
              style={{
                ...inputStyle,
                width: "auto",
                cursor: "pointer",
                display: "flex",
                gap: 7,
                alignItems: "center",
              }}
            >
              <Download size={14} /> Export CSV
            </button>
            <button
              type="button"
              onClick={() => exportData("json")}
              style={{
                ...inputStyle,
                width: "auto",
                cursor: "pointer",
                display: "flex",
                gap: 7,
                alignItems: "center",
              }}
            >
              <Download size={14} /> Export JSON
            </button>
          </div>
        </div>
      </section>

      <section style={{ ...panel, marginBottom: 20 }}>
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 10,
          marginBottom: 15,
        }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 19 }}>
              <Activity size={19} color="#22D3EE" /> Security Event Feed
            </h2>
            <p style={muted}>
              Automatically refreshed every five seconds.
              {lastUpdated && ` Last updated: ${lastUpdated.toLocaleTimeString()}`}
            </p>
          </div>

          <span style={{
            color: "#4ADE80",
            fontSize: 11,
            fontWeight: 800,
          }}>
            ● LIVE REFRESH
          </span>
        </div>

        <div style={{
          display: "flex",
          gap: 8,
          flexWrap: "wrap",
          marginBottom: 15,
        }}>
          <button
            type="button"
            onClick={() => setView("logs")}
            style={{
              ...inputStyle,
              width: "auto",
              cursor: "pointer",
              borderColor: view === "logs" ? "#22D3EE" : "#334155",
            }}
          >
            Audit Events ({filteredLogs.length})
          </button>
          <button
            type="button"
            onClick={() => setView("incidents")}
            style={{
              ...inputStyle,
              width: "auto",
              cursor: "pointer",
              borderColor: view === "incidents" ? "#22D3EE" : "#334155",
            }}
          >
            Incidents ({incidents.length})
          </button>
        </div>

        {loading ? (
          <p style={muted}>Loading security records...</p>
        ) : view === "logs" ? (
          filteredLogs.length === 0 ? (
            <p style={muted}>No audit events match these filters.</p>
          ) : (
            <div style={{ display: "grid", gap: 10 }}>
              {filteredLogs.map((log, index) => (
                <div
                  key={log.id ?? index}
                  style={{
                    padding: 14,
                    borderRadius: 10,
                    background: "#0B1120",
                    border: "1px solid #263449",
                    display: "grid",
                    gridTemplateColumns: "minmax(0,1fr) auto",
                    gap: 12,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      flexWrap: "wrap",
                    }}>
                      <strong style={{ fontSize: 14 }}>
                        {log.event_type || "Security Event"}
                      </strong>
                      <span style={{
                        color: severityColor(log.severity),
                        background: `${severityColor(log.severity)}18`,
                        border: `1px solid ${severityColor(log.severity)}55`,
                        borderRadius: 20,
                        padding: "3px 8px",
                        fontSize: 10,
                        fontWeight: 800,
                      }}>
                        {log.severity || "INFO"}
                      </span>
                    </div>

                    <p style={{
                      fontSize: 13,
                      color: "#CBD5E1",
                      lineHeight: 1.6,
                      overflowWrap: "anywhere",
                    }}>
                      {log.message || "No event description available."}
                    </p>

                    <div style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: 12,
                      ...muted,
                    }}>
                      <span>IP: {log.source_ip || "Unknown"}</span>
                      <span>Action: {log.action || "N/A"}</span>
                      <span>Event ID: {log.id ?? "N/A"}</span>
                    </div>
                  </div>

                  <div style={{
                    ...muted,
                    textAlign: "right",
                    minWidth: 110,
                  }}>
                    {formatDate(log.created_at)}
                  </div>
                </div>
              ))}
            </div>
          )
        ) : (
          incidents.length === 0 ? (
            <p style={muted}>No incidents available.</p>
          ) : (
            <div style={{ display: "grid", gap: 10 }}>
              {incidents.map((incident) => (
                <div
                  key={incident.id}
                  style={{
                    padding: 14,
                    borderRadius: 10,
                    background: "#0B1120",
                    border: "1px solid #263449",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: 12,
                  }}
                >
                  <div>
                    <strong>{incident.title}</strong>
                    <p style={muted}>
                      Incident #{incident.id} · Risk score {incident.risk_score}
                    </p>
                  </div>
                  <div style={{
                    display: "flex",
                    gap: 8,
                    alignItems: "center",
                    flexWrap: "wrap",
                  }}>
                    <span style={{
                      color: severityColor(incident.severity),
                      fontWeight: 800,
                      fontSize: 11,
                    }}>
                      {incident.severity}
                    </span>
                    <span style={muted}>{incident.status}</span>
                  </div>
                </div>
              ))}
            </div>
          )
        )}
      </section>

      <section style={panel}>
        <div style={{ marginBottom: 15 }}>
          <h2 style={{ margin: 0, fontSize: 19 }}>
            <Network size={19} color="#22D3EE" /> Suspicious Source Correlation
          </h2>
          <p style={muted}>
            Sources appearing in at least three of the currently loaded audit events.
          </p>
        </div>

        {suspiciousSources.length === 0 ? (
          <p style={muted}>
            No repeated source IPs detected in the loaded audit records.
          </p>
        ) : (
          <div style={{ display: "grid", gap: 9 }}>
            {suspiciousSources.map(([ip, count]) => (
              <div
                key={ip}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: 10,
                  padding: 12,
                  borderRadius: 8,
                  background: "#0B1120",
                  border: "1px solid #334155",
                }}
              >
                <div>
                  <strong style={{ fontFamily: "monospace" }}>{ip}</strong>
                  <div style={muted}>
                    Repeated source in the current audit sample
                  </div>
                </div>
                <span style={{
                  color: "#FBBF24",
                  fontWeight: 800,
                  fontSize: 13,
                }}>
                  {count} events
                </span>
              </div>
            ))}
          </div>
        )}

        <p style={{ ...muted, marginTop: 15 }}>
          Correlation is a heuristic based on event frequency, not proof of an attack.
          The backend currently supplies up to 100 audit records.
        </p>
      </section>
    </PageLayout>
  );
}

export default SecurityLogs;
