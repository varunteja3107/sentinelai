import { API_BASE as API } from "../api";
import PageLayout from "../components/PageLayout";
import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  ShieldAlert,
  RefreshCw,
  Search,
  X
} from "lucide-react";

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [editStatus, setEditStatus] = useState("OPEN");
  const [editNotes, setEditNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");
  const [incidentAuditLogs, setIncidentAuditLogs] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [showIncidentTimeline, setShowIncidentTimeline] = useState(false);
  const [auditError, setAuditError] = useState("");



  const loadIncidents = async () => {
    try {
      setRefreshing(true);

      const response = await fetch(`${API}/api/incidents`);

      if (!response.ok) {
        throw new Error("Incident API request failed");
      }

      const data = await response.json();

      setIncidents(Array.isArray(data) ? data : []);
      setError("");
    } catch (err) {
      console.error(err);
      setError("Unable to connect to SecureX AI incident management.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };



  const loadIncidentAudit = async (incident) => {
    setAuditLoading(true);
    setAuditError("");
    setIncidentAuditLogs([]);

    try {
      const response = await fetch(`${API}/api/logs`);
      if (!response.ok) {
        throw new Error(`Audit API returned HTTP ${response.status}`);
      }

      const logs = await response.json();
      const sourceIp = incident.source_ip || "";
      const incidentId = String(incident.id);

      const related = (Array.isArray(logs) ? logs : []).filter((log) => {
        const message = String(log.message || "");
        const isIncidentUpdate =
          String(log.event_type || "") === "INCIDENT_UPDATED" &&
          message.includes(`Incident #${incidentId} `);

        const isRelatedThreat =
          sourceIp &&
          log.source_ip === sourceIp &&
          ["THREAT_DETECTED", "THREAT_BLOCKED"].includes(
            String(log.event_type || "")
          );

        return isIncidentUpdate || isRelatedThreat;
      });

      setIncidentAuditLogs(related.slice(0, 30));
    } catch (error) {
      setAuditError(error.message || "Unable to load audit history.");
    } finally {
      setAuditLoading(false);
    }
  };

  const openIncident = (incident) => {
    setSelectedIncident(incident);
    loadIncidentAudit(incident);
    setEditStatus(incident.status || "OPEN");
    setEditNotes(incident.notes || "");
    setSaveMessage("");
  };

  const saveIncident = async () => {
    if (!selectedIncident || saving) return;
    try {
      setSaving(true);
      setSaveMessage("");
      const response = await fetch(
        `${API}/api/incidents/${selectedIncident.id}`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: editStatus, notes: editNotes })
        }
      );
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail || "Unable to save changes.");
      }
      setSelectedIncident(result);
      setIncidents(items => items.map(item =>
        item.id === result.id ? result : item
      ));
      setEditStatus(result.status || "OPEN");
      setEditNotes(result.notes || "");
      setSaveMessage("Changes saved successfully.");
    } catch (err) {
      setSaveMessage(err.message || "Unable to save changes.");
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => {
    loadIncidents();

    const interval = setInterval(loadIncidents, 10000);

    return () => clearInterval(interval);
  }, []);

  const filtered = incidents.filter((incident) => {
    const q = search.toLowerCase();

    return (
      String(incident.title || "").toLowerCase().includes(q) ||
      String(incident.severity || "").toLowerCase().includes(q) ||
      String(incident.status || "").toLowerCase().includes(q) ||
      String(incident.id || "").includes(q)
    );
  });

  const critical = incidents.filter(
    (i) => i.severity === "CRITICAL"
  ).length;

  const high = incidents.filter(
    (i) => i.severity === "HIGH"
  ).length;

  const resolved = incidents.filter(
    (i) =>
      i.status === "RESOLVED" ||
      i.status === "CLOSED"
  ).length;

  const open = incidents.length - resolved;

  return (
    <PageLayout title="Incident Management">
      <div style={{ width: "100%", minWidth: 0 }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "28px"
          }}
        >
          <div>
            <div
              style={{
                color: "#64748B",
                fontSize: "12px",
                fontWeight: 800,
                letterSpacing: "1.5px"
              }}
            >
              SECURITY OPERATIONS
            </div>

            <h1 style={{ margin: "7px 0 0", fontSize: "30px" }}>
              Incident Management
            </h1>

            <p style={{ color: "#94A3B8", marginTop: "8px" }}>
              Investigate, track and manage AI-detected security incidents
            </p>
          </div>

          <button
            onClick={loadIncidents}
            disabled={refreshing}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              background: "#111827",
              border: "1px solid #263449",
              color: "#F8FAFC",
              padding: "11px 17px",
              borderRadius: "9px",
              cursor: "pointer",
              fontWeight: 700
            }}
          >
            <RefreshCw size={17} />
            Refresh
          </button>
        </div>

        {error && (
          <div
            style={{
              marginBottom: "20px",
              padding: "13px 16px",
              borderRadius: "9px",
              color: "#EF4444",
              background: "rgba(239,68,68,0.08)",
              border: "1px solid rgba(239,68,68,0.25)"
            }}
          >
            {error}
          </div>
        )}

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "16px",
            marginBottom: "20px"
          }}
        >
          <Stat
            icon={<ShieldAlert />}
            title="Total Incidents"
            value={incidents.length}
            color="#00D4FF"
          />

          <Stat
            icon={<AlertTriangle />}
            title="Critical"
            value={critical}
            color="#EF4444"
          />

          <Stat
            icon={<AlertTriangle />}
            title="High Risk"
            value={high}
            color="#F97316"
          />

          <Stat
            icon={<Clock />}
            title="Open"
            value={open}
            color="#F59E0B"
          />
        </div>

        <section
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            overflow: "hidden"
          }}
        >
          <div
            style={{
              padding: "20px 22px",
              borderBottom: "1px solid #1E293B",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center"
            }}
          >
            <div>
              <h2 style={{ margin: 0, fontSize: "19px" }}>
                Active Incidents
              </h2>

              <p
                style={{
                  margin: "5px 0 0",
                  color: "#64748B",
                  fontSize: "13px"
                }}
              >
                Live incidents generated by the threat response engine
              </p>
            </div>

            <div
              style={{
                position: "relative"
              }}
            >
              <Search
                size={16}
                color="#64748B"
                style={{
                  position: "absolute",
                  left: "12px",
                  top: "50%",
                  transform: "translateY(-50%)"
                }}
              />

              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search incidents..."
                style={{
                  width: "210px",
                  background: "#0B1120",
                  border: "1px solid #263449",
                  borderRadius: "8px",
                  padding: "10px 10px 10px 35px",
                  color: "#F8FAFC",
                  outline: "none"
                }}
              />
            </div>
          </div>

          {loading ? (
            <div
              style={{
                padding: "60px",
                textAlign: "center",
                color: "#64748B"
              }}
            >
              Loading incidents...
            </div>
          ) : filtered.length === 0 ? (
            <div
              style={{
                padding: "60px",
                textAlign: "center"
              }}
            >
              <CheckCircle
                size={42}
                color="#22C55E"
                style={{ marginBottom: "12px" }}
              />
              <h3 style={{ margin: 0 }}>No incidents found</h3>
            </div>
          ) : (
            filtered.map((incident) => (
              <IncidentRow
                key={incident.id}
                incident={incident}
                onClick={() => openIncident(incident)}
              />
            ))
          )}
        </section>

        <div
          style={{
            marginTop: "18px",
            display: "flex",
            justifyContent: "center",
            gap: "25px",
            color: "#64748B",
            fontSize: "12px"
          }}
        >
          <span>
            Total: <b style={{ color: "#CBD5E1" }}>
              {incidents.length}
            </b>
          </span>

          <span>
            Resolved: <b style={{ color: "#22C55E" }}>
              {resolved}
            </b>
          </span>

          <span>
            Live monitoring: <b style={{ color: "#22C55E" }}>
              ACTIVE
            </b>
          </span>
        </div>

      {selectedIncident && (
        <div
          onClick={() => setSelectedIncident(null)}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            background: "rgba(2, 6, 23, 0.82)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "20px",
            overflowY: "auto"
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="incident-detail-title"
            onClick={(event) => event.stopPropagation()}
            style={{
              width: "100%",
              maxWidth: "680px",
              maxHeight: "90vh",
              overflowY: "auto",
              overscrollBehavior: "contain",
              display: "flex",
              flexDirection: "column",
              background: "#0F172A",
              border: "1px solid #263449",
              borderRadius: "16px",
              padding: "24px",
              color: "#F8FAFC",
              boxShadow: "0 24px 80px rgba(0,0,0,0.45)"
            }}
          >
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
              gap: "16px",
              marginBottom: "22px"
            }}>
              <div>
                <div style={{
                  color: "#38BDF8",
                  fontSize: "11px",
                  fontWeight: 800,
                  letterSpacing: "1.5px",
                  marginBottom: "8px"
                }}>
                  SECURITY INCIDENT DETAILS
                </div>
                <h2 id="incident-detail-title" style={{
                  fontSize: "22px",
                  margin: 0,
                  overflowWrap: "anywhere"
                }}>
                  {selectedIncident.title || "Security Incident"}
                </h2>
                <p style={{ color: "#94A3B8", marginBottom: 0 }}>
                  Incident #{selectedIncident.id}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                aria-label="Close incident details"
                style={{
                  background: "#1E293B",
                  color: "#F8FAFC",
                  border: "1px solid #334155",
                  borderRadius: "8px",
                  padding: "8px",
                  cursor: "pointer",
                  display: "flex"
                }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "12px",
              marginBottom: "20px"
            }}>
              {[
                ["Severity", selectedIncident.severity],
                ["Status", selectedIncident.status],
                ["Risk Score", selectedIncident.risk_score],
                ["Threat Type", selectedIncident.threat_type],
                ["Source IP", selectedIncident.source_ip],
                ["Destination IP", selectedIncident.destination_ip],
                ["Created At", selectedIncident.created_at],
                ["Description", selectedIncident.description]
              ].map(([label, value]) => (
                <div key={label} style={{
                  background: "#111827",
                  border: "1px solid #263449",
                  borderRadius: "10px",
                  padding: "14px",
                  minWidth: 0
                }}>
                  <div style={{
                    color: "#64748B",
                    fontSize: "12px",
                    fontWeight: 700,
                    marginBottom: "8px"
                  }}>
                    {label}
                  </div>
                  <div style={{
                    color: "#E2E8F0",
                    fontSize: "14px",
                    fontWeight: 600,
                    overflowWrap: "anywhere"
                  }}>
                    {value === null || value === undefined || value === ""
                      ? "Not available"
                      : typeof value === "object"
                        ? JSON.stringify(value)
                        : String(value)}
                  </div>
                </div>
              ))}
            </div>



            <button
              type="button"
              onClick={() => setShowIncidentTimeline((shown) => !shown)}
              style={{
                marginBottom: "16px",
                background: "#111827",
                color: "#BAE6FD",
                border: "1px solid #263449",
                borderRadius: "8px",
                padding: "9px 12px",
                fontWeight: 700,
                cursor: "pointer"
              }}
            >
              {showIncidentTimeline ? "Hide Activity Timeline" : "Show Activity Timeline"}
            </button>

            {showIncidentTimeline && <div style={{
              marginBottom: "14px",
              padding: "14px",
              height: "180px",
              minHeight: "180px",
              boxSizing: "border-box",
              overflowY: "auto",
              flexShrink: 0,
              background: "#111827",
              border: "1px solid #263449",
              borderRadius: "12px"
            }}>
              <div style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "12px",
                marginBottom: "14px"
              }}>
                <h3 style={{ margin: 0, fontSize: "16px", color: "#E2E8F0" }}>
                  Incident Activity Timeline
                </h3>
                <button
                  type="button"
                  onClick={() => loadIncidentAudit(selectedIncident)}
                  disabled={auditLoading}
                  style={{
                    background: "#1E293B",
                    color: "#BAE6FD",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                    padding: "7px 10px",
                    cursor: auditLoading ? "wait" : "pointer"
                  }}
                >
                  {auditLoading ? "Refreshing..." : "Refresh"}
                </button>
              </div>

              {auditLoading && (
                <p style={{ color: "#94A3B8", fontSize: "13px" }}>
                  Loading audit history...
                </p>
              )}

              {auditError && (
                <p role="alert" style={{ color: "#FCA5A5", fontSize: "13px" }}>
                  {auditError}
                </p>
              )}

              {!auditLoading && !auditError && incidentAuditLogs.length === 0 && (
                <p style={{ color: "#94A3B8", fontSize: "13px" }}>
                  No matching audit events found for this incident.
                </p>
              )}

              <div style={{ display: "grid", gap: "12px" }}>
                {incidentAuditLogs.map((log) => (
                  <div
                    key={log.id}
                    style={{
                      borderLeft: `3px solid ${
                        log.action === "BLOCK" || log.severity === "HIGH"
                          ? "#F87171"
                          : log.event_type === "INCIDENT_UPDATED"
                            ? "#38BDF8"
                            : "#64748B"
                      }`,
                      padding: "4px 0 4px 12px"
                    }}
                  >
                    <div style={{
                      display: "flex",
                      flexWrap: "wrap",
                      justifyContent: "space-between",
                      gap: "8px",
                      marginBottom: "5px"
                    }}>
                      <strong style={{ color: "#E2E8F0", fontSize: "13px" }}>
                        {String(log.event_type || "SECURITY EVENT").replaceAll("_", " ")}
                      </strong>
                      <span style={{ color: "#94A3B8", fontSize: "11px" }}>
                        {log.created_at
                          ? new Date(log.created_at).toLocaleString()
                          : "Time unavailable"}
                      </span>
                    </div>
                    <p style={{
                      color: "#CBD5E1",
                      fontSize: "13px",
                      lineHeight: 1.5,
                      margin: "0 0 6px",
                      overflowWrap: "anywhere"
                    }}>
                      {log.message || "No event details available."}
                    </p>
                    <span style={{
                      color: "#94A3B8",
                      fontSize: "11px"
                    }}>
                      Severity: {log.severity || "N/A"} · Action: {log.action || "N/A"}
                      {log.source_ip ? ` · Source: ${log.source_ip}` : ""}
                    </span>
                  </div>
                ))}
              </div>
            </div>}
            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: "16px",
              marginBottom: "22px"
            }}>
              <div>
                <label htmlFor="incident-status" style={{
                  display: "block",
                  marginBottom: "8px",
                  color: "#CBD5E1",
                  fontWeight: 700
                }}>
                  Investigation Status
                </label>
                <select
                  id="incident-status"
                  value={editStatus}
                  onChange={(e) => {
                    setEditStatus(e.target.value);
                    setSaveMessage("");
                  }}
                  style={{
                    width: "100%",
                    padding: "12px",
                    borderRadius: "8px",
                    background: "#111827",
                    color: "#F8FAFC",
                    border: "1px solid #334155"
                  }}
                >
                  <option value="OPEN">Open</option>
                  <option value="INVESTIGATING">Investigating</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                </select>
              </div>

              <div>
                <label htmlFor="incident-notes" style={{
                  display: "block",
                  marginBottom: "8px",
                  color: "#CBD5E1",
                  fontWeight: 700
                }}>
                  Analyst Investigation Notes
                </label>
                <textarea
                  id="incident-notes"
                  value={editNotes}
                  maxLength={5000}
                  rows={5}
                  placeholder="Record evidence, findings, and follow-up actions..."
                  onChange={(e) => {
                    setEditNotes(e.target.value);
                    setSaveMessage("");
                  }}
                  style={{
                    width: "100%",
                    boxSizing: "border-box",
                    padding: "12px",
                    borderRadius: "8px",
                    background: "#111827",
                    color: "#F8FAFC",
                    border: "1px solid #334155",
                    font: "inherit",
                    resize: "vertical"
                  }}
                />
                <div style={{
                  textAlign: "right",
                  color: "#64748B",
                  fontSize: "11px"
                }}>
                  {editNotes.length}/5000 characters
                </div>
              </div>
            </div>

            {saveMessage && (
              <p role="status" style={{
                color: saveMessage === "Changes saved successfully."
                  ? "#4ADE80"
                  : "#FCA5A5"
              }}>
                {saveMessage}
              </p>
            )}

            <div style={{
              display: "flex",
              justifyContent: "flex-end",
              borderTop: "1px solid #263449",
              paddingTop: "18px",
              marginTop: "auto",
              position: "sticky",
              bottom: "0",
              background: "#0F172A",
              paddingBottom: "8px",
              zIndex: 2
            }}>
              <button
                type="button"
                onClick={saveIncident}
                disabled={saving}
                style={{
                  background: "#166534",
                  border: "1px solid #15803D",
                  color: "#F8FAFC",
                  borderRadius: "8px",
                  padding: "10px 18px",
                  fontWeight: 700,
                  cursor: saving ? "wait" : "pointer"
                }}
              >
                {saving ? "Saving..." : "Save Changes"}
              </button>
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                style={{
                  background: "#164E63",
                  border: "1px solid #0E7490",
                  color: "#F8FAFC",
                  borderRadius: "8px",
                  padding: "10px 18px",
                  fontWeight: 700,
                  cursor: "pointer"
                }}
              >
                Close Details
              </button>
            </div>
          </section>
        </div>
      )}

      </div>
    </PageLayout>
  );
}

function IncidentRow({ incident, onClick }) {
  const isCritical = incident.severity === "CRITICAL";
  const isHigh = incident.severity === "HIGH";

  const color = isCritical
    ? "#EF4444"
    : isHigh
      ? "#F97316"
      : "#F59E0B";

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`Open incident ${incident.id}: ${incident.title || "Security Incident"}`}
      onClick={onClick}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onClick();
        }
      }}
      title="Click to view incident details"
      style={{
        cursor: "pointer",
        padding: "18px 22px",
        borderBottom: "1px solid #1E293B",
        display: "flex",
        alignItems: "center",
        gap: "16px"
      }}
    >
      <div
        style={{
          width: "42px",
          height: "42px",
          borderRadius: "9px",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: `${color}18`,
          color
        }}
      >
        <AlertTriangle size={21} />
      </div>

      <div style={{ flex: 1 }}>
        <div
          style={{
            fontWeight: 800,
            color: "#F8FAFC"
          }}
        >
          {incident.title || "Security Incident"}
        </div>

        <div
          style={{
            marginTop: "5px",
            color: "#64748B",
            fontSize: "12px"
          }}
        >
          Incident #{incident.id} • Risk Score{" "}
          {incident.risk_score ?? "N/A"}
        </div>
      </div>

      <span
        style={{
          padding: "6px 11px",
          borderRadius: "6px",
          background: `${color}18`,
          color,
          fontSize: "11px",
          fontWeight: 900
        }}
      >
        {incident.severity}
      </span>

      <span
        style={{
          minWidth: "75px",
          textAlign: "center",
          color:
            incident.status === "RESOLVED" ||
            incident.status === "CLOSED"
              ? "#22C55E"
              : "#F59E0B",
          fontSize: "11px",
          fontWeight: 900
        }}
      >
        {incident.status || "OPEN"}
      </span>
    </div>
  );
}

function Stat({ icon, title, value, color }) {
  return (
    <div
      style={{
        background: "#111827",
        border: "1px solid #1E293B",
        borderRadius: "12px",
        padding: "19px"
      }}
    >
      <div style={{ color }}>{icon}</div>

      <div
        style={{
          color: "#64748B",
          fontSize: "12px",
          fontWeight: 700,
          marginTop: "14px"
        }}
      >
        {title}
      </div>

      <div
        style={{
          fontSize: "25px",
          fontWeight: 900,
          marginTop: "5px"
        }}
      >
        {value}
      </div>
    </div>
  );
}
