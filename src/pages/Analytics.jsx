import { API_BASE as API } from "../api";
import PageLayout from "../components/PageLayout";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  BarChart3,
  ShieldAlert,
  Ban,
  Activity,
  Target,
  RefreshCw,
  TrendingUp
} from "lucide-react";

const investigationInputStyle = {
  width: "100%",
  minWidth: 0,
  boxSizing: "border-box",
  background: "#0B1120",
  color: "#E2E8F0",
  border: "1px solid #263449",
  borderRadius: "8px",
  padding: "10px 11px",
  fontSize: "12px",
};

const investigationButtonStyle = {
  background: "#0B1120",
  color: "#CBD5E1",
  border: "1px solid #263449",
  borderRadius: "8px",
  padding: "9px 11px",
  fontSize: "12px",
  fontWeight: 700,
  cursor: "pointer",
};

export default function Analytics() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [score, setScore] = useState(null);
  const [logs, setLogs] = useState([]);
  const [activeBlocks, setActiveBlocks] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [selectedSourceIp, setSelectedSourceIp] = useState("");
  const [actionFilter, setActionFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [ipSearch, setIpSearch] = useState("");


  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const loadAnalytics = async () => {
    try {
      setRefreshing(true);

      const [analyticsResponse, scoreResponse] = await Promise.all([
        fetch(`${API}/api/analytics/summary`),
        fetch(`${API}/api/security-score`)
      ]);

      if (!analyticsResponse.ok || !scoreResponse.ok) {
        throw new Error("Analytics API request failed");
      }

      const analytics = await analyticsResponse.json();
      const securityScore = await scoreResponse.json();

      setData(analytics);
      setScore(securityScore);
      const [logsResult, blocksResult, incidentsResult] = await Promise.allSettled([
        fetch(`${API}/api/logs`).then((r) => {
          if (!r.ok) throw new Error("Audit log request failed");
          return r.json();
        }),
        fetch(`${API}/api/firewall/blocks`).then((r) => {
          if (!r.ok) throw new Error("Temporary block request failed");
          return r.json();
        }),
        fetch(`${API}/api/incidents`).then((r) => {
          if (!r.ok) throw new Error("Incident request failed");
          return r.json();
        }),
      ]);

      if (logsResult.status === "fulfilled") {
        setLogs(Array.isArray(logsResult.value) ? logsResult.value : []);
      }

      if (blocksResult.status === "fulfilled") {
        const value = blocksResult.value;
        setActiveBlocks(Array.isArray(value.blocks) ? value.blocks : []);
      }

      if (incidentsResult.status === "fulfilled") {
        setIncidents(Array.isArray(incidentsResult.value) ? incidentsResult.value : []);
      }
      setError("");
    } catch (err) {
      console.error(err);
      setError("Unable to connect to SecureX AI analytics.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadAnalytics();

    const interval = setInterval(loadAnalytics, 10000);

    return () => clearInterval(interval);
  }, []);

  const severity = data?.severity || {};

  const maxSeverity = Math.max(
    severity.critical || 0,
    severity.high || 0,
    severity.medium || 0,
    severity.low || 0,
    1
  );

  const threatTypes = Object.entries(data?.threat_types || {});

  const isBlockedEvent = (item) => {
    const action = String(item.action || "").toUpperCase();
    const type = String(item.event_type || "").toUpperCase();
    return action === "BLOCK" || type.includes("BLOCK");
  };

  const isAllowedEvent = (item) =>
    String(item.action || "").toUpperCase() === "ALLOW";

  const blockedLogCount = logs.filter(isBlockedEvent).length;
  const allowedLogCount = logs.filter(isAllowedEvent).length;
  const recordedBlockRate = logs.length
    ? Math.round((blockedLogCount / logs.length) * 100)
    : 0;

  const topBlockedSources = Object.entries(
    logs.reduce((acc, item) => {
      if (!isBlockedEvent(item)) return acc;
      const ip = String(item.source_ip || "").trim();
      if (!ip) return acc;
      acc[ip] = (acc[ip] || 0) + 1;
      return acc;
    }, {})
  )
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const unresolvedIncidents = incidents.filter(
    (incident) => !["RESOLVED", "FALSE_POSITIVE"].includes(
      String(incident.status || "OPEN").toUpperCase()
    )
  );

  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const priorityIncident = [...unresolvedIncidents].sort((a, b) =>
    (severityRank[String(b.severity || "").toUpperCase()] || 0) -
      (severityRank[String(a.severity || "").toUpperCase()] || 0) ||
    (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0)
  )[0];

  const repeatedSource = topBlockedSources[0];
  const priorityEvidence = priorityIncident
    ? logs.filter((item) =>
        priorityIncident.source_ip &&
        String(item.source_ip || "") === String(priorityIncident.source_ip)
      ).slice(0, 3)
    : [];

  const investigationRecommendations = [];
  if (priorityIncident) {
    investigationRecommendations.push(
      `Review incident #${priorityIncident.id} and validate its source, destination, and evidence.`
    );
  }
  if (repeatedSource && repeatedSource.count >= 2) {
    investigationRecommendations.push(
      `Review ${repeatedSource.ip}, recorded in ${repeatedSource.count} blocked audit events.`
    );
  }
  if (activeBlocks.length > 0) {
    investigationRecommendations.push(
      `Review ${activeBlocks.length} active temporary block(s) and their expiry times.`
    );
  }
  if (!investigationRecommendations.length) {
    investigationRecommendations.push(
      "Continue monitoring. No unresolved incident or repeated blocked source is currently available."
    );
  }

  const decisionMax = Math.max(blockedLogCount, allowedLogCount, 1);

  const filteredLogs = logs.filter((item) => {
    const action = String(item.action || "").toUpperCase();
    const severityValue = String(item.severity || "").toUpperCase();
    const ip = String(item.source_ip || "");
    const query = ipSearch.trim().toLowerCase();

    if (actionFilter === "BLOCK" && !isBlockedEvent(item)) return false;
    if (actionFilter === "ALLOW" && !isAllowedEvent(item)) return false;
    if (actionFilter === "MFA" && action !== "MFA") return false;
    if (severityFilter !== "ALL" && severityValue !== severityFilter) return false;
    if (selectedSourceIp && ip !== selectedSourceIp) return false;
    if (query && !ip.toLowerCase().includes(query)) return false;

    return true;
  });

  function exportFilteredCsv() {
    const columns = [
      ["id", "ID"],
      ["created_at", "Timestamp"],
      ["event_type", "Event"],
      ["source_ip", "Source IP"],
      ["action", "Action"],
      ["severity", "Severity"],
      ["message", "Message"],
    ];

    const escapeCsv = (value) => {
      const text = value == null ? "" : String(value);
      return '"' + text.replace(/"/g, '""') + '"';
    };

    const rows = [
      columns.map(([, label]) => escapeCsv(label)).join(","),
      ...filteredLogs.map((item) =>
        columns.map(([key]) => escapeCsv(item[key])).join(",")
      ),
    ];

    const blob = new Blob(["\uFEFF", rows.join("\r\n")], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinelai-investigation-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function clearInvestigationFilters() {
    setSelectedSourceIp("");
    setActionFilter("ALL");
    setSeverityFilter("ALL");
    setIpSearch("");
  }



  return (
    <PageLayout title="Security Analytics">
      <div style={{ width: "100%", minWidth: 0 }}>
        {/* Header */}
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
              SECURITY CONSOLE
            </div>

            <h1 style={{ margin: "7px 0 0", fontSize: "30px" }}>
              Security Analytics
            </h1>

            <p style={{ color: "#94A3B8", marginTop: "8px" }}>
              AI threat intelligence, risk analysis and security performance
            </p>
          </div>

          <button
            onClick={loadAnalytics}
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

        {/* Top stats */}
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
            title="Total Threats"
            value={data?.total_threats ?? 0}
            color="#00D4FF"
          />

          <Stat
            icon={<Ban />}
            title="Blocked Attacks"
            value={data?.blocked ?? 0}
            color="#EF4444"
          />

          <Stat
            icon={<Activity />}
            title="MFA Decisions"
            value={data?.mfa ?? 0}
            color="#F59E0B"
          />

          <Stat
            icon={<Target />}
            title="Security Score"
            value={`${score?.score ?? 0}/100`}
            color="#22C55E"
          />
        </div>

        {/* LIVE DASHBOARD INSIGHTS */}
        <section
          aria-label="Live dashboard insights"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 320px), 1fr))",
            gap: "20px",
            marginBottom: "20px"
          }}
        >
          <section style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "22px",
            minWidth: 0
          }}>
            <h2 style={{ margin: "0 0 8px", fontSize: "18px" }}>
              <Activity size={19} color="#00D4FF" /> Threat Activity
            </h2>
            <p style={{ color: "#64748B", fontSize: "12px" }}>
              Recorded ALLOW and BLOCK events over the last six hours.
            </p>
            <div style={{ display: "flex", gap: "16px", fontSize: "12px", margin: "16px 0" }}>
              <span style={{ color: "#34D399" }}>● ALLOW</span>
              <span style={{ color: "#F87171" }}>● BLOCK</span>
            </div>
            <div style={{ display: "grid", gap: "14px" }}>
              {(() => {
                const validEvents = logs
                  .map((item) => ({
                    item,
                    timestamp: new Date(item.created_at)
                  }))
                  .filter(({ timestamp }) => !Number.isNaN(timestamp.getTime()))
                  .filter(({ item }) => isAllowedEvent(item) || isBlockedEvent(item))
                  .sort((a, b) => a.timestamp - b.timestamp);

                const latestTimestamp = validEvents.length
                  ? validEvents[validEvents.length - 1].timestamp
                  : new Date();

                const latestHour = new Date(latestTimestamp);
                latestHour.setMinutes(0, 0, 0);

                const firstEventTime = validEvents.length
                  ? validEvents[0].timestamp.getTime()
                  : latestHour.getTime();

                const windowStart = new Date(
                  Math.min(
                    latestHour.getTime() - 5 * 60 * 60 * 1000,
                    firstEventTime
                  )
                );
                windowStart.setMinutes(0, 0, 0);

                const hourCount = Math.min(
                  6,
                  Math.max(
                    1,
                    Math.floor(
                      (latestHour.getTime() - windowStart.getTime()) /
                      (60 * 60 * 1000)
                    ) + 1
                  )
                );

                const buckets = Array.from({ length: hourCount }, (_, index) => {
                  const start = new Date(
                    latestHour.getTime() -
                    (hourCount - 1 - index) * 60 * 60 * 1000
                  );
                  const end = new Date(start.getTime() + 60 * 60 * 1000);

                  const events = validEvents.filter(({ timestamp }) =>
                    timestamp >= start && timestamp < end
                  );

                  return {
                    start,
                    allowed: events.filter(({ item }) => isAllowedEvent(item)).length,
                    blocked: events.filter(({ item }) => isBlockedEvent(item)).length
                  };
                });

                const maxCount = Math.max(
                  1,
                  ...buckets.map((bucket) => bucket.allowed + bucket.blocked)
                );

                return buckets.map((bucket) => {
                  const total = bucket.allowed + bucket.blocked;
                  const allowedWidth = bucket.allowed / maxCount * 100;
                  const blockedWidth = bucket.blocked / maxCount * 100;

                  return (
                    <div key={bucket.start.toISOString()}>
                      <div style={{
                        display: "flex",
                        justifyContent: "space-between",
                        color: "#94A3B8",
                        fontSize: "11px",
                        marginBottom: "6px"
                      }}>
                        <span>
                          {bucket.start.toLocaleDateString([], {
                            month: "short",
                            day: "numeric"
                          })}{" "}
                          {bucket.start.toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit"
                          })}
                        </span>
                        <span>{total} events</span>
                      </div>

                      <div style={{
                        display: "flex",
                        height: "12px",
                        background: "#263449",
                        borderRadius: "5px",
                        overflow: "hidden"
                      }}>
                        <div
                          title={`ALLOW ${bucket.allowed}`}
                          style={{
                            width: `${allowedWidth}%`,
                            background: "#34D399"
                          }}
                        />
                        <div
                          title={`BLOCK ${bucket.blocked}`}
                          style={{
                            width: `${blockedWidth}%`,
                            background: "#F87171"
                          }}
                        />
                      </div>
                    </div>
                  );
                });
              })()}
            </div>
            <p style={{ color: "#64748B", fontSize: "11px", marginBottom: 0 }}>
              From the {logs.length} audit records currently returned by the API.
            </p>
          </section>

          <section style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "22px",
            minWidth: 0
          }}>
            <h2 style={{ margin: "0 0 8px", fontSize: "18px" }}>
              <BarChart3 size={19} color="#00D4FF" /> Severity Distribution
            </h2>
            <p style={{ color: "#64748B", fontSize: "12px" }}>
              Threat counts reported by the analytics API.
            </p>
            {[
              { label: "Critical", value: Number(severity.critical || 0), color: "#FB7185" },
              { label: "High", value: Number(severity.high || 0), color: "#F87171" },
              { label: "Medium", value: Number(severity.medium || 0), color: "#FBBF24" },
              { label: "Low", value: Number(severity.low || 0), color: "#34D399" }
            ].map((item) => {
              const total = Math.max(
                1,
                Number(severity.critical || 0) +
                Number(severity.high || 0) +
                Number(severity.medium || 0) +
                Number(severity.low || 0)
              );
              return (
                <div key={item.label} style={{ marginTop: "20px" }}>
                  <div style={{
                    display: "flex",
                    justifyContent: "space-between",
                    marginBottom: "7px",
                    fontSize: "13px"
                  }}>
                    <span style={{ color: "#CBD5E1" }}>{item.label}</span>
                    <strong style={{ color: item.color }}>{item.value}</strong>
                  </div>
                  <div style={{
                    height: "8px",
                    background: "#263449",
                    borderRadius: "99px",
                    overflow: "hidden"
                  }}>
                    <div style={{
                      width: `${item.value / total * 100}%`,
                      height: "100%",
                      background: item.color
                    }} />
                  </div>
                </div>
              );
            })}
          </section>

          <section style={{
            gridColumn: "1 / -1",
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "22px"
          }}>
            <h2 style={{ margin: "0 0 8px", fontSize: "18px" }}>
              <ShieldAlert size={19} color="#00D4FF" /> Investigation Summary
            </h2>
            <p style={{ color: "#64748B", fontSize: "12px" }}>
              A quick view of current incidents and security activity.
            </p>
            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(155px, 1fr))",
              gap: "12px",
              marginTop: "18px"
            }}>
              {[
                {
                  label: "Total threats",
                  value: data?.total_threats ?? 0,
                  color: "#38BDF8"
                },
                {
                  label: "Blocked attacks",
                  value: data?.blocked ?? 0,
                  color: "#FB7185"
                },
                {
                  label: "Active temporary blocks",
                  value: activeBlocks.length,
                  color: "#F87171"
                },
                {
                  label: "Audit records loaded",
                  value: logs.length,
                  color: "#A78BFA"
                }
              ].map((item) => (
                <div key={item.label} style={{
                  background: "#0B1120",
                  border: "1px solid #263449",
                  borderRadius: "10px",
                  padding: "16px"
                }}>
                  <div style={{
                    color: "#94A3B8",
                    fontSize: "12px",
                    minHeight: "36px"
                  }}>{item.label}</div>
                  <div style={{
                    color: item.color,
                    fontSize: "28px",
                    fontWeight: 800,
                    marginTop: "8px"
                  }}>{item.value}</div>
                </div>
              ))}
            </div>
          </section>
        </section>

        {/* INVESTIGATION INTELLIGENCE BRIEFING */}
        <section style={{
          background: "#111827",
          border: "1px solid #334155",
          borderRadius: "14px",
          padding: "22px",
          marginBottom: "22px"
        }}>
          <h2 style={{ margin: "0 0 8px", fontSize: "19px", color: "#E2E8F0" }}>
            <ShieldAlert size={20} color="#00D4FF" /> Investigation Intelligence Briefing
          </h2>
          <p style={{ color: "#94A3B8", fontSize: "12px", lineHeight: 1.7 }}>
            Rule-based priorities from the latest incident, audit-log, and temporary-block data.
          </p>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "14px"
          }}>
            <div
              role={priorityIncident ? "button" : undefined}
              tabIndex={priorityIncident ? 0 : undefined}
              onClick={() => {
                if (priorityIncident) navigate(`/incidents?id=${priorityIncident.id}`);
              }}
              onKeyDown={(event) => {
                if (priorityIncident && (event.key === "Enter" || event.key === " ")) {
                  event.preventDefault();
                  navigate(`/incidents?id=${priorityIncident.id}`);
                }
              }}
              style={{
                background: "#0B1120",
                border: "1px solid #7F1D1D",
                borderRadius: "10px",
                padding: "16px",
                cursor: priorityIncident ? "pointer" : "default",
                outlineOffset: "3px"
              }}
            >
              <strong style={{ color: "#FCA5A5", fontSize: "12px" }}>PRIORITY INCIDENT</strong>
              {priorityIncident ? (
                <>
                  <h3 style={{ color: "#F8FAFC", fontSize: "15px" }}>
                    {priorityIncident.title || `Incident #${priorityIncident.id}`}
                  </h3>
                  <p style={{ color: "#CBD5E1", fontSize: "12px", lineHeight: 1.8 }}>
                    Incident: #{priorityIncident.id}<br />
                    Severity: {String(priorityIncident.severity || "UNKNOWN").toUpperCase()}<br />
                    Status: {String(priorityIncident.status || "OPEN").replaceAll("_", " ")}<br />
                    Risk score: {priorityIncident.risk_score ?? "Not recorded"}<br />
                    Source: {priorityIncident.source_ip || "Not recorded"}<br />
                    Destination: {priorityIncident.destination_ip || "Not recorded"}
                  </p>
                  {priorityIncident.description && (
                    <p style={{ color: "#94A3B8", fontSize: "12px" }}>
                      {priorityIncident.description}
                    </p>
                  )}
                  {priorityIncident.notes && (
                    <p style={{ color: "#A5B4FC", fontSize: "12px" }}>
                      Analyst notes: {priorityIncident.notes}
                    </p>
                  )}
                </>
              ) : (
                <p style={{ color: "#94A3B8", fontSize: "13px" }}>
                  No unresolved incident is available in the latest incident response.
                </p>
              )}
            </div>

            <div
              role="button"
              tabIndex={0}
              onClick={() => navigate(`/logs?source=${encodeURIComponent(repeatedSource?.ip || "")}`)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  navigate(`/logs?source=${encodeURIComponent(repeatedSource?.ip || "")}`);
                }
              }}
              style={{ background: "#0B1120", border: "1px solid #263449", borderRadius: "10px", padding: "16px", cursor: "pointer" }}
            >
              <strong style={{ color: "#FBBF24", fontSize: "12px" }}>REPEATED BLOCKED SOURCE</strong>
              {repeatedSource ? (
                <>
                  <h3 style={{ color: "#F8FAFC", fontSize: "19px" }}>{repeatedSource.ip}</h3>
                  <p style={{ color: "#CBD5E1", fontSize: "13px" }}>
                    {repeatedSource.count} blocked event(s) among the loaded audit records.
                  </p>
                  <p style={{ color: "#94A3B8", fontSize: "12px" }}>
                    Repeated blocks warrant investigation but do not alone prove malicious intent.
                  </p>
                </>
              ) : (
                <p style={{ color: "#94A3B8", fontSize: "13px" }}>
                  No blocked source IP is present in the loaded audit records.
                </p>
              )}
            </div>

            <div
              role="button"
              tabIndex={0}
              onClick={() => navigate("/incidents")}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  navigate("/incidents");
                }
              }}
              style={{ background: "#0B1120", border: "1px solid #263449", borderRadius: "10px", padding: "16px", cursor: "pointer" }}
            >
              <strong style={{ color: "#67E8F9", fontSize: "12px" }}>EVIDENCE SUMMARY</strong>
              <p style={{ color: "#CBD5E1", fontSize: "13px", lineHeight: 1.9 }}>
                Incidents loaded: {incidents.length}<br />
                Unresolved incidents: {unresolvedIncidents.length}<br />
                Audit records loaded: {logs.length}<br />
                Blocked audit events: {blockedLogCount}<br />
                Active temporary blocks: {activeBlocks.length}
              </p>
              {priorityIncident && (
                <p style={{ color: "#94A3B8", fontSize: "12px", lineHeight: 1.7 }}>
                  Matching audit events for priority source: {priorityEvidence.length}
                  {priorityEvidence[0] && (
                    <>
                      <br />
                      Latest matching event: {priorityEvidence[0].event_type || priorityEvidence[0].action || "Recorded event"}
                    </>
                  )}
                </p>
              )}
            </div>
          </div>

          <div style={{ marginTop: "16px", background: "#0B1120", border: "1px solid #263449", borderRadius: "10px", padding: "16px" }}>
            <h3 style={{ color: "#E2E8F0", fontSize: "14px", marginTop: 0 }}>
              Recommended Investigation Actions
            </h3>
            <ol style={{ color: "#CBD5E1", fontSize: "13px", lineHeight: 1.9, paddingLeft: "20px" }}>
              {investigationRecommendations.map((item, index) => (
                <li key={`${index}-${item}`}>{item}</li>
              ))}
            </ol>
            <p style={{ color: "#64748B", fontSize: "11px", lineHeight: 1.6, marginBottom: 0 }}>
              Recommendations are rule-based, not autonomous AI conclusions. Verify evidence and policy before taking action.
            </p>
          </div>
        </section>

        {/* AI metrics */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "20px",
            marginBottom: "20px"
          }}
        >
          <section
            style={{
              background: "#111827",
              border: "1px solid #1E293B",
              borderRadius: "14px",
              padding: "23px"
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px"
              }}
            >
              <Activity color="#00D4FF" />
              <h2 style={{ margin: 0, fontSize: "19px" }}>
                AI Detection Metrics
              </h2>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "14px",
                marginTop: "20px"
              }}
            >
              <Metric
                label="Average Risk"
                value={`${data?.average_risk ?? 0}/100`}
              />

              <Metric
                label="Average Anomaly"
                value={`${data?.average_anomaly ?? 0}/100`}
              />

              <Metric
                label="Blocked Ratio"
                value={
                  data?.total_threats
                    ? `${Math.round(
                        (data.blocked / data.total_threats) * 100
                      )}%`
                    : "0%"
                }
              />

              <Metric
                label="Security Status"
                value={score?.status || "SECURE"}
              />
            </div>
          </section>

          {/* Risk distribution */}
          <section
            style={{
              background: "#111827",
              border: "1px solid #1E293B",
              borderRadius: "14px",
              padding: "23px"
            }}
          >
            <h2 style={{ margin: 0, fontSize: "19px" }}>
              Risk Distribution
            </h2>

            <p
              style={{
                color: "#64748B",
                fontSize: "13px",
                marginTop: "5px"
              }}
            >
              Threat severity across detected events
            </p>

            <RiskBar
              label="Critical"
              value={severity.critical || 0}
              max={maxSeverity}
              color="#EF4444"
            />

            <RiskBar
              label="High"
              value={severity.high || 0}
              max={maxSeverity}
              color="#F97316"
            />

            <RiskBar
              label="Medium"
              value={severity.medium || 0}
              max={maxSeverity}
              color="#F59E0B"
            />

            <RiskBar
              label="Low"
              value={severity.low || 0}
              max={maxSeverity}
              color="#22C55E"
            />
          </section>
        </div>

        {/* Threat types */}
        <section
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "23px",
            marginBottom: "20px"
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px"
            }}
          >
            <BarChart3 color="#00D4FF" />
            <div>
              <h2 style={{ margin: 0, fontSize: "19px" }}>
                Threat Categories
              </h2>
              <p
                style={{
                  margin: "5px 0 0",
                  color: "#64748B",
                  fontSize: "13px"
                }}
              >
                Distribution of detected attack types
              </p>
            </div>
          </div>

          {threatTypes.length === 0 ? (
            <div
              style={{
                marginTop: "20px",
                padding: "35px",
                textAlign: "center",
                color: "#64748B",
                border: "1px dashed #263449",
                borderRadius: "9px"
              }}
            >
              No threat categories available.
            </div>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                gap: "14px",
                marginTop: "20px"
              }}
            >
              {threatTypes.map(([name, count]) => {
                const percentage = data.total_threats
                  ? Math.round((count / data.total_threats) * 100)
                  : 0;

                return (
                  <div
                    key={name}
                    style={{
                      background: "#0B1120",
                      border: "1px solid #1E293B",
                      borderRadius: "10px",
                      padding: "16px"
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center"
                      }}
                    >
                      <span
                        style={{
                          fontWeight: 800,
                          color: "#CBD5E1"
                        }}
                      >
                        {name}
                      </span>

                      <span
                        style={{
                          color: "#00D4FF",
                          fontWeight: 900
                        }}
                      >
                        {count}
                      </span>
                    </div>

                    <div
                      style={{
                        height: "6px",
                        background: "#1E293B",
                        borderRadius: "99px",
                        marginTop: "12px",
                        overflow: "hidden"
                      }}
                    >
                      <div
                        style={{
                          width: `${percentage}%`,
                          height: "100%",
                          background: "#00D4FF"
                        }}
                      />
                    </div>

                    <div
                      style={{
                        marginTop: "7px",
                        color: "#64748B",
                        fontSize: "11px"
                      }}
                    >
                      {percentage}% of detected threats
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>


        {/* Firewall decision analytics */}
        <section style={{
          background: "#111827",
          border: "1px solid #1E293B",
          borderRadius: "14px",
          padding: "23px",
          marginBottom: "20px",
        }}>
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "12px",
            flexWrap: "wrap",
          }}>
            <div>
              <h2 style={{ margin: 0, fontSize: "19px" }}>
                <Activity color="#00D4FF" size={20} /> Firewall Decision Analytics
              </h2>
              <p style={{ color: "#64748B", fontSize: "13px", marginTop: "6px" }}>
                Based on the latest {logs.length} audit records returned by the backend.
              </p>
            </div>
            <div style={{
              padding: "7px 11px",
              borderRadius: "99px",
              border: "1px solid #164E63",
              color: "#67E8F9",
              fontSize: "12px",
              fontWeight: 800,
            }}>
              {activeBlocks.length} ACTIVE TEMPORARY BLOCKS
            </div>
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))",
            gap: "14px",
            marginTop: "18px",
          }}>
            <div style={{
              background: "#0B1120",
              border: "1px solid #263449",
              borderRadius: "10px",
              padding: "16px",
            }}>
              <div style={{ color: "#94A3B8", fontSize: "12px" }}>Recorded ALLOW events</div>
              <div style={{ color: "#4ADE80", fontSize: "27px", fontWeight: 900, marginTop: "7px" }}>
                {allowedLogCount}
              </div>
            </div>
            <div style={{
              background: "#0B1120",
              border: "1px solid #263449",
              borderRadius: "10px",
              padding: "16px",
            }}>
              <div style={{ color: "#94A3B8", fontSize: "12px" }}>Recorded BLOCK events</div>
              <div style={{ color: "#F87171", fontSize: "27px", fontWeight: 900, marginTop: "7px" }}>
                {blockedLogCount}
              </div>
            </div>
            <div style={{
              background: "#0B1120",
              border: "1px solid #263449",
              borderRadius: "10px",
              padding: "16px",
            }}>
              <div style={{ color: "#94A3B8", fontSize: "12px" }}>Block rate in returned logs</div>
              <div style={{ color: "#22D3EE", fontSize: "27px", fontWeight: 900, marginTop: "7px" }}>
                {recordedBlockRate}%
              </div>
            </div>
          </div>

          <div style={{ marginTop: "22px" }}>
            <div style={{ color: "#CBD5E1", fontWeight: 800, marginBottom: "14px" }}>
              ALLOW vs BLOCK
            </div>
            {[
              { label: "Allowed", value: allowedLogCount, color: "#22C55E" },
              { label: "Blocked", value: blockedLogCount, color: "#EF4444" },
            ].map((item) => (
              <div key={item.label} style={{ marginBottom: "14px" }}>
                <div style={{
                  display: "flex",
                  justifyContent: "space-between",
                  color: "#94A3B8",
                  fontSize: "13px",
                  marginBottom: "7px",
                }}>
                  <span>{item.label}</span>
                  <strong style={{ color: item.color }}>{item.value}</strong>
                </div>
                <div style={{
                  height: "9px",
                  background: "#263449",
                  borderRadius: "99px",
                  overflow: "hidden",
                }}>
                  <div style={{
                    height: "100%",
                    width: `${(item.value / decisionMax) * 100}%`,
                    background: item.color,
                    borderRadius: "99px",
                    transition: "width 250ms ease",
                  }} />
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Top blocked sources */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(min(100%,320px),1fr))",
          gap: "20px",
          marginBottom: "20px",
        }}>
          <section style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "23px",
          }}>
            <h2 style={{ margin: 0, fontSize: "19px" }}>
              <Ban color="#F87171" size={20} /> Top Blocked Sources
            </h2>
            <p style={{ color: "#64748B", fontSize: "13px", marginTop: "6px" }}>
              Ranked by BLOCK events in the returned audit records.
            </p>

            {topBlockedSources.length === 0 ? (
              <div style={{
                padding: "24px 10px",
                textAlign: "center",
                color: "#64748B",
                border: "1px dashed #263449",
                borderRadius: "9px",
                marginTop: "16px",
              }}>
                No blocked source IPs found in these audit records.
              </div>
            ) : topBlockedSources.map((source, index) => (
              <div
                key={source.ip}
                role="button"
                tabIndex={0}
                aria-pressed={selectedSourceIp === source.ip}
                onClick={() => setSelectedSourceIp(
                  selectedSourceIp === source.ip ? "" : source.ip
                )}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setSelectedSourceIp(
                      selectedSourceIp === source.ip ? "" : source.ip
                    );
                  }
                }}
                title="Click to filter the timeline by this source IP"
                style={{
                  cursor: "pointer",
                  outline: selectedSourceIp === source.ip ? "1px solid #22D3EE" : "none",
                  outlineOffset: "3px",
                display: "flex",
                alignItems: "center",
                gap: "12px",
                padding: "13px 0",
                borderBottom: "1px solid #1E293B",
              }}>
                <div style={{
                  width: "30px",
                  height: "30px",
                  display: "grid",
                  placeItems: "center",
                  borderRadius: "8px",
                  background: "#3B1D29",
                  color: "#F87171",
                  fontWeight: 900,
                  flexShrink: 0,
                }}>{index + 1}</div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    color: "#E2E8F0",
                    fontFamily: "monospace",
                    overflowWrap: "anywhere",
                  }}>{source.ip}</div>
                  <div style={{
                    height: "5px",
                    background: "#263449",
                    borderRadius: "99px",
                    overflow: "hidden",
                    marginTop: "7px",
                  }}>
                    <div style={{
                      width: `${(source.count / topBlockedSources[0].count) * 100}%`,
                      height: "100%",
                      background: "#EF4444",
                    }} />
                  </div>
                </div>
                <strong style={{ color: "#F87171" }}>{source.count}</strong>
              </div>
            ))}
          </section>

          {/* Recent security timeline */}
          <section style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "23px",
          }}>
            <h2 style={{ margin: 0, fontSize: "19px" }}>
              <Activity color="#00D4FF" size={20} /> Security Event Timeline
            </h2>
            <p style={{ color: "#64748B", fontSize: "13px", marginTop: "6px" }}>
              Latest recorded audit events, newest first.
            </p>

            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
              gap: "10px",
              marginTop: "16px",
              marginBottom: "14px",
            }}>
              <input
                aria-label="Search source IP"
                placeholder="Search source IP..."
                value={ipSearch}
                onChange={(event) => setIpSearch(event.target.value)}
                style={investigationInputStyle}
              />
              <select
                aria-label="Filter by action"
                value={actionFilter}
                onChange={(event) => setActionFilter(event.target.value)}
                style={investigationInputStyle}
              >
                <option value="ALL">All actions</option>
                <option value="BLOCK">BLOCK</option>
                <option value="ALLOW">ALLOW</option>
                <option value="MFA">MFA</option>
              </select>
              <select
                aria-label="Filter by severity"
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value)}
                style={investigationInputStyle}
              >
                <option value="ALL">All severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
                <option value="WARNING">WARNING</option>
                <option value="INFO">INFO</option>
                <option value="ERROR">ERROR</option>
              </select>
            </div>

            <div style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "10px",
              flexWrap: "wrap",
              marginBottom: "12px",
            }}>
              <span style={{ color: "#94A3B8", fontSize: "12px" }}>
                Showing {filteredLogs.length} of {logs.length} returned audit records
                {selectedSourceIp ? ` · Source ${selectedSourceIp}` : ""}
              </span>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                <button
                  type="button"
                  onClick={clearInvestigationFilters}
                  style={investigationButtonStyle}
                >
                  Clear filters
                </button>
                <button
                  type="button"
                  onClick={exportFilteredCsv}
                  disabled={filteredLogs.length === 0}
                  style={{
                    ...investigationButtonStyle,
                    color: "#67E8F9",
                    borderColor: "#155E75",
                    opacity: filteredLogs.length === 0 ? 0.5 : 1,
                    cursor: filteredLogs.length === 0 ? "not-allowed" : "pointer",
                  }}
                >
                  Export filtered CSV
                </button>
              </div>
            </div>

            {filteredLogs.length === 0 ? (
              <div style={{
                padding: "24px 10px",
                textAlign: "center",
                color: "#64748B",
                border: "1px dashed #263449",
                borderRadius: "9px",
                marginTop: "16px",
              }}>
                {logs.length === 0 ? "No audit events are available." : "No events match the current filters."}
              </div>
            ) : (
              <div style={{ marginTop: "14px" }}>
                {filteredLogs.slice(0, 20).map((item, index) => {
                  const blocked = isBlockedEvent(item);
                  const timestamp = item.created_at
                    ? new Date(item.created_at).toLocaleString()
                    : "Time unavailable";

                  return (
                    <div key={item.id ?? `${item.event_type}-${index}`} style={{
                      display: "flex",
                      gap: "11px",
                      padding: "12px 0",
                      borderBottom: "1px solid #1E293B",
                    }}>
                      <div style={{
                        width: "9px",
                        height: "9px",
                        borderRadius: "50%",
                        background: blocked ? "#F87171" : "#22D3EE",
                        marginTop: "5px",
                        flexShrink: 0,
                      }} />
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{
                          display: "flex",
                          justifyContent: "space-between",
                          gap: "8px",
                          flexWrap: "wrap",
                        }}>
                          <strong style={{
                            color: blocked ? "#FCA5A5" : "#CBD5E1",
                            fontSize: "13px",
                          }}>
                            {item.event_type || item.action || "Security event"}
                          </strong>
                          <span style={{ color: "#64748B", fontSize: "11px" }}>
                            {timestamp}
                          </span>
                        </div>
                        <div style={{
                          color: "#94A3B8",
                          fontSize: "12px",
                          marginTop: "5px",
                          overflowWrap: "anywhere",
                        }}>
                          {item.message || "No event description"}
                        </div>
                        <div style={{
                          display: "flex",
                          gap: "10px",
                          flexWrap: "wrap",
                          marginTop: "5px",
                          color: "#64748B",
                          fontSize: "11px",
                        }}>
                          {item.source_ip && <span>IP: {item.source_ip}</span>}
                          {item.severity && <span>Severity: {item.severity}</span>}
                          {item.action && <span>Action: {item.action}</span>}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>

        {/* Pipeline */}
        <section
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "23px"
          }}
        >
          <h2 style={{ margin: 0, fontSize: "19px" }}>
            Security Analytics Pipeline
          </h2>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(5, 1fr)",
              gap: "12px",
              marginTop: "20px"
            }}
          >
            <Pipeline number="01" title="Traffic" />
            <Pipeline number="02" title="AI Detection" />
            <Pipeline number="03" title="Risk Scoring" />
            <Pipeline number="04" title="Zero Trust" />
            <Pipeline number="05" title="Response" />
          </div>
        </section>

        <div
          style={{
            marginTop: "18px",
            color: "#64748B",
            fontSize: "12px",
            textAlign: "center"
          }}
        >
          Live analytics • Auto-refresh every 10 seconds • SecureX AI
        </div>
      </div>
    </PageLayout>
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
          marginTop: "14px",
          color: "#64748B",
          fontSize: "12px",
          fontWeight: 700
        }}
      >
        {title}
      </div>

      <div
        style={{
          marginTop: "5px",
          fontSize: "25px",
          fontWeight: 900
        }}
      >
        {value}
      </div>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div
      style={{
        background: "#0B1120",
        border: "1px solid #1E293B",
        borderRadius: "9px",
        padding: "15px"
      }}
    >
      <div
        style={{
          color: "#64748B",
          fontSize: "11px",
          fontWeight: 800
        }}
      >
        {label}
      </div>

      <div
        style={{
          color: "#F8FAFC",
          fontSize: "21px",
          fontWeight: 900,
          marginTop: "6px"
        }}
      >
        {value}
      </div>
    </div>
  );
}

function RiskBar({ label, value, max, color }) {
  const width = Math.max(3, (value / max) * 100);

  return (
    <div style={{ marginTop: "17px" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: "12px",
          marginBottom: "6px"
        }}
      >
        <span style={{ color: "#CBD5E1" }}>{label}</span>
        <span style={{ color, fontWeight: 800 }}>{value}</span>
      </div>

      <div
        style={{
          height: "8px",
          background: "#1E293B",
          borderRadius: "99px",
          overflow: "hidden"
        }}
      >
        <div
          style={{
            width: `${width}%`,
            height: "100%",
            background: color,
            borderRadius: "99px"
          }}
        />
      </div>
    </div>
  );
}

function Pipeline({ number, title }) {
  return (
    <div
      style={{
        padding: "18px",
        textAlign: "center",
        background: "#0B1120",
        border: "1px solid #1E293B",
        borderRadius: "9px"
      }}
    >
      <div
        style={{
          color: "#00D4FF",
          fontSize: "11px",
          fontWeight: 900
        }}
      >
        {number}
      </div>

      <div
        style={{
          marginTop: "7px",
          fontWeight: 800,
          fontSize: "13px"
        }}
      >
        {title}
      </div>
    </div>
  );
}
