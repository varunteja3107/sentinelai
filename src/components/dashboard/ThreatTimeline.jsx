import { useCallback, useEffect, useMemo, useState } from "react";
import {
  BarChart,
  Bar,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Download, RefreshCw, Activity } from "lucide-react";
import { API_BASE as API } from "../../api";

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const severityColors = {
  CRITICAL: "#fb5475",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#4ade80",
};


function buildInvestigationReport(event) {
  const type = String(event.threat_type || "UNKNOWN").toUpperCase();
  const severity = String(event.severity || "UNKNOWN").toUpperCase();
  const action = String(event.action || "UNKNOWN").toUpperCase();

  const riskFactors = [
    `Recorded threat category: ${type}`,
    `Recorded severity: ${severity}`,
    `Recorded risk score: ${event.risk_score ?? "Not available"}`,
    `Recorded response action: ${action}`,
  ];

  const recommendations = [];

  if (/BRUTE|LOGIN|AUTH|CREDENTIAL/.test(type)) {
    recommendations.push(
      "Review authentication logs and identify repeated failed login attempts.",
      "Verify account activity and enforce multi-factor authentication.",
      "Consider rate limiting repeated authentication attempts."
    );
  } else if (/PORT.?SCAN|SCAN/.test(type)) {
    recommendations.push(
      "Review exposed ports and confirm that each service is required.",
      "Inspect network logs for follow-up connections from the source.",
      "Restrict unnecessary access using approved firewall policies."
    );
  } else if (/DDOS|DOS|FLOOD/.test(type)) {
    recommendations.push(
      "Review traffic volume and connection patterns around the event time.",
      "Consider rate limiting and upstream traffic mitigation.",
      "Check service availability and resource utilization."
    );
  } else if (/MALWARE|RANSOMWARE|TROJAN/.test(type)) {
    recommendations.push(
      "Review endpoint security logs for related indicators.",
      "Validate the detection before isolating an affected device.",
      "Follow the organization's malware containment and recovery procedure."
    );
  } else if (/BENIGN/.test(type)) {
    recommendations.push(
      "Review surrounding network activity to confirm the benign classification.",
      "Do not block traffic solely on the basis of this event label."
    );
  } else {
    recommendations.push(
      "Correlate this event with nearby network and security logs.",
      "Validate the source and destination before taking containment action.",
      "Apply approved firewall policies if the activity is confirmed malicious."
    );
  }

  if (severity === "CRITICAL" || severity === "HIGH") {
    recommendations.unshift(
      "Prioritize analyst review because the recorded severity is elevated."
    );
  }

  if (action === "BLOCK") {
    riskFactors.push("The recorded response action is BLOCK.");
    recommendations.push(
      "Verify that the block was effective and did not disrupt legitimate traffic."
    );
  } else if (action === "MFA") {
    riskFactors.push("The recorded response action is MFA.");
    recommendations.push(
      "Verify that the additional authentication challenge was completed successfully."
    );
  } else if (action === "ALLOW") {
    riskFactors.push("The recorded response action is ALLOW.");
    recommendations.push(
      "Confirm that allowing this traffic remains consistent with current security policy."
    );
  }

  if (event.is_test) {
    riskFactors.push(
      "This record is classified as a test event, not a confirmed live incident."
    );
    recommendations.unshift(
      "Treat this as a test or simulation record. Do not interpret it as proof of a live attack."
    );
  }

  const evidence = [
    `Event ID: ${event.id ?? "—"}`,
    `Threat type: ${event.threat_type || "—"}`,
    `Source IP: ${event.source_ip || "—"}`,
    `Destination IP: ${event.destination_ip || "—"}`,
    `Destination port: ${event.port ?? "—"}`,
    `Protocol: ${event.protocol || "—"}`,
    `Risk score: ${event.risk_score ?? "—"}`,
    `Severity: ${event.severity || "—"}`,
    `Action: ${event.action || "—"}`,
    `Status: ${event.status || "—"}`,
    `Recorded at: ${event.created_at || "—"}`,
    `Classification: ${event.is_test ? "TEST EVENT" : "LIVE EVENT"}`,
  ];

  const reportText = [
    "SENTINELAI - THREAT INVESTIGATION REPORT",
    "",
    "RECORDED EVENT EVIDENCE",
    ...evidence.map((item) => `- ${item}`),
    "",
    "RISK FACTORS",
    ...riskFactors.map((item) => `- ${item}`),
    "",
    "RECOMMENDED ACTIONS",
    ...recommendations.map((item, index) => `${index + 1}. ${item}`),
    "",
    "NOTE: Recommendations are rule-based guidance, not proof of malicious activity.",
    "Validate findings against authoritative network and endpoint logs before taking action.",
  ].join("\n");

  return { riskFactors, recommendations, reportText };
}

function ThreatTimeline({ sourceIp = null } = {}) {
  const [hours, setHours] = useState(24);
  const [severity, setSeverity] = useState("ALL");
  const [includeTest, setIncludeTest] = useState(true);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);

  const loadTimeline = useCallback(async () => {
    setRefreshing(true);
    setError("");

    try {
      const params = new URLSearchParams({
        hours: String(hours),
        include_test: String(includeTest),
      });

      if (severity !== "ALL") {
        params.set("severity", severity);
      }
      if (sourceIp) {
        params.set("source_ip", sourceIp);
      }

      const response = await fetch(
        `${API}/api/threats/timeline?${params.toString()}`
      );

      if (!response.ok) {
        throw new Error(`Timeline request failed (${response.status})`);
      }

      const result = await response.json();
      setEvents(Array.isArray(result.events) ? result.events : []);
    } catch (err) {
      setError(err.message || "Unable to load threat activity.");
      setEvents([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [hours, severity, includeTest, sourceIp]);

  useEffect(() => {
    loadTimeline();
  }, [loadTimeline]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      loadTimeline();
    }, 30000);

    return () => window.clearInterval(timer);
  }, [loadTimeline]);

  const chartData = useMemo(() => {
    const buckets = new Map();

    events.forEach((event) => {
      const date = new Date(event.created_at);

      if (Number.isNaN(date.getTime())) return;

      date.setMinutes(0, 0, 0);

      const key = date.toISOString();

      if (!buckets.has(key)) {
        buckets.set(key, {
          timestamp: date.getTime(),
          label:
            hours === 168
              ? date.toLocaleString([], {
                  month: "short",
                  day: "numeric",
                  hour: "2-digit",
                })
              : date.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                }),
          CRITICAL: 0,
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
        });
      }

      const level = String(event.severity || "LOW").toUpperCase();

      if (Object.hasOwn(buckets.get(key), level)) {
        buckets.get(key)[level] += 1;
      }
    });

    return Array.from(buckets.values()).sort(
      (a, b) => a.timestamp - b.timestamp
    );
  }, [events, hours]);

  const exportCSV = () => {
    if (events.length === 0) return;

    const columns = [
      "ID",
      "Threat Type",
      "Source IP",
      "Destination IP",
      "Port",
      "Protocol",
      "Risk Score",
      "Severity",
      "Action",
      "Status",
      "Created At",
      "Test Event",
    ];

    const rows = events.map((event) => [
      event.id,
      event.threat_type,
      event.source_ip,
      event.destination_ip,
      event.port,
      event.protocol,
      event.risk_score,
      event.severity,
      event.action,
      event.status,
      event.created_at,
      event.is_test,
    ]);

    const escapeCSV = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const csv = [columns, ...rows]
      .map((row) => row.map(escapeCSV).join(","))
      .join("\n");

    const blob = new Blob([csv], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinelai-threat-timeline-${hours}h.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const investigationReport = selectedEvent
    ? buildInvestigationReport(selectedEvent)
    : null;

  return (
    <section className="monitor-card threat-timeline-card">
      <div className="monitor-card-header">
        <div>
          <h2>
              {sourceIp
                ? `Attack Timeline: ${sourceIp}`
                : "Threat Activity Timeline"}
            </h2>
          <p>Recorded security events grouped by hour</p>
        </div>
        <Activity size={21} />
      </div>

      <div className="timeline-controls">
        <div className="timeline-filter-group">
          <span>Time range</span>
          <div className="timeline-range-buttons">
            {[
              { label: "1 Hour", value: 1 },
              { label: "24 Hours", value: 24 },
              { label: "7 Days", value: 168 },
            ].map((option) => (
              <button
                key={option.value}
                type="button"
                className={hours === option.value ? "active" : ""}
                onClick={() => setHours(option.value)}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        <label className="timeline-severity-filter">
          <span>Severity</span>
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            {SEVERITIES.map((level) => (
              <option key={level} value={level}>
                {level === "ALL" ? "All severities" : level}
              </option>
            ))}
          </select>
        </label>

        <label className="timeline-test-toggle">
          <input
            type="checkbox"
            checked={includeTest}
            onChange={(event) => setIncludeTest(event.target.checked)}
          />
          Include test events
        </label>

        <div className="timeline-actions">
          <button
            type="button"
            onClick={loadTimeline}
            disabled={refreshing}
            title="Refresh timeline"
          >
            <RefreshCw size={15} className={refreshing ? "spin-icon" : ""} />
            Refresh
          </button>
          <button
            type="button"
            onClick={exportCSV}
            disabled={events.length === 0}
          >
            <Download size={15} />
            Export CSV
          </button>
        </div>
      </div>

      <div className="timeline-summary">
        <div>
          <strong>{loading ? "..." : events.length}</strong>
          <span>Matching events</span>
        </div>
        <div>
          <strong>{chartData.length}</strong>
          <span>Active hours</span>
        </div>
        <div>
          <strong>{events.filter((event) => event.is_test).length}</strong>
          <span>Test events</span>
        </div>
      </div>

      {error && (
        <div className="monitor-error" role="alert">
          {error}
        </div>
      )}

      {loading ? (
        <div className="monitor-empty">
          <p>Loading threat activity...</p>
        </div>
      ) : events.length === 0 ? (
        <div className="monitor-empty">
          <p>No matching threat events in this time range.</p>
        </div>
      ) : (
        <>
          <div className="timeline-chart">
            <ResponsiveContainer width="100%" height={260}>
              <BarChart
                data={chartData}
                margin={{ top: 10, right: 12, left: -15, bottom: 8 }}
              >
                <CartesianGrid
                  stroke="#294158"
                  strokeDasharray="3 3"
                  vertical={false}
                />
                <XAxis
                  dataKey="label"
                  stroke="#91a4b8"
                  tick={{ fontSize: 11 }}
                  minTickGap={22}
                />
                <YAxis
                  allowDecimals={false}
                  stroke="#91a4b8"
                  tick={{ fontSize: 11 }}
                />
                <Tooltip
                  contentStyle={{
                    background: "#102236",
                    border: "1px solid #294158",
                    borderRadius: "9px",
                    color: "#e5edf5",
                  }}
                />
                <Bar dataKey="CRITICAL" stackId="severity" fill={severityColors.CRITICAL} />
                <Bar dataKey="HIGH" stackId="severity" fill={severityColors.HIGH} />
                <Bar dataKey="MEDIUM" stackId="severity" fill={severityColors.MEDIUM} />
                <Bar
                  dataKey="LOW"
                  stackId="severity"
                  fill={severityColors.LOW}
                  radius={[3, 3, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="timeline-legend">
            {Object.entries(severityColors).map(([level, color]) => (
              <span key={level}>
                <i style={{ background: color }} />
                {level}
              </span>
            ))}
          </div>

          <div className="timeline-events">
            <h3>Recorded Events</h3>
            <div className="timeline-table-wrap">
              <table className="threat-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Threat</th>
                    <th>Source IP</th>
                    <th>Risk</th>
                    <th>Severity</th>
                    <th>Action</th>
                    <th>Type</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {events.slice(0, 20).map((event) => (
                    <tr
                      key={event.id}
                      onClick={() => setSelectedEvent(event)}
                      className={
                        selectedEvent?.id === event.id
                          ? "timeline-row-selected"
                          : "timeline-clickable-row"
                      }
                    >
                      <td>
                        {new Date(event.created_at).toLocaleString()}
                      </td>
                      <td>{event.threat_type || "—"}</td>
                      <td>{event.source_ip || "—"}</td>
                      <td>{event.risk_score ?? "—"}</td>
                      <td>
                        <span
                          className={`threat-severity ${
                            String(event.severity || "unknown").toLowerCase()
                          }`}
                        >
                          {event.severity || "UNKNOWN"}
                        </span>
                      </td>
                      <td>{event.action || "—"}</td>
                      <td>{event.is_test ? "TEST" : "LIVE"}</td>
                      <td>
                        <button
                          type="button"
                          className="timeline-view-button"
                          onClick={(clickEvent) => {
                            clickEvent.stopPropagation();
                            setSelectedEvent(event);
                          }}
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selectedEvent && (
              <div className="timeline-detail-panel">
                <div className="timeline-detail-header">
                  <div>
                    <span>EVENT DETAILS</span>
                    <h3>{selectedEvent.threat_type || "Unknown Threat"}</h3>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedEvent(null)}
                    aria-label="Close event details"
                  >
                    Close
                  </button>
                </div>

                <div className="timeline-detail-grid">
                  <div>
                    <span>Event ID</span>
                    <strong>#{selectedEvent.id}</strong>
                  </div>
                  <div>
                    <span>Severity</span>
                    <strong>{selectedEvent.severity || "UNKNOWN"}</strong>
                  </div>
                  <div>
                    <span>Risk Score</span>
                    <strong>{selectedEvent.risk_score ?? "—"}</strong>
                  </div>
                  <div>
                    <span>Response Action</span>
                    <strong>{selectedEvent.action || "—"}</strong>
                  </div>
                  <div>
                    <span>Source IP</span>
                    <strong>{selectedEvent.source_ip || "—"}</strong>
                  </div>
                  <div>
                    <span>Destination IP</span>
                    <strong>{selectedEvent.destination_ip || "—"}</strong>
                  </div>
                  <div>
                    <span>Destination Port</span>
                    <strong>{selectedEvent.port ?? "—"}</strong>
                  </div>
                  <div>
                    <span>Protocol</span>
                    <strong>{selectedEvent.protocol || "—"}</strong>
                  </div>
                  <div>
                    <span>Event Status</span>
                    <strong>{selectedEvent.status || "—"}</strong>
                  </div>
                  <div>
                    <span>Event Classification</span>
                    <strong>{selectedEvent.is_test ? "TEST EVENT" : "LIVE EVENT"}</strong>
                  </div>
                  <div className="timeline-detail-wide">
                    <span>Recorded At</span>
                    <strong>
                      {selectedEvent.created_at
                        ? new Date(selectedEvent.created_at).toLocaleString()
                        : "—"}
                    </strong>
                  </div>
                </div>
                <p className="timeline-detail-note">
                  Read-only event information from the SentinelAI threat database.
                </p>

                <div className="investigation-report">
                  <div className="investigation-report-header">
                    <div>
                      <span>SECURITY ANALYSIS</span>
                      <h3>Threat Investigation Report</h3>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard
                          .writeText(investigationReport.reportText)
                          .catch(() =>
                            setError("Could not copy the report. Check browser clipboard permissions.")
                          );
                      }}
                    >
                      Copy Report
                    </button>
                  </div>

                  <div className="investigation-report-section">
                    <h4>Recorded Evidence</h4>
                    <p>
                      The evidence above contains fields returned by the SentinelAI
                      threat database. No additional network activity is assumed.
                    </p>
                  </div>

                  <div className="investigation-report-section">
                    <h4>Risk Factors</h4>
                    <ul>
                      {investigationReport.riskFactors.map((factor, index) => (
                        <li key={index}>{factor}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="investigation-report-section">
                    <h4>Recommended Actions</h4>
                    <ol>
                      {investigationReport.recommendations.map((recommendation, index) => (
                        <li key={index}>{recommendation}</li>
                      ))}
                    </ol>
                  </div>

                  <p className="investigation-report-disclaimer">
                    Rule-based guidance only. Validate findings using network
                    and endpoint evidence before taking security action.
                  </p>
                </div>
              </div>
            )}

            {events.length > 20 && (
              <p className="timeline-note">
                Showing the latest 20 events. CSV export includes all {events.length} matching events.
              </p>
            )}
          </div>
        </>
      )}
    </section>
  );
}

export default ThreatTimeline;
