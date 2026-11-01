import { API_BASE as API } from "../api";
import PageLayout from "../components/PageLayout";
import { lazy, Suspense } from "react";
const ThreatTimeline = lazy(() => import("../components/dashboard/ThreatTimeline"));
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Search,
  X,
  Eye
} from "lucide-react";

export default function ThreatDetection() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [actionFilter, setActionFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("newest");
  const [expandedCorrelation, setExpandedCorrelation] = useState(null);
const [timelineSourceIp, setTimelineSourceIp] = useState(null);
  const [responsePriorityFilter, setResponsePriorityFilter] = useState("ALL");
  const [expandedResponseGroup, setExpandedResponseGroup] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [scenario, setScenario] = useState("port_scan");
  const [simulationMessage, setSimulationMessage] = useState("");

  const loadThreats = async () => {
    try {
      setRefreshing(true);

      const response = await fetch(`${API}/api/threats/recent?limit=200`);

      if (!response.ok) {
        throw new Error("Unable to load threat data");
      }

      const data = await response.json();

      setThreats(Array.isArray(data) ? data : []);
      setError("");
    } catch (err) {
      console.error(err);
      setError("Unable to connect to SecureX AI backend.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const simulateAttack = async () => {
    try {
      setSimulating(true);
      setSimulationMessage("");
      setError("");

      const response = await fetch(`${API}/api/demo/attack?scenario=${encodeURIComponent(scenario)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.detail || data.message || `Request failed (${response.status})`);
      }

      setSimulationMessage(
        `${data.threat_type || scenario} simulated successfully. Risk: ${data.risk_score ?? "N/A"} | Severity: ${data.severity || "Unknown"} | Action: ${data.action || "Unknown"}`
      );

      await loadThreats();
    } catch (err) {
      console.error("Demo attack failed:", err);
      setError(
        `Demo attack failed: ${err instanceof Error ? err.message : String(err)}`
      );
    } finally {
      setSimulating(false);
    }
  };

  useEffect(() => {
    loadThreats();

    const interval = setInterval(loadThreats, 10000);



  return () => clearInterval(interval);
  }, []);

  const mitreMappings = [
    {
      id: "T1046",
      name: "Network Service Discovery",
      tactic: "Discovery",
      patterns: /PORT.?SCAN|NETWORK.?SCAN|SERVICE.?SCAN/i,
      explanation: "Port scanning can be associated with discovering network services and exposed ports."
    },
    {
      id: "T1110",
      name: "Brute Force",
      tactic: "Credential Access",
      patterns: /BRUTE.?FORCE|LOGIN.?ATTACK|PASSWORD.?GUESS/i,
      explanation: "Repeated credential attempts can be associated with brute-force activity."
    },
    {
      id: "T1498",
      name: "Network Denial of Service",
      tactic: "Impact",
      patterns: /DDOS|DOS|FLOOD/i,
      explanation: "Denial-of-service traffic can be associated with attempts to disrupt network availability."
    },
    {
      id: "T1204",
      name: "User Execution",
      tactic: "Execution",
      patterns: /MALWARE|RANSOMWARE|TROJAN/i,
      explanation: "Malware labels alone do not establish user execution. Additional endpoint evidence is required."
    }
  ];

  const mitreResults = mitreMappings
    .map((mapping) => ({
      ...mapping,
      matchingEvents: threats.filter((threat) =>
        mapping.patterns.test(String(threat.threat_type || ""))
      )
    }))
    .filter((mapping) => mapping.matchingEvents.length > 0);



  const responseRecommendations = threats.map((threat) => {
    const type = String(threat.threat_type || "UNKNOWN").toUpperCase();
    const severity = String(threat.severity || "LOW").toUpperCase();
    const risk = Number(threat.risk_score || 0);

    let recommendation = {
      priority: "LOW",
      title: "Continue monitoring",
      action: "Monitor network activity and review future events.",
      reason: "The recorded event does not currently match a recognised high-risk pattern."
    };

    if (/DDOS|DOS|FLOOD/.test(type)) {
      recommendation = {
        priority: risk >= 80 || severity === "CRITICAL" ? "CRITICAL" : "HIGH",
        title: "Investigate denial-of-service activity",
        action: "Review traffic volume, connection rates and affected services. Consider rate limiting after analyst verification.",
        reason: "The recorded category suggests possible traffic intended to disrupt service availability."
      };
    } else if (/BRUTE.?FORCE|LOGIN.?ATTACK|PASSWORD.?GUESS/.test(type)) {
      recommendation = {
        priority: "HIGH",
        title: "Review authentication activity",
        action: "Inspect failed login records, verify affected accounts and consider enabling MFA.",
        reason: "Repeated credential attempts may indicate password guessing or unauthorised access attempts."
      };
    } else if (/PORT.?SCAN|NETWORK.?SCAN|SERVICE.?SCAN/.test(type)) {
      recommendation = {
        priority: "MEDIUM",
        title: "Inspect exposed network services",
        action: "Review destination ports, check listening services and investigate unusual connection patterns.",
        reason: "Scanning activity can indicate reconnaissance before a possible intrusion."
      };
    } else if (/MALWARE|RANSOMWARE|TROJAN/.test(type)) {
      recommendation = {
        priority: "CRITICAL",
        title: "Investigate the potentially affected endpoint",
        action: "Review endpoint security alerts, inspect affected files and escalate for security-team investigation.",
        reason: "The recorded malware category warrants endpoint investigation. The label alone does not confirm infection."
      };
    } else if (severity === "CRITICAL" || risk >= 80) {
      recommendation = {
        priority: "CRITICAL",
        title: "Escalate high-risk security event",
        action: "Review supporting evidence, inspect related logs and escalate to the security analyst.",
        reason: "The recorded risk score or severity indicates a potentially serious event."
      };
    } else if (severity === "HIGH" || risk >= 60) {
      recommendation = {
        priority: "HIGH",
        title: "Investigate suspicious activity",
        action: "Review source and destination activity, inspect related events and validate the detection.",
        reason: "The recorded event has a high risk level and requires analyst review."
      };
    } else if (severity === "MEDIUM" || risk >= 30) {
      recommendation = {
        priority: "MEDIUM",
        title: "Review and monitor the event",
        action: "Check related traffic and authentication logs, then monitor for repeated activity.",
        reason: "The recorded event has moderate risk and may require further investigation."
      };
    }

    return { ...recommendation, threat };
  }).sort((a, b) => {
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return rank[b.priority] - rank[a.priority] ||
      Number(b.threat.risk_score || 0) - Number(a.threat.risk_score || 0);
  });


  // Exclude clearly benign traffic from analyst recommendations.
  const actionableRecommendations = responseRecommendations.filter((item) => {
    const type = String(item.threat.threat_type || "").toUpperCase();
    const action = String(item.threat.action || "").toUpperCase();
    const risk = Number(item.threat.risk_score || 0);

    if (/BENIGN|NORMAL|LEGITIMATE/.test(type)) return false;
    if (action === "ALLOW" && risk < 30) return false;

    return true;
  });

  // Group repeated recommendations by source IP and recommendation type.
  const responseGroupMap = new Map();

  actionableRecommendations.forEach((item) => {
    const sourceIp = String(item.threat.source_ip || "Unknown source");
    const key = `${item.priority}|${item.title}|${sourceIp}`;

    if (!responseGroupMap.has(key)) {
      responseGroupMap.set(key, {
        key,
        priority: item.priority,
        title: item.title,
        action: item.action,
        reason: item.reason,
        sourceIp,
        events: []
      });
    }

    responseGroupMap.get(key).events.push(item.threat);
  });

  const responseGroups = [...responseGroupMap.values()].sort((a, b) => {
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return rank[b.priority] - rank[a.priority];
  });

  const responsePriorityCounts = {
    CRITICAL: responseGroups.filter((item) => item.priority === "CRITICAL").length,
    HIGH: responseGroups.filter((item) => item.priority === "HIGH").length,
    MEDIUM: responseGroups.filter((item) => item.priority === "MEDIUM").length,
    LOW: responseGroups.filter((item) => item.priority === "LOW").length
  };

  const visibleResponseGroups = responsePriorityFilter === "ALL"
    ? responseGroups
    : responseGroups.filter((item) => item.priority === responsePriorityFilter);

  const critical = threats.filter(
    (t) => t.severity === "CRITICAL"
  ).length;

  const high = threats.filter(
    (t) => t.severity === "HIGH"
  ).length;

  const medium = threats.filter(
    (t) => t.severity === "MEDIUM"
  ).length;

  const low = threats.filter(
    (t) => t.severity === "LOW"
  ).length;

  const filteredThreats = threats
    .filter((threat) => {
      const value = search.toLowerCase();

      const matchesSearch =
        String(threat.threat_type || "").toLowerCase().includes(value) ||
        String(threat.source_ip || "").toLowerCase().includes(value) ||
        String(threat.destination_ip || "").toLowerCase().includes(value) ||
        String(threat.port || "").includes(value) ||
        String(threat.action || "").toLowerCase().includes(value);

      const matchesSeverity =
        severityFilter === "ALL" || threat.severity === severityFilter;

      const matchesAction =
        actionFilter === "ALL" || threat.action === actionFilter;

      return matchesSearch && matchesSeverity && matchesAction;
    })
    .sort((a, b) => {
      if (sortBy === "highest") {
        return Number(b.risk_score || 0) - Number(a.risk_score || 0);
      }

      if (sortBy === "lowest") {
        return Number(a.risk_score || 0) - Number(b.risk_score || 0);
      }

      const dateA = new Date(a.created_at || 0).getTime() || 0;
      const dateB = new Date(b.created_at || 0).getTime() || 0;

      return sortBy === "oldest" ? dateA - dateB : dateB - dateA;
    });


  const correlationGroups = Object.values(
    threats.reduce((groups, threat) => {
      const source = String(threat.source_ip || "").trim();

      if (!source) return groups;

      if (!groups[source]) {
        groups[source] = {
          source_ip: source,
          events: [],
          highestRisk: 0,
          severity: "LOW",
          latest: null,
          threatTypes: new Set()
        };
      }

      const group = groups[source];
      group.events.push(threat);
      group.highestRisk = Math.max(
        group.highestRisk,
        Number(threat.risk_score || 0)
      );

      group.threatTypes.add(threat.threat_type || "UNKNOWN");

      const severityRank = {
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4
      };

      if (
        (severityRank[threat.severity] || 0) >
        (severityRank[group.severity] || 0)
      ) {
        group.severity = threat.severity;
      }

      const eventTime = new Date(threat.created_at || 0).getTime() || 0;
      const latestTime = group.latest
        ? new Date(group.latest.created_at || 0).getTime() || 0
        : 0;

      if (!group.latest || eventTime > latestTime) {
        group.latest = threat;
      }

      return groups;
    }, {})
  )
    .filter((group) => group.events.length >= 2)
    .sort((a, b) =>
      b.events.length - a.events.length ||
      b.highestRisk - a.highestRisk
    );

  const exportThreatsCSV = () => {
    const columns = [
      ["id", "Threat ID"],
      ["threat_type", "Threat Type"],
      ["source_ip", "Source IP"],
      ["destination_ip", "Destination IP"],
      ["protocol", "Protocol"],
      ["port", "Port"],
      ["packets", "Packets"],
      ["bytes_transferred", "Bytes Transferred"],
      ["anomaly_score", "AI Anomaly Score"],
      ["risk_score", "Risk Score"],
      ["severity", "Severity"],
      ["action", "Security Action"],
      ["status", "Status"],
      ["created_at", "Detected At"]
    ];

    const escapeCSV = (value) => {
      let text = String(value ?? "");

      if (/^[=+\-@\t\r]/.test(text)) {
        text = "'" + text;
      }

      return '"' + text.replace(/"/g, '""') + '"';
    };

    const header = columns
      .map(([, label]) => escapeCSV(label))
      .join(",");

    const rows = filteredThreats.map((threat) =>
      columns
        .map(([key]) => escapeCSV(threat[key]))
        .join(",")
    );

    const csvContent = [
      header,
      ...rows
    ].join("\r\n");

    const blob = new Blob(
      ["\uFEFF", csvContent],
      { type: "text/csv;charset=utf-8;" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "SentinelAI_Threat_Report.csv";

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const severityStyle = (severity) => {
    if (severity === "CRITICAL") {
      return {
        background: "rgba(239,68,68,0.15)",
        color: "#EF4444",
        border: "1px solid rgba(239,68,68,0.35)"
      };
    }

    if (severity === "HIGH") {
      return {
        background: "rgba(249,115,22,0.15)",
        color: "#F97316",
        border: "1px solid rgba(249,115,22,0.35)"
      };
    }

    if (severity === "MEDIUM") {
      return {
        background: "rgba(245,158,11,0.15)",
        color: "#F59E0B",
        border: "1px solid rgba(245,158,11,0.35)"
      };
    }

    return {
      background: "rgba(34,197,94,0.15)",
      color: "#22C55E",
      border: "1px solid rgba(34,197,94,0.35)"
    };
  };

  const actionStyle = (action) => {
    if (action === "BLOCK") {
      return {
        background: "rgba(239,68,68,0.12)",
        color: "#EF4444"
      };
    }

    if (action === "MFA") {
      return {
        background: "rgba(245,158,11,0.12)",
        color: "#F59E0B"
      };
    }

    return {
      background: "rgba(34,197,94,0.12)",
      color: "#22C55E"
    };
  };

  const formatDate = (value) => {
    if (!value) return "Unknown";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "Unknown";
    }

    return date.toLocaleString();
  };

  return (
    <PageLayout title="Threat Detection">
      <div style={{ width: "100%", minWidth: 0 }}>
      <div
        style={{
          maxWidth: "1500px",
          margin: "0 auto"
        }}
      >
        {/* Header */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "28px",
            gap: "20px"
          }}
        >
          <div>
            <div
              style={{
                fontSize: "12px",
                color: "#64748B",
                letterSpacing: "1.5px",
                fontWeight: 700,
                marginBottom: "7px"
              }}
            >
              SECURITY CONSOLE
            </div>

            <h1
              style={{
                margin: 0,
                fontSize: "30px",
                fontWeight: 800
              }}
            >
              Threat Detection
            </h1>

            <p
              style={{
                margin: "8px 0 0",
                color: "#94A3B8"
              }}
            >
              AI-powered network threat detection and risk analysis
            </p>
          </div>

          <select
            value={scenario}
            onChange={(event) => setScenario(event.target.value)}
            disabled={simulating}
            aria-label="Attack simulation scenario"
            style={{
              background: "#111827",
              color: "#F8FAFC",
              border: "1px solid #243244",
              borderRadius: "10px",
              padding: "11px 12px",
              minWidth: "175px"
            }}
          >
            <option value="port_scan">Port Scan</option>
            <option value="ddos">DDoS Simulation</option>
            <option value="brute_force">Brute Force</option>
            <option value="benign">Benign Traffic</option>
          </select>

          <button
            onClick={simulateAttack}
            disabled={simulating}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "9px",
              background: simulating ? "#334155" : "#7F1D1D",
              border: "1px solid #B91C1C",
              color: "#F8FAFC",
              padding: "11px 17px",
              borderRadius: "10px",
              cursor: simulating ? "wait" : "pointer",
              fontWeight: 700
            }}
          >
            <ShieldAlert size={17} />
            {simulating ? "Simulating..." : "Simulate Selected"}
          </button>

          <button
            onClick={loadThreats}
            disabled={refreshing}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "9px",
              background: "#111827",
              border: "1px solid #243244",
              color: "#F8FAFC",
              padding: "11px 17px",
              borderRadius: "10px",
              cursor: refreshing ? "wait" : "pointer",
              fontWeight: 700
            }}
          >
            <RefreshCw
              size={17}
              style={{
                animation: refreshing ? "spin 1s linear infinite" : "none"
              }}
            />
            Refresh
          </button>
        </div>

        {simulationMessage && (
          <div
            role="status"
            style={{
              marginBottom: "16px",
              padding: "12px 16px",
              borderRadius: "10px",
              color: "#86EFAC",
              background: "rgba(34,197,94,0.10)",
              border: "1px solid rgba(34,197,94,0.25)"
            }}
          >
            {simulationMessage}
          </div>
        )}

        {/* Live status */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            background: "rgba(34,197,94,0.08)",
            border: "1px solid rgba(34,197,94,0.22)",
            borderRadius: "10px",
            padding: "12px 16px",
            marginBottom: "22px",
            color: "#22C55E"
          }}
        >
          <Activity size={18} />
          <span style={{ fontWeight: 700 }}>
            AI Threat Detection Online
          </span>
          <span
            style={{
              color: "#64748B",
              fontSize: "13px"
            }}
          >
            Live threat feed • Auto-refresh every 10 seconds
          </span>
        </div>

        {/* Error */}
        {error && (
          <div
            style={{
              background: "rgba(239,68,68,0.08)",
              border: "1px solid rgba(239,68,68,0.3)",
              color: "#EF4444",
              padding: "14px 16px",
              borderRadius: "10px",
              marginBottom: "22px"
            }}
          >
            {error}
          </div>
        )}

        {/* Statistics */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(5, minmax(0, 1fr))",
            gap: "16px",
            marginBottom: "22px"
          }}
        >
          <StatCard
            icon={<ShieldAlert size={20} />}
            title="Total Threats"
            value={threats.length}
            color="#00D4FF"
          />

          <StatCard
            icon={<AlertTriangle size={20} />}
            title="Critical"
            value={critical}
            color="#EF4444"
          />

          <StatCard
            icon={<AlertTriangle size={20} />}
            title="High"
            value={high}
            color="#F97316"
          />

          <StatCard
            icon={<Activity size={20} />}
            title="Medium"
            value={medium}
            color="#F59E0B"
          />

          <StatCard
            icon={<ShieldCheck size={20} />}
            title="Low"
            value={low}
            color="#22C55E"
          />
        </div>

        {/* Search */}
        <div
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "12px",
            padding: "14px",
            marginBottom: "16px"
          }}
        >
          <div
            style={{
              position: "relative"
            }}
          >
            <Search
              size={18}
              style={{
                position: "absolute",
                left: "14px",
                top: "50%",
                transform: "translateY(-50%)",
                color: "#64748B"
              }}
            />

            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search threat type, IP address, port or action..."
              style={{
                width: "100%",
                boxSizing: "border-box",
                background: "#0B1120",
                border: "1px solid #263449",
                borderRadius: "9px",
                padding: "12px 14px 12px 42px",
                color: "#F8FAFC",
                outline: "none",
                fontSize: "14px"
              }}
            />
          </div>
        </div>


          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "10px",
              marginTop: "13px",
              alignItems: "center"
            }}
          >
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={filterSelectStyle}
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              style={filterSelectStyle}
            >
              <option value="ALL">All actions</option>
              <option value="BLOCK">Block</option>
              <option value="MFA">MFA</option>
              <option value="ALLOW">Allow</option>
              <option value="MONITOR">Monitor</option>
            </select>

            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              style={filterSelectStyle}
            >
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
              <option value="highest">Highest risk</option>
              <option value="lowest">Lowest risk</option>
            </select>

            <button
              onClick={exportThreatsCSV}
              disabled={filteredThreats.length === 0}
              style={{
                background: "#14532D",
                color: "#BBF7D0",
                border: "1px solid #166534",
                borderRadius: "8px",
                padding: "10px 14px",
                cursor: "pointer",
                fontWeight: 700
              }}
            >
              Export CSV ({filteredThreats.length})
            </button>
          </div>

        {/* Threat Correlation Engine */}
        <div
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "20px",
            marginBottom: "18px"
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "12px",
              marginBottom: "16px"
            }}
          >
            <div>
              <h2 style={{ margin: 0, fontSize: "18px", color: "#F8FAFC" }}>
                Threat Correlation Engine
              </h2>
              <p style={{ margin: "6px 0 0", color: "#64748B", fontSize: "12px" }}>
                Repeated threat events grouped by source IP
              </p>
            </div>

            <span
              style={{
                background: "rgba(0,212,255,0.10)",
                border: "1px solid rgba(0,212,255,0.25)",
                color: "#00D4FF",
                borderRadius: "20px",
                padding: "7px 12px",
                fontSize: "12px",
                fontWeight: 700
              }}
            >
              {correlationGroups.length} correlated sources
            </span>
          </div>

          {correlationGroups.length === 0 ? (
            <div style={{
              padding: "22px",
              textAlign: "center",
              color: "#94A3B8",
              background: "#0B1120",
              borderRadius: "9px"
            }}>
              No repeated source IPs found in the loaded threat records.
            </div>
          ) : (
            <div style={{ display: "grid", gap: "10px" }}>
              {correlationGroups.map((group) => {
                const expanded = expandedCorrelation === group.source_ip;

                return (
                  <div
                    key={group.source_ip}
                    style={{
                      background: "#0B1120",
                      border: "1px solid #263449",
                      borderRadius: "10px",
                      overflow: "hidden"
                    }}
                  >
                    <button
                      type="button"
                      onClick={() =>
                        setExpandedCorrelation(
                          expanded ? null : group.source_ip
                        )
                      }
                      style={{
                        width: "100%",
                        padding: "14px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: "12px",
                        background: "transparent",
                        border: "none",
                        color: "#E2E8F0",
                        textAlign: "left",
                        cursor: "pointer"
                      }}
                    >
                      <div>
                        <div style={{
                          fontWeight: 800,
                          fontFamily: "monospace",
                          color: "#38BDF8"
                        }}>
                          {group.source_ip}
                        </div>
                        <div style={{
                          color: "#94A3B8",
                          fontSize: "11px",
                          marginTop: "5px"
                        }}>
                          {group.threatTypes.size} threat categories
                          {" · "}
                          Latest: {group.latest?.created_at
                            ? new Date(group.latest.created_at).toLocaleString()
                            : "Unknown"}
                        </div>
                      </div>

                      <div style={{
                        display: "flex",
                        alignItems: "center",
                        flexWrap: "wrap",
                        gap: "12px"
                      }}>
                        <span style={{ fontSize: "12px", color: "#CBD5E1" }}>
                          {group.events.length} events
                        </span>
                        <span style={{
                          fontSize: "12px",
                          fontWeight: 800,
                          color: group.severity === "CRITICAL"
                            ? "#EF4444"
                            : group.severity === "HIGH"
                              ? "#F97316"
                              : group.severity === "MEDIUM"
                                ? "#F59E0B"
                                : "#22C55E"
                        }}>
                          {group.severity}
                        </span>
                        <span style={{ fontSize: "12px", color: "#F8FAFC" }}>
                          Risk {group.highestRisk}/100
                        </span>
                        <span style={{ color: "#94A3B8" }}>
                          {expanded ? "−" : "+"}
                        </span>
                      </div>
                    </button>

                    {expanded && (
                      <div style={{
                        borderTop: "1px solid #263449",
                        padding: "14px"
                      }}>
                        <div style={{
                          color: "#94A3B8",
                          fontSize: "11px",
                          marginBottom: "10px"
                        }}>
                          RELATED RECORDED EVENTS
                        </div>

                        <button
                          type="button"
                          onClick={() => setTimelineSourceIp(group.source_ip)}
                          style={{
                            marginBottom: "14px",
                            padding: "9px 13px",
                            background: "#082F49",
                            color: "#7DD3FC",
                            border: "1px solid #075985",
                            borderRadius: "7px",
                            cursor: "pointer",
                            fontWeight: 700
                          }}
                        >
                          View Attack Timeline
                        </button>
                        <div style={{ display: "grid", gap: "8px" }}>
                          {[...group.events]
                            .sort((a, b) =>
                              (new Date(b.created_at || 0).getTime() || 0) -
                              (new Date(a.created_at || 0).getTime() || 0)
                            )
                            .map((event) => (
                              <div
                                key={event.id}
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  flexWrap: "wrap",
                                  gap: "8px",
                                  padding: "10px",
                                  background: "#111827",
                                  borderRadius: "7px",
                                  fontSize: "12px"
                                }}
                              >
                                <span style={{ color: "#E2E8F0" }}>
                                  #{event.id} · {event.threat_type}
                                </span>
                                <span style={{ color: "#94A3B8" }}>
                                  Risk: {event.risk_score ?? "N/A"}
                                  {" · "}
                                  {event.action || "N/A"}
                                </span>
                                <span style={{ color: "#64748B" }}>
                                  {event.created_at
                                    ? new Date(event.created_at).toLocaleString()
                                    : "Unknown time"}
                                </span>
                              </div>
                            ))}
                        </div>

                        <p style={{
                          margin: "12px 0 0",
                          color: "#64748B",
                          fontSize: "11px"
                        }}>
                          Correlation is based on matching source IP addresses.
                          Shared IPs alone do not prove a coordinated attack.
                        </p>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {timelineSourceIp && (
          <div style={{ marginBottom: "18px" }}>
            <button
              type="button"
              onClick={() => setTimelineSourceIp(null)}
              style={{
                marginBottom: "12px",
                padding: "9px 13px",
                background: "#1E293B",
                color: "#E2E8F0",
                border: "1px solid #334155",
                borderRadius: "7px",
                cursor: "pointer"
              }}
            >
              Close Attack Timeline
            </button>
            <Suspense fallback={<div>Loading attack timeline...</div>}>
              <ThreatTimeline sourceIp={timelineSourceIp} />
            </Suspense>
          </div>
        )}

        {/* MITRE ATT&CK Intelligence */}
        <section
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "20px",
            marginBottom: "18px"
          }}
        >
          <div style={{ marginBottom: "16px" }}>
            <h2 style={{ margin: 0, color: "#F8FAFC", fontSize: "18px" }}>
              MITRE ATT&CK Intelligence
            </h2>
            <p style={{ color: "#94A3B8", fontSize: "12px", marginTop: "6px" }}>
              Candidate technique mappings based on recorded threat categories
            </p>
          </div>

          {mitreResults.length === 0 ? (
            <div style={{
              padding: "20px",
              background: "#0B1120",
              borderRadius: "9px",
              color: "#94A3B8",
              textAlign: "center"
            }}>
              No recognised threat categories found for MITRE mapping.
            </div>
          ) : (
            <div style={{ display: "grid", gap: "12px" }}>
              {mitreResults.map((item) => (
                <div
                  key={item.id}
                  style={{
                    background: "#0B1120",
                    border: "1px solid #263449",
                    borderRadius: "10px",
                    padding: "15px"
                  }}
                >
                  <div style={{
                    display: "flex",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "10px"
                  }}>
                    <div>
                      <span style={{
                        color: "#38BDF8",
                        fontWeight: 800,
                        fontFamily: "monospace"
                      }}>
                        {item.id}
                      </span>
                      <h3 style={{
                        color: "#F8FAFC",
                        margin: "6px 0"
                      }}>
                        {item.name}
                      </h3>
                    </div>
                    <span style={{
                      color: "#C4B5FD",
                      background: "#312E81",
                      borderRadius: "20px",
                      padding: "6px 11px",
                      fontSize: "11px",
                      height: "fit-content"
                    }}>
                      {item.tactic}
                    </span>
                  </div>

                  <p style={{
                    color: "#94A3B8",
                    fontSize: "12px",
                    lineHeight: 1.6
                  }}>
                    {item.explanation}
                  </p>

                  <div style={{
                    color: "#CBD5E1",
                    fontSize: "12px",
                    marginTop: "10px"
                  }}>
                    Matching recorded events: {item.matchingEvents.length}
                  </div>

                  <div style={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: "7px",
                    marginTop: "9px"
                  }}>
                    {[...new Set(item.matchingEvents.map(
                      (event) => event.threat_type || "UNKNOWN"
                    ))].map((type) => (
                      <span
                        key={type}
                        style={{
                          background: "#1E293B",
                          color: "#CBD5E1",
                          padding: "5px 9px",
                          borderRadius: "6px",
                          fontSize: "11px"
                        }}
                      >
                        {type}
                      </span>
                    ))}
                  </div>

                  <p style={{
                    color: "#FBBF24",
                    fontSize: "11px",
                    marginBottom: 0
                  }}>
                    Candidate mapping only. Validate with additional security evidence.
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Intelligent Response Recommendations */}
        <section style={{
          background: "#111827",
          border: "1px solid #1E293B",
          borderRadius: "14px",
          padding: "20px",
          marginBottom: "18px"
        }}>
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "10px",
            marginBottom: "16px"
          }}>
            <div>
              <h2 style={{ margin: 0, color: "#F8FAFC", fontSize: "18px" }}>
                Intelligent Response Recommendations
              </h2>
              <p style={{ color: "#94A3B8", fontSize: "12px", marginTop: "6px" }}>
                Grouped rule-based analyst guidance from recorded threat evidence
              </p>
            </div>
            <span style={{
              background: "#1E293B",
              color: "#CBD5E1",
              padding: "7px 10px",
              borderRadius: "7px",
              fontSize: "12px"
            }}>
              {responseGroups.length} recommendations · {actionableRecommendations.length} events
            </span>
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(105px, 1fr))",
            gap: "8px",
            marginBottom: "16px"
          }}>
            {[
              ["ALL", "All", responseGroups.length, "#CBD5E1"],
              ["CRITICAL", "Critical", responsePriorityCounts.CRITICAL, "#EF4444"],
              ["HIGH", "High", responsePriorityCounts.HIGH, "#F97316"],
              ["MEDIUM", "Medium", responsePriorityCounts.MEDIUM, "#F59E0B"],
              ["LOW", "Low", responsePriorityCounts.LOW, "#22C55E"]
            ].map(([value, label, count, color]) => (
              <button
                key={value}
                type="button"
                onClick={() => setResponsePriorityFilter(value)}
                style={{
                  background: responsePriorityFilter === value ? "#263449" : "#0B1120",
                  border: `1px solid ${responsePriorityFilter === value ? color : "#263449"}`,
                  color,
                  borderRadius: "8px",
                  padding: "10px",
                  cursor: "pointer",
                  textAlign: "left"
                }}
              >
                <div style={{ fontSize: "11px" }}>{label}</div>
                <strong style={{ fontSize: "19px" }}>{count}</strong>
              </button>
            ))}
          </div>

          {visibleResponseGroups.length === 0 ? (
            <p style={{ color: "#94A3B8", textAlign: "center", padding: "20px" }}>
              No recommendations match this priority filter.
            </p>
          ) : (
            <div style={{ display: "grid", gap: "12px" }}>
              {visibleResponseGroups.slice(0, 12).map((item) => {
                const priorityColors = {
                  CRITICAL: "#EF4444",
                  HIGH: "#F97316",
                  MEDIUM: "#F59E0B",
                  LOW: "#22C55E"
                };
                const color = priorityColors[item.priority];
                const expanded = expandedResponseGroup === item.key;
                const highestRisk = Math.max(
                  ...item.events.map((event) => Number(event.risk_score || 0))
                );

                return (
                  <article key={item.key} style={{
                    background: "#0B1120",
                    border: "1px solid #263449",
                    borderLeft: `4px solid ${color}`,
                    borderRadius: "9px",
                    padding: "15px"
                  }}>
                    <div style={{
                      display: "flex",
                      justifyContent: "space-between",
                      flexWrap: "wrap",
                      gap: "8px"
                    }}>
                      <strong style={{ color: "#F8FAFC", fontSize: "14px" }}>
                        {item.title}
                      </strong>
                      <span style={{
                        color,
                        background: `${color}20`,
                        border: `1px solid ${color}55`,
                        borderRadius: "6px",
                        padding: "4px 8px",
                        fontSize: "10px",
                        fontWeight: 700
                      }}>
                        {item.priority} PRIORITY
                      </span>
                    </div>

                    <p style={{ color: "#CBD5E1", fontSize: "12px", margin: "10px 0 6px" }}>
                      <strong>Source:</strong> {item.sourceIp}
                      {" · "}
                      <strong>Related events:</strong> {item.events.length}
                      {" · "}
                      <strong>Highest risk:</strong> {highestRisk}
                    </p>

                    <p style={{ color: "#94A3B8", fontSize: "12px", lineHeight: 1.6 }}>
                      <strong style={{ color: "#CBD5E1" }}>Evidence:</strong> {item.reason}
                    </p>

                    <p style={{ color: "#A7F3D0", fontSize: "12px", lineHeight: 1.6 }}>
                      <strong>Recommended action:</strong> {item.action}
                    </p>

                    <button
                      type="button"
                      onClick={() => setExpandedResponseGroup(expanded ? null : item.key)}
                      style={{
                        background: "#1E293B",
                        border: "1px solid #334155",
                        color: "#E2E8F0",
                        borderRadius: "7px",
                        padding: "8px 11px",
                        cursor: "pointer",
                        fontSize: "12px"
                      }}
                    >
                      {expanded ? "Hide supporting events" : `View ${item.events.length} supporting event(s)`}
                    </button>

                    {expanded && (
                      <div style={{
                        marginTop: "12px",
                        display: "grid",
                        gap: "8px"
                      }}>
                        {item.events.map((event, index) => (
                          <div key={event.id ?? `${item.key}-${index}`} style={{
                            background: "#111827",
                            border: "1px solid #263449",
                            borderRadius: "7px",
                            padding: "10px",
                            color: "#CBD5E1",
                            fontSize: "12px"
                          }}>
                            <strong>Event #{event.id ?? "N/A"}</strong>
                            <div style={{ marginTop: "5px" }}>
                              Type: {event.threat_type || "UNKNOWN"}
                              {" · "}
                              Risk: {event.risk_score ?? "N/A"}
                              {" · "}
                              Action: {event.action || "N/A"}
                            </div>
                            <div style={{ marginTop: "4px", color: "#94A3B8" }}>
                              Destination: {event.destination_ip || "N/A"}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          )}

          {visibleResponseGroups.length > 12 && (
            <p style={{ color: "#94A3B8", fontSize: "12px", marginTop: "12px" }}>
              Showing 12 of {visibleResponseGroups.length} matching recommendation groups.
            </p>
          )}

          <p style={{
            color: "#FBBF24",
            fontSize: "11px",
            marginTop: "14px",
            marginBottom: 0
          }}>
            Benign traffic is excluded from recommendations but remains in threat records.
            Analyst guidance only. No firewall, endpoint or network changes are executed.
          </p>
        </section>

        {/* Threat table */}
        <div
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
              <h2
                style={{
                  margin: 0,
                  fontSize: "18px"
                }}
              >
                Detected Threats
              </h2>

              <p
                style={{
                  margin: "5px 0 0",
                  color: "#64748B",
                  fontSize: "13px"
                }}
              >
                Live AI detection results from the SecureX AI backend
              </p>
            </div>

            <span
              style={{
                color: "#94A3B8",
                fontSize: "13px"
              }}
            >
              {filteredThreats.length} result
              {filteredThreats.length === 1 ? "" : "s"}
            </span>
          </div>

          {loading ? (
            <div
              style={{
                padding: "60px 20px",
                textAlign: "center",
                color: "#64748B"
              }}
            >
              Loading threat intelligence...
            </div>
          ) : filteredThreats.length === 0 ? (
            <div
              style={{
                padding: "70px 20px",
                textAlign: "center"
              }}
            >
              <ShieldCheck
                size={42}
                color="#22C55E"
                style={{ marginBottom: "12px" }}
              />

              <h3 style={{ margin: "0 0 8px" }}>
                No threats found
              </h3>

              <p
                style={{
                  margin: 0,
                  color: "#64748B"
                }}
              >
                {search
                  ? "No threats match your search."
                  : "The network is currently clean."}
              </p>
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table
                style={{
                  width: "100%",
                  borderCollapse: "collapse",
                  minWidth: "1050px"
                }}
              >
                <thead>
                  <tr
                    style={{
                      background: "#0D1525",
                      color: "#64748B",
                      fontSize: "11px",
                      textTransform: "uppercase",
                      letterSpacing: "0.8px"
                    }}
                  >
                    <th style={thStyle}>Threat</th>
                    <th style={thStyle}>Source</th>
                    <th style={thStyle}>Destination</th>
                    <th style={thStyle}>Port</th>
                    <th style={thStyle}>AI Anomaly</th>
                    <th style={thStyle}>Risk</th>
                    <th style={thStyle}>Severity</th>
                    <th style={thStyle}>Action</th>
                    <th style={thStyle}>Details</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredThreats.map((threat) => (
                    <tr
                      key={threat.id}
                      style={{
                        borderTop: "1px solid #1E293B"
                      }}
                    >
                      <td style={tdStyle}>
                        <div
                          style={{
                            fontWeight: 700,
                            color: "#F8FAFC"
                          }}
                        >
                          {threat.threat_type}
                        </div>

                        <div
                          style={{
                            color: "#64748B",
                            fontSize: "11px",
                            marginTop: "4px"
                          }}
                        >
                          #{threat.id} • {threat.protocol}
                        </div>
                      </td>

                      <td style={tdStyle}>
                        <code style={codeStyle}>
                          {threat.source_ip}
                        </code>
                      </td>

                      <td style={tdStyle}>
                        <code style={codeStyle}>
                          {threat.destination_ip}
                        </code>
                      </td>

                      <td style={tdStyle}>
                        <span
                          style={{
                            background: "#172033",
                            padding: "5px 8px",
                            borderRadius: "6px",
                            fontWeight: 700
                          }}
                        >
                          {threat.port}
                        </span>
                      </td>

                      <td style={tdStyle}>
                        <ScoreBar
                          value={threat.anomaly_score}
                          color="#00D4FF"
                        />
                      </td>

                      <td style={tdStyle}>
                        <ScoreBar
                          value={threat.risk_score}
                          color={
                            threat.risk_score >= 80
                              ? "#EF4444"
                              : threat.risk_score >= 60
                                ? "#F59E0B"
                                : "#22C55E"
                          }
                        />
                      </td>

                      <td style={tdStyle}>
                        <span
                          style={{
                            ...severityStyle(threat.severity),
                            display: "inline-block",
                            padding: "5px 9px",
                            borderRadius: "6px",
                            fontSize: "11px",
                            fontWeight: 800
                          }}
                        >
                          {threat.severity}
                        </span>
                      </td>

                      <td style={tdStyle}>
                        <span
                          style={{
                            ...actionStyle(threat.action),
                            display: "inline-block",
                            padding: "6px 10px",
                            borderRadius: "6px",
                            fontSize: "11px",
                            fontWeight: 800
                          }}
                        >
                          {threat.action}
                        </span>
                      </td>

                      <td style={tdStyle}>
                        <button
                          onClick={() => setSelectedThreat(threat)}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                            background: "#172033",
                            border: "1px solid #263449",
                            color: "#CBD5E1",
                            padding: "7px 10px",
                            borderRadius: "7px",
                            cursor: "pointer"
                          }}
                        >
                          <Eye size={14} />
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Details Modal */}
      {selectedThreat && (
        <div
          onClick={() => setSelectedThreat(null)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.65)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "20px",
            zIndex: 1000
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "100%",
              maxWidth: "650px",
              maxHeight: "90vh",
              overflowY: "auto",
              background: "#111827",
              border: "1px solid #263449",
              borderRadius: "16px",
              padding: "26px",
              boxShadow: "0 25px 80px rgba(0,0,0,0.45)"
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: "24px"
              }}
            >
              <div>
                <div
                  style={{
                    color: "#64748B",
                    fontSize: "11px",
                    letterSpacing: "1px",
                    fontWeight: 800,
                    marginBottom: "7px"
                  }}
                >
                  THREAT DETAILS
                </div>

                <h2 style={{ margin: 0 }}>
                  {selectedThreat.threat_type}
                </h2>
              </div>

              <button
                onClick={() => setSelectedThreat(null)}
                style={{
                  background: "#172033",
                  border: "1px solid #263449",
                  color: "#CBD5E1",
                  width: "36px",
                  height: "36px",
                  borderRadius: "8px",
                  cursor: "pointer"
                }}
              >
                <X size={18} />
              </button>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "12px"
              }}
            >
              <Detail label="Threat ID" value={`#${selectedThreat.id}`} />
              <Detail label="Protocol" value={selectedThreat.protocol} />
              <Detail label="Source IP" value={selectedThreat.source_ip} />
              <Detail
                label="Destination IP"
                value={selectedThreat.destination_ip}
              />
              <Detail label="Destination Port" value={selectedThreat.port} />
              <Detail
                label="Packets"
                value={selectedThreat.packets}
              />
              <Detail
                label="Bytes Transferred"
                value={selectedThreat.bytes_transferred}
              />
              <Detail
                label="Status"
                value={selectedThreat.status}
              />
              <Detail
                label="AI Anomaly Score"
                value={`${selectedThreat.anomaly_score}/100`}
              />
              <Detail
                label="Risk Score"
                value={`${selectedThreat.risk_score}/100`}
              />
              <Detail
                label="Severity"
                value={selectedThreat.severity}
              />
              <Detail
                label="Firewall Action"
                value={selectedThreat.action}
              />
            </div>

            <div
              style={{
                marginTop: "16px",
                padding: "14px",
                background: "#0B1120",
                borderRadius: "10px",
                border: "1px solid #1E293B"
              }}
            >
              <div
                style={{
                  color: "#64748B",
                  fontSize: "11px",
                  fontWeight: 800,
                  marginBottom: "7px"
                }}
              >
                DETECTED AT
              </div>

              <div style={{ color: "#CBD5E1" }}>
                {formatDate(selectedThreat.created_at)}
              </div>
            </div>

            <div
              style={{
                marginTop: "16px",
                padding: "15px",
                borderRadius: "10px",
                background:
                  selectedThreat.action === "BLOCK"
                    ? "rgba(239,68,68,0.08)"
                    : "rgba(34,197,94,0.08)",
                border:
                  selectedThreat.action === "BLOCK"
                    ? "1px solid rgba(239,68,68,0.2)"
                    : "1px solid rgba(34,197,94,0.2)"
              }}
            >
              <strong>AI Response: </strong>
              {selectedThreat.action === "BLOCK"
                ? `The ${selectedThreat.threat_type} was classified as ${selectedThreat.severity} risk and the adaptive firewall selected BLOCK.`
                : `The connection was classified as ${selectedThreat.severity} risk and the policy engine selected ${selectedThreat.action}.`}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        @media (max-width: 900px) {
          .threat-stats {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
      `}</style>
      </div>
    </PageLayout>
  );
}
function StatCard({ icon, title, value, color }) {
  return (
    <div
      style={{
        background: "#111827",
        border: "1px solid #1E293B",
        borderRadius: "12px",
        padding: "18px"
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center"
        }}
      >
        <div
          style={{
            width: "38px",
            height: "38px",
            borderRadius: "9px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color,
            background: `${color}18`
          }}
        >
          {icon}
        </div>
      </div>

      <div
        style={{
          marginTop: "17px",
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
          fontSize: "28px",
          fontWeight: 800
        }}
      >
        {value}
      </div>
    </div>
  );
}

function ScoreBar({ value, color }) {
  const score = Math.max(0, Math.min(100, Number(value) || 0));

  return (
    <div style={{ minWidth: "95px" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: "5px",
          fontSize: "11px",
          color: "#94A3B8"
        }}
      >
        <span>{score}</span>
        <span>/100</span>
      </div>

      <div
        style={{
          height: "5px",
          background: "#1E293B",
          borderRadius: "99px",
          overflow: "hidden"
        }}
      >
        <div
          style={{
            width: `${score}%`,
            height: "100%",
            background: color,
            borderRadius: "99px"
          }}
        />
      </div>
    </div>
  );
}

function Detail({ label, value }) {
  return (
    <div
      style={{
        background: "#0B1120",
        border: "1px solid #1E293B",
        borderRadius: "9px",
        padding: "12px"
      }}
    >
      <div
        style={{
          color: "#64748B",
          fontSize: "10px",
          fontWeight: 800,
          textTransform: "uppercase",
          marginBottom: "5px"
        }}
      >
        {label}
      </div>

      <div
        style={{
          color: "#E2E8F0",
          fontSize: "13px",
          fontWeight: 600,
          wordBreak: "break-word"
        }}
      >
        {String(value ?? "N/A")}
      </div>
    </div>
  );
}

const filterSelectStyle = {
  background: "#0B1120",
  color: "#CBD5E1",
  border: "1px solid #263449",
  borderRadius: "8px",
  padding: "10px 12px",
  fontSize: "13px",
  outline: "none",
  cursor: "pointer"
};

const thStyle = {
  textAlign: "left",
  padding: "13px 15px",
  whiteSpace: "nowrap"
};

const tdStyle = {
  padding: "15px",
  verticalAlign: "middle",
  fontSize: "13px",
  color: "#CBD5E1"
};

const codeStyle = {
  background: "#0B1120",
  padding: "5px 8px",
  borderRadius: "5px",
  color: "#94A3B8",
  fontFamily: "monospace",
  fontSize: "12px"
};
