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

const API = "https://sentinelai-wnno.onrender.com";

export default function ThreatDetection() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [selectedThreat, setSelectedThreat] = useState(null);

  const loadThreats = async () => {
    try {
      setRefreshing(true);

      const response = await fetch(`${API}/api/threats/recent?limit=50`);

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

  useEffect(() => {
    loadThreats();

    const interval = setInterval(loadThreats, 10000);

    return () => clearInterval(interval);
  }, []);

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

  const filteredThreats = threats.filter((threat) => {
    const value = search.toLowerCase();

    return (
      String(threat.threat_type || "").toLowerCase().includes(value) ||
      String(threat.source_ip || "").toLowerCase().includes(value) ||
      String(threat.destination_ip || "").toLowerCase().includes(value) ||
      String(threat.port || "").includes(value) ||
      String(threat.action || "").toLowerCase().includes(value)
    );
  });

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
    <div
      style={{
        minHeight: "100vh",
        background: "#0B1120",
        color: "#F8FAFC",
        padding: "28px"
      }}
    >
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
