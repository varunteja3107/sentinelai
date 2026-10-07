import { useEffect, useState } from "react";
import {
  BarChart3,
  ShieldAlert,
  Ban,
  Activity,
  Target,
  RefreshCw,
  TrendingUp
} from "lucide-react";

const API = "https://sentinelai-wnno.onrender.com";

export default function Analytics() {
  const [data, setData] = useState(null);
  const [score, setScore] = useState(null);
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

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0B1120",
        color: "#F8FAFC",
        padding: "28px"
      }}
    >
      <div style={{ maxWidth: "1450px", margin: "0 auto" }}>
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
