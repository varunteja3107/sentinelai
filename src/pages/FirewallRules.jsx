import { useEffect, useState } from "react";
import {
  Shield,
  ShieldCheck,
  Ban,
  Activity,
  Lock,
  RefreshCw,
  Wifi,
  AlertTriangle
} from "lucide-react";

const API = "https://sentinelai-wnno.onrender.com";

export default function FirewallRules() {
  const [data, setData] = useState(null);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const loadFirewall = async () => {
    try {
      setRefreshing(true);

      const [firewallResponse, threatsResponse] = await Promise.all([
        fetch(`${API}/api/firewall/status`),
        fetch(`${API}/api/threats/recent?limit=20`)
      ]);

      if (!firewallResponse.ok || !threatsResponse.ok) {
        throw new Error("Backend request failed");
      }

      const firewall = await firewallResponse.json();
      const recentThreats = await threatsResponse.json();

      setData(firewall);
      setThreats(Array.isArray(recentThreats) ? recentThreats : []);
      setError("");
    } catch (err) {
      console.error(err);
      setError("Unable to connect to SecureX AI firewall.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadFirewall();

    const interval = setInterval(loadFirewall, 10000);

    return () => clearInterval(interval);
  }, []);

  const blockedThreats = threats.filter(
    (threat) => threat.action === "BLOCK"
  );

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
              Adaptive Firewall
            </h1>

            <p style={{ color: "#94A3B8", marginTop: "8px" }}>
              AI-driven dynamic firewall response and connection control
            </p>
          </div>

          <button
            onClick={loadFirewall}
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

        {/* Main status */}
        <div
          style={{
            background:
              "linear-gradient(120deg, rgba(0,212,255,0.10), rgba(17,24,39,0.95))",
            border: "1px solid rgba(0,212,255,0.25)",
            borderRadius: "15px",
            padding: "25px",
            marginBottom: "20px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "17px" }}>
            <div
              style={{
                width: "58px",
                height: "58px",
                borderRadius: "13px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "rgba(34,197,94,0.12)",
                color: "#22C55E"
              }}
            >
              <ShieldCheck size={32} />
            </div>

            <div>
              <div
                style={{
                  color: "#64748B",
                  fontSize: "11px",
                  fontWeight: 800,
                  letterSpacing: "1px"
                }}
              >
                FIREWALL STATUS
              </div>

              <h2 style={{ margin: "5px 0 0", fontSize: "25px" }}>
                {loading ? "Loading..." : data?.firewall || "UNKNOWN"}
              </h2>

              <div style={{ color: "#22C55E", marginTop: "5px" }}>
                {data?.mode || "Checking protection mode..."}
              </div>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              color: "#22C55E",
              fontWeight: 800
            }}
          >
            <span
              style={{
                width: "9px",
                height: "9px",
                borderRadius: "50%",
                background: "#22C55E",
                boxShadow: "0 0 12px rgba(34,197,94,.7)"
              }}
            />
            PROTECTION ACTIVE
          </div>
        </div>

        {/* Stats */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "16px",
            marginBottom: "20px"
          }}
        >
          <Stat
            icon={<Ban />}
            title="Blocked Connections"
            value={data?.blocked_connections ?? 0}
            color="#EF4444"
          />

          <Stat
            icon={<Shield />}
            title="Blocked IPs"
            value={data?.blocked_ips?.length ?? 0}
            color="#F59E0B"
          />

          <Stat
            icon={<Lock />}
            title="Zero Trust"
            value={data?.zero_trust ? "ENABLED" : "DISABLED"}
            color="#00D4FF"
          />

          <Stat
            icon={<Activity />}
            title="Dynamic Response"
            value={data?.dynamic_response ? "ACTIVE" : "OFF"}
            color="#22C55E"
          />
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "20px"
          }}
        >
          {/* Firewall capabilities */}
          <section
            style={{
              background: "#111827",
              border: "1px solid #1E293B",
              borderRadius: "14px",
              padding: "23px"
            }}
          >
            <h2 style={{ margin: 0, fontSize: "19px" }}>
              Protection Controls
            </h2>

            <p style={{ color: "#64748B", fontSize: "13px" }}>
              Current adaptive firewall capabilities
            </p>

            <Control
              icon={<ShieldCheck />}
              title="AI Adaptive Firewall"
              value={data?.firewall === "ACTIVE"}
            />

            <Control
              icon={<Activity />}
              title="Dynamic Threat Response"
              value={data?.dynamic_response}
            />

            <Control
              icon={<Lock />}
              title="Zero Trust Integration"
              value={data?.zero_trust}
            />

            <Control
              icon={<Wifi />}
              title="Simulation Mode"
              value={data?.simulation_mode}
            />
          </section>

          {/* Blocked IPs */}
          <section
            style={{
              background: "#111827",
              border: "1px solid #1E293B",
              borderRadius: "14px",
              padding: "23px"
            }}
          >
            <h2 style={{ margin: 0, fontSize: "19px" }}>
              Blocked Sources
            </h2>

            <p style={{ color: "#64748B", fontSize: "13px" }}>
              IP addresses currently identified for blocking
            </p>

            {data?.blocked_ips?.length ? (
              <div>
                {data.blocked_ips.map((ip) => (
                  <div
                    key={ip}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      padding: "13px",
                      marginTop: "10px",
                      borderRadius: "8px",
                      background: "rgba(239,68,68,0.07)",
                      border: "1px solid rgba(239,68,68,0.18)"
                    }}
                  >
                    <Ban size={17} color="#EF4444" />

                    <code
                      style={{
                        color: "#FCA5A5",
                        fontFamily: "monospace"
                      }}
                    >
                      {ip}
                    </code>

                    <span
                      style={{
                        marginLeft: "auto",
                        color: "#EF4444",
                        fontSize: "11px",
                        fontWeight: 800
                      }}
                    >
                      BLOCKED
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  padding: "35px 15px",
                  textAlign: "center",
                  color: "#64748B",
                  border: "1px dashed #263449",
                  borderRadius: "9px",
                  marginTop: "15px"
                }}
              >
                No blocked IPs currently reported.
              </div>
            )}
          </section>
        </div>

        {/* Recent firewall actions */}
        <section
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            marginTop: "20px",
            overflow: "hidden"
          }}
        >
          <div
            style={{
              padding: "20px 22px",
              borderBottom: "1px solid #1E293B"
            }}
          >
            <h2 style={{ margin: 0, fontSize: "19px" }}>
              Recent Firewall Actions
            </h2>

            <p
              style={{
                margin: "5px 0 0",
                color: "#64748B",
                fontSize: "13px"
              }}
            >
              Security events that triggered firewall decisions
            </p>
          </div>

          {blockedThreats.length === 0 ? (
            <div
              style={{
                padding: "40px",
                textAlign: "center",
                color: "#64748B"
              }}
            >
              No blocked events available.
            </div>
          ) : (
            blockedThreats.map((threat) => (
              <div
                key={threat.id}
                style={{
                  padding: "16px 22px",
                  borderBottom: "1px solid #1E293B",
                  display: "grid",
                  gridTemplateColumns: "1.3fr 1fr 1fr 120px 100px",
                  gap: "15px",
                  alignItems: "center"
                }}
              >
                <div>
                  <div style={{ fontWeight: 800 }}>
                    {threat.threat_type}
                  </div>
                  <div
                    style={{
                      color: "#64748B",
                      fontSize: "11px",
                      marginTop: "4px"
                    }}
                  >
                    Threat #{threat.id}
                  </div>
                </div>

                <code style={{ color: "#94A3B8" }}>
                  {threat.source_ip}
                </code>

                <div style={{ color: "#CBD5E1" }}>
                  Port {threat.port}
                </div>

                <div
                  style={{
                    color: threat.risk_score >= 60 ? "#EF4444" : "#F59E0B",
                    fontWeight: 800
                  }}
                >
                  Risk {threat.risk_score}
                </div>

                <span
                  style={{
                    textAlign: "center",
                    padding: "6px",
                    borderRadius: "6px",
                    background: "rgba(239,68,68,0.12)",
                    color: "#EF4444",
                    fontSize: "11px",
                    fontWeight: 900
                  }}
                >
                  BLOCK
                </span>
              </div>
            ))
          )}
        </section>

        {/* Demo disclaimer */}
        <div
          style={{
            marginTop: "18px",
            padding: "13px 16px",
            borderRadius: "9px",
            background: "rgba(245,158,11,0.06)",
            border: "1px solid rgba(245,158,11,0.16)",
            color: "#94A3B8",
            fontSize: "12px",
            display: "flex",
            gap: "9px",
            alignItems: "center"
          }}
        >
          <AlertTriangle size={16} color="#F59E0B" />
          Firewall actions are simulated for authorized security lab and
          demonstration purposes.
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
          fontSize: "24px",
          fontWeight: 900,
          marginTop: "5px"
        }}
      >
        {value}
      </div>
    </div>
  );
}

function Control({ icon, title, value }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "12px",
        padding: "14px",
        background: "#0B1120",
        border: "1px solid #1E293B",
        borderRadius: "9px",
        marginTop: "11px"
      }}
    >
      <div style={{ color: "#00D4FF" }}>{icon}</div>

      <span style={{ flex: 1, fontWeight: 700 }}>
        {title}
      </span>

      <span
        style={{
          color: value ? "#22C55E" : "#EF4444",
          fontSize: "11px",
          fontWeight: 900
        }}
      >
        {value ? "ACTIVE" : "OFF"}
      </span>
    </div>
  );
}
