import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  ShieldAlert,
  RefreshCw,
  Search
} from "lucide-react";

const API = "https://sentinelai-wnno.onrender.com";

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");

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
      </div>
    </div>
  );
}

function IncidentRow({ incident }) {
  const isCritical = incident.severity === "CRITICAL";
  const isHigh = incident.severity === "HIGH";

  const color = isCritical
    ? "#EF4444"
    : isHigh
      ? "#F97316"
      : "#F59E0B";

  return (
    <div
      style={{
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
