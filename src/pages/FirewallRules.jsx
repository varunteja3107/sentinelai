import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Ban,
  Clock,
  Lock,
  RefreshCw,
  Shield,
  ShieldCheck,
  Wifi,
  XCircle,
} from "lucide-react";
import PageLayout from "../components/PageLayout";
import { API_BASE as API } from "../api";

const panel = {
  background: "#111827",
  border: "1px solid #263449",
  borderRadius: 14,
  padding: 20,
  color: "#E2E8F0",
  minWidth: 0,
};

const muted = { color: "#94A3B8", fontSize: 13 };
const inputStyle = {
  width: "100%",
  boxSizing: "border-box",
  padding: "11px 12px",
  background: "#0B1120",
  border: "1px solid #334155",
  borderRadius: 8,
  color: "#F8FAFC",
  outline: "none",
};
const buttonStyle = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 8,
  padding: "10px 14px",
  borderRadius: 8,
  border: "1px solid #334155",
  background: "#172337",
  color: "#E2E8F0",
  cursor: "pointer",
  fontWeight: 700,
};
const cyanButton = {
  ...buttonStyle,
  background: "#22D3EE",
  border: "1px solid #22D3EE",
  color: "#082F49",
};

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      body.detail || body.message || `Request failed (${response.status})`
    );
  }
  return body;
}

function Stat({ icon: Icon, title, value, color = "#22D3EE" }) {
  return (
    <div style={panel}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, color }}>
        <Icon size={19} />
        <span style={{ fontSize: 12, fontWeight: 700 }}>{title}</span>
      </div>
      <div style={{ fontSize: 25, fontWeight: 900, marginTop: 14 }}>
        {value}
      </div>
    </div>
  );
}

function Badge({ children, color = "#22D3EE" }) {
  return (
    <span
      style={{
        display: "inline-block",
        color,
        background: `${color}18`,
        border: `1px solid ${color}45`,
        borderRadius: 20,
        padding: "5px 9px",
        fontSize: 11,
        fontWeight: 800,
      }}
    >
      {children}
    </span>
  );
}

export default function FirewallRules() {
  const [data, setData] = useState(null);
  const [threats, setThreats] = useState([]);
  const [blocks, setBlocks] = useState([]);
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [sourceIp, setSourceIp] = useState("");
  const [duration, setDuration] = useState("300");
  const [reason, setReason] = useState("Manual security block");
  const [simulation, setSimulation] = useState(null);
  const [simulating, setSimulating] = useState(false);


  const loadFirewall = useCallback(async (showSpinner = true) => {
    if (showSpinner) setRefreshing(true);

    try {
      const results = await Promise.allSettled([
        apiRequest("/api/firewall/status"),
        apiRequest("/api/threats/recent?limit=20"),
        apiRequest("/api/firewall/blocks"),
        apiRequest("/api/firewall/protection/config"),
      ]);

      const [firewallResult, threatsResult, blocksResult, configResult] =
        results;

      if (firewallResult.status === "fulfilled") {
        setData(firewallResult.value);
      } else {
        throw firewallResult.reason;
      }

      if (threatsResult.status === "fulfilled") {
        const value = threatsResult.value;
        setThreats(Array.isArray(value) ? value : []);
      }

      if (blocksResult.status === "fulfilled") {
        setBlocks(
          Array.isArray(blocksResult.value.blocks)
            ? blocksResult.value.blocks
            : []
        );
      }

      if (configResult.status === "fulfilled") {
        setConfig(configResult.value);
      }

      const protectionFailed =
        blocksResult.status === "rejected" ||
        configResult.status === "rejected";

      setError(
        protectionFailed
          ? "Firewall status loaded, but protection details could not be loaded. Check the protection API endpoints."
          : ""
      );
    } catch (err) {
      console.error(err);
      setError(err.message || "Unable to connect to the firewall API.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadFirewall(false);
    const timer = setInterval(() => loadFirewall(false), 10000);
    return () => clearInterval(timer);
  }, [loadFirewall]);

  const blockedThreats = threats.filter(
    (threat) => String(threat.action || "").toUpperCase() === "BLOCK"
  );


  async function runTrafficSimulation() {
    if (simulating) return;

    const testIp = "198.51.100.25";
    let allowed = 0;
    let blocked = 0;
    const events = [];

    setSimulating(true);
    setError("");
    setNotice("");
    setSimulation({
      testIp, sent: 0, allowed: 0, blocked: 0,
      events: [], outcome: "Running simulation...",
    });

    try {
      for (let i = 1; i <= 21; i++) {
        const params = new URLSearchParams({
          port: "443",
          protocol: "TCP",
          source_ip: testIp,
        });

        const result = await apiRequest(
          `/api/firewall/evaluate?${params.toString()}`,
          { method: "POST" }
        );

        const action = String(result.action || "UNKNOWN").toUpperCase();
        if (action === "BLOCK") blocked++;
        if (action === "ALLOW") allowed++;

        events.unshift({
          id: i,
          action,
          rule: result.rule || result.rule_name || "Firewall evaluator",
          reason: result.block_reason || result.reason || "",
        });

        setSimulation({
          testIp, sent: i, allowed, blocked,
          events: [...events],
          outcome: "Running simulation...",
        });
      }

      setSimulation({
        testIp, sent: 21, allowed, blocked, events: [...events],
        outcome: blocked
          ? "Protection triggered: the API returned BLOCK decisions."
          : "No BLOCK decision was returned. Check rate-limit settings.",
      });

      setNotice(`Simulation finished: ${blocked} blocked and ${allowed} allowed decisions.`);
    } catch (err) {
      setError(`Simulation failed: ${err.message || "Firewall API request failed"}`);
      setSimulation((old) => old ? {
        ...old, outcome: "Simulation stopped because an API request failed.",
      } : old);
    } finally {
      await loadFirewall(false);
      setSimulating(false);
    }
  }

  async function createBlock(event) {
    event.preventDefault();
    setNotice("");
    setError("");

    const ip = sourceIp.trim();
    if (!ip) {
      setError("Enter an IP address.");
      return;
    }

    setBusy(true);
    try {
      const params = new URLSearchParams({
        source_ip: ip,
        duration_seconds: duration,
        reason: reason.trim() || "Manual security block",
      });

      const result = await apiRequest(
        `/api/firewall/blocks?${params.toString()}`,
        { method: "POST" }
      );

      setNotice(
        `Blocked ${result.source_ip}. This is a simulated firewall action.`
      );
      setSourceIp("");
      await loadFirewall(false);
    } catch (err) {
      setError(err.message || "Could not create the temporary block.");
    } finally {
      setBusy(false);
    }
  }

  async function releaseBlock(ip) {
    if (!window.confirm(`Release the temporary block for ${ip}?`)) return;

    setBusy(true);
    setError("");
    setNotice("");

    try {
      const params = new URLSearchParams({ source_ip: ip });
      await apiRequest(
        `/api/firewall/blocks/release?${params.toString()}`,
        { method: "POST" }
      );
      setNotice(`Temporary block released for ${ip}.`);
      await loadFirewall(false);
    } catch (err) {
      setError(err.message || `Could not release the block for ${ip}.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <PageLayout title="Adaptive Firewall">
      <div style={{ width: "100%", minWidth: 0, color: "#F8FAFC" }}>
        <header
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 14,
            marginBottom: 24,
          }}
        >
          <div>
            <div
              style={{
                color: "#64748B",
                fontSize: 12,
                fontWeight: 800,
                letterSpacing: 1.5,
              }}
            >
              SECURITY CONSOLE
            </div>
            <h1 style={{ margin: "7px 0 0", fontSize: 30 }}>
              Adaptive Firewall
            </h1>
            <p style={{ ...muted, marginTop: 8 }}>
              Dynamic firewall response, IP protection and rate limiting
            </p>
          </div>
          <button
            type="button"
            onClick={() => loadFirewall()}
            disabled={refreshing}
            style={buttonStyle}
          >
            <RefreshCw size={16} />
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </header>

        {error && (
          <div
            role="alert"
            style={{
              ...panel,
              marginBottom: 16,
              borderColor: "#7F1D1D",
              color: "#FCA5A5",
            }}
          >
            <AlertTriangle size={17} style={{ verticalAlign: "middle" }} />{" "}
            {error}
          </div>
        )}

        {notice && (
          <div
            role="status"
            style={{
              ...panel,
              marginBottom: 16,
              borderColor: "#166534",
              color: "#86EFAC",
            }}
          >
            <ShieldCheck size={17} style={{ verticalAlign: "middle" }} />{" "}
            {notice}
          </div>
        )}

        <section
          style={{
            ...panel,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 18,
            marginBottom: 18,
            background:
              "linear-gradient(120deg,rgba(0,212,255,.10),rgba(17,24,39,.95))",
            borderColor: "#164E63",
          }}
        >
          <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
            <ShieldCheck size={36} color="#22C55E" />
            <div>
              <div style={muted}>FIREWALL STATUS</div>
              <h2 style={{ margin: "5px 0", fontSize: 24 }}>
                {loading ? "Loading..." : data?.firewall || "UNKNOWN"}
              </h2>
              <div style={{ color: "#22D3EE", fontSize: 13 }}>
                {data?.mode || "Checking protection mode..."}
              </div>
            </div>
          </div>
          <Badge color={data?.simulation_mode ? "#FBBF24" : "#22C55E"}>
            {data?.simulation_mode ? "SIMULATION MODE" : "PROTECTION STATUS"}
          </Badge>
        </section>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(175px,1fr))",
            gap: 14,
            marginBottom: 20,
          }}
        >
          <Stat
            icon={Ban}
            title="Blocked Connections"
            value={data?.blocked_connections ?? 0}
            color="#F87171"
          />
          <Stat
            icon={Shield}
            title="Active Temporary Blocks"
            value={blocks.length}
            color="#FBBF24"
          />
          <Stat
            icon={Lock}
            title="Zero Trust"
            value={data?.zero_trust ? "ENABLED" : "DISABLED"}
          />
          <Stat
            icon={Activity}
            title="Dynamic Response"
            value={data?.dynamic_response ? "ACTIVE" : "OFF"}
            color="#4ADE80"
          />
        </div>


        <section style={{ ...panel, marginBottom: 20 }}>
          <div style={{
            display: "flex", justifyContent: "space-between",
            alignItems: "center", flexWrap: "wrap", gap: 14,
          }}>
            <div>
              <h2 style={{ margin: "0 0 6px", fontSize: 19 }}>
                <Activity size={19} color="#22D3EE" /> Traffic Simulation Lab
              </h2>
              <p style={muted}>
                Run 21 sequential HTTPS evaluations against the local firewall API
                using a reserved test IP. No external traffic is sent.
              </p>
            </div>
            <button
              type="button"
              disabled={simulating || loading}
              onClick={runTrafficSimulation}
              style={{
                ...cyanButton,
                opacity: simulating || loading ? 0.65 : 1,
                cursor: simulating || loading ? "not-allowed" : "pointer",
              }}
            >
              <Wifi size={16} />
              {simulating ? "Running simulation..." : "Run Traffic Simulation"}
            </button>
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))",
            gap: 12, marginTop: 16,
          }}>
            {[
              ["Requests sent", simulation?.sent ?? 0, "#22D3EE"],
              ["Allowed", simulation?.allowed ?? 0, "#4ADE80"],
              ["Blocked", simulation?.blocked ?? 0, "#F87171"],
            ].map(([label, value, color]) => (
              <div key={label} style={{
                background: "#0B1120", border: "1px solid #263449",
                borderRadius: 10, padding: 14,
              }}>
                <div style={muted}>{label}</div>
                <div style={{
                  fontSize: 25, fontWeight: 900, color, marginTop: 6,
                }}>{value}</div>
              </div>
            ))}
          </div>

          {simulation && (
            <div style={{ marginTop: 14 }}>
              <p style={{
                color: simulation.blocked ? "#86EFAC" : "#FBBF24",
              }}>{simulation.outcome}</p>
              <p style={muted}>
                Test source: <code>{simulation.testIp}</code> · Port 443/TCP
              </p>
              <div style={{ display: "grid", gap: 8, marginTop: 12 }}>
                {simulation.events.slice(0, 8).map((event) => (
                  <div key={event.id} style={{
                    display: "grid",
                    gridTemplateColumns: "80px 85px minmax(0,1fr)",
                    gap: 10, alignItems: "start", padding: 10,
                    background: "#0B1120", borderRadius: 8,
                    border: "1px solid #263449", fontSize: 12,
                  }}>
                    <span style={muted}>Request {event.id}</span>
                    <Badge color={
                      event.action === "BLOCK" ? "#F87171" :
                      event.action === "ALLOW" ? "#4ADE80" : "#FBBF24"
                    }>{event.action}</Badge>
                    <div style={{ overflowWrap: "anywhere" }}>
                      <div>{event.rule}</div>
                      {event.reason && <div style={muted}>{event.reason}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <p style={{ ...muted, marginBottom: 0, marginTop: 14 }}>
            Simulation only. This exercises the SentinelAI API and does not
            block packets through the macOS system firewall. Repeated runs may
            encounter an existing temporary block for the test IP.
          </p>
        </section>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(min(100%,320px),1fr))",
            gap: 18,
            marginBottom: 20,
          }}
        >
          <section style={panel}>
            <h2 style={{ margin: "0 0 6px", fontSize: 19 }}>
              <Shield size={19} color="#22D3EE" /> IP Protection Center
            </h2>
            <p style={muted}>
              Add a temporary simulated block for a valid IPv4 or IPv6 address.
            </p>

            <form onSubmit={createBlock} style={{ display: "grid", gap: 13 }}>
              <label style={{ fontSize: 13, fontWeight: 700 }}>
                IP address
                <input
                  value={sourceIp}
                  onChange={(e) => setSourceIp(e.target.value)}
                  placeholder="Example: 192.0.2.100"
                  autoComplete="off"
                  style={{ ...inputStyle, marginTop: 7 }}
                  required
                />
              </label>

              <label style={{ fontSize: 13, fontWeight: 700 }}>
                Block duration
                <select
                  value={duration}
                  onChange={(e) => setDuration(e.target.value)}
                  style={{ ...inputStyle, marginTop: 7 }}
                >
                  <option value="60">1 minute</option>
                  <option value="300">5 minutes</option>
                  <option value="900">15 minutes</option>
                  <option value="3600">1 hour</option>
                  <option value="86400">24 hours</option>
                </select>
              </label>

              <label style={{ fontSize: 13, fontWeight: 700 }}>
                Reason
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  maxLength={200}
                  placeholder="Reason for blocking"
                  style={{ ...inputStyle, marginTop: 7 }}
                />
              </label>

              <button
                type="submit"
                disabled={busy}
                style={{
                  ...cyanButton,
                  background: busy ? "#64748B" : "#22D3EE",
                }}
              >
                <Ban size={16} />
                {busy ? "Processing..." : "Create Temporary Block"}
              </button>
            </form>
            <p style={{ ...muted, marginBottom: 0 }}>
              Only use IP addresses you are authorized to test.
            </p>
          </section>

          <section style={panel}>
            <h2 style={{ margin: "0 0 6px", fontSize: 19 }}>
              <Activity size={19} color="#22D3EE" /> Rate-Limit Configuration
            </h2>
            <p style={muted}>
              Current backend protection thresholds.
            </p>

            <div style={{ display: "grid", gap: 12, marginTop: 18 }}>
              {[
                [
                  "Evaluation threshold",
                  config?.rate_limit_requests,
                  "evaluations",
                ],
                [
                  "Evaluation window",
                  config?.rate_limit_window_seconds,
                  "seconds",
                ],
                [
                  "Automatic block duration",
                  config?.temporary_block_seconds,
                  "seconds",
                ],
              ].map(([label, value, unit]) => (
                <div
                  key={label}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: 12,
                    padding: 13,
                    borderRadius: 9,
                    background: "#0B1120",
                    border: "1px solid #263449",
                  }}
                >
                  <span style={muted}>{label}</span>
                  <strong style={{ color: "#67E8F9", textAlign: "right" }}>
                    {value ?? "--"} {unit}
                  </strong>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 16 }}>
              <Badge color="#4ADE80">
                {config?.rate_limiting_enabled
                  ? "RATE LIMITING ENABLED"
                  : "STATUS UNAVAILABLE"}
              </Badge>
            </div>
            <p style={{ ...muted, marginBottom: 0 }}>
              Thresholds are displayed from the backend. This page does not
              modify the rate-limit configuration.
            </p>
          </section>
        </div>

        <section style={{ ...panel, marginBottom: 20 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 12,
            }}
          >
            <div>
              <h2 style={{ margin: 0, fontSize: 19 }}>
                <Ban size={19} color="#F87171" /> Active Temporary Blocks
              </h2>
              <p style={muted}>
                Automatically refreshed every 10 seconds.
              </p>
            </div>
            <Badge color={blocks.length ? "#F87171" : "#4ADE80"}>
              {blocks.length} ACTIVE
            </Badge>
          </div>

          {blocks.length === 0 ? (
            <div
              style={{
                padding: 28,
                textAlign: "center",
                color: "#94A3B8",
                border: "1px dashed #334155",
                borderRadius: 9,
                marginTop: 12,
              }}
            >
              <ShieldCheck size={25} />
              <p>No active temporary IP blocks.</p>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 12, marginTop: 14 }}>
              {blocks.map((block) => (
                <div
                  key={block.source_ip}
                  style={{
                    padding: 15,
                    borderRadius: 10,
                    border: "1px solid #7F1D1D",
                    background: "rgba(127,29,29,.13)",
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))",
                    gap: 13,
                    alignItems: "center",
                  }}
                >
                  <div>
                    <div style={muted}>SOURCE IP</div>
                    <code style={{ color: "#FCA5A5", fontSize: 14 }}>
                      {block.source_ip}
                    </code>
                  </div>
                  <div>
                    <div style={muted}>REASON</div>
                    <div style={{ marginTop: 4, overflowWrap: "anywhere" }}>
                      {block.reason}
                    </div>
                  </div>
                  <div>
                    <div style={muted}>TIME REMAINING</div>
                    <div
                      style={{
                        marginTop: 4,
                        color: "#FBBF24",
                        fontWeight: 800,
                      }}
                    >
                      <Clock size={14} style={{ verticalAlign: "middle" }} />{" "}
                      {Math.max(0, block.remaining_seconds ?? 0)} seconds
                    </div>
                  </div>
                  <div>
                    <div style={muted}>EXPIRES</div>
                    <div style={{ fontSize: 12, marginTop: 4 }}>
                      {block.expires_at
                        ? new Date(block.expires_at).toLocaleString()
                        : "Unknown"}
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => releaseBlock(block.source_ip)}
                    style={{
                      ...buttonStyle,
                      color: "#FCA5A5",
                      borderColor: "#7F1D1D",
                    }}
                  >
                    <XCircle size={16} />
                    Release block
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>

        <section style={panel}>
          <h2 style={{ margin: "0 0 6px", fontSize: 19 }}>
            <Activity size={19} color="#22D3EE" /> Recent Firewall Actions
          </h2>
          <p style={muted}>Recent threat records marked as blocked.</p>

          {blockedThreats.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", ...muted }}>
              No blocked threat records available.
            </div>
          ) : (
            <div style={{ display: "grid", gap: 10, marginTop: 14 }}>
              {blockedThreats.map((threat) => (
                <div
                  key={threat.id}
                  style={{
                    display: "grid",
                    gridTemplateColumns:
                      "repeat(auto-fit,minmax(115px,1fr))",
                    gap: 12,
                    alignItems: "center",
                    padding: 13,
                    border: "1px solid #263449",
                    borderRadius: 9,
                    background: "#0B1120",
                  }}
                >
                  <div>
                    <div style={muted}>THREAT</div>
                    {threat.threat_type || `Threat #${threat.id}`}
                  </div>
                  <div>
                    <div style={muted}>SOURCE IP</div>
                    <code>{threat.source_ip || "Unknown"}</code>
                  </div>
                  <div>
                    <div style={muted}>PORT</div>
                    {threat.port ?? "Unknown"}
                  </div>
                  <div>
                    <div style={muted}>RISK SCORE</div>
                    {threat.risk_score ?? "--"}
                  </div>
                  <Badge color="#F87171">BLOCK</Badge>
                </div>
              ))}
            </div>
          )}
        </section>

        <div
          style={{
            marginTop: 18,
            padding: 13,
            borderRadius: 9,
            background: "rgba(245,158,11,.06)",
            border: "1px solid rgba(245,158,11,.2)",
            color: "#CBD5E1",
            fontSize: 12,
            display: "flex",
            gap: 9,
            alignItems: "flex-start",
          }}
        >
          <AlertTriangle size={17} color="#FBBF24" />
          <span>
            <strong>Simulation mode:</strong> these actions update SentinelAI's
            simulated protection engine. They do not modify macOS's firewall or
            block real network packets. Temporary blocks and rate-limit
            counters currently reside in backend memory and reset when the
            backend restarts.
          </span>
        </div>
      </div>
    </PageLayout>
  );
}
