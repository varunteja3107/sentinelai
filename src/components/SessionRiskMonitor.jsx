import { useEffect, useState } from "react";
import { Activity } from "lucide-react";

const KEY = "sentinelai_session_risk";

const initialSessions = [
  { id: "SES-001", user: "admin", device: "MacBook-Air", resource: "Security Dashboard", risk: 12, age: 18, active: true },
  { id: "SES-002", user: "analyst", device: "Windows-Workstation", resource: "Threat Analytics", risk: 38, age: 75, active: true },
  { id: "SES-003", user: "unknown-user", device: "Unknown-Endpoint", resource: "Firewall Rules", risk: 86, age: 12, active: true }
];

const decision = risk => risk >= 80 ? "BLOCK" : risk >= 30 ? "MFA" : "ALLOW";

const colors = {
  ALLOW: "#4ADE80",
  MFA: "#FBBF24",
  BLOCK: "#F87171",
  TERMINATED: "#94A3B8"
};

const buttonStyle = {
  color: "white",
  border: 0,
  borderRadius: 6,
  padding: "7px 9px",
  fontSize: 11,
  fontWeight: 700,
  cursor: "pointer"
};

export default function SessionRiskMonitor() {
  const [sessions, setSessions] = useState(() => {
    try {
      const saved = localStorage.getItem(KEY);
      return saved ? JSON.parse(saved) : initialSessions;
    } catch {
      return initialSessions;
    }
  });

  const [history, setHistory] = useState([]);

  useEffect(() => {
    localStorage.setItem(KEY, JSON.stringify(sessions));
  }, [sessions]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setSessions(previous => previous.map(session => {
        if (!session.active) return session;

        const age = session.age + 1;
        const risk = Math.min(
          100,
          session.risk + (age > 120 && age % 5 === 0 ? 2 : 0)
        );

        return { ...session, age, risk };
      }));
    }, 15000);

    return () => window.clearInterval(timer);
  }, []);

  const log = (message, session) => {
    setHistory(previous => [{
      id: `${Date.now()}-${Math.random()}`,
      message,
      user: session.user,
      time: new Date().toLocaleString()
    }, ...previous].slice(0, 30));
  };

  const updateSession = (id, action) => {
    setSessions(previous => previous.map(session => {
      if (session.id !== id || !session.active) return session;

      let updated = { ...session };

      if (action === "risk") {
        updated.risk = Math.min(100, updated.risk + 25);
        updated.status = decision(updated.risk);
        log(`Simulated suspicious activity. Risk increased to ${updated.risk}`, updated);
      } else if (action === "reassess") {
        updated.status = decision(updated.risk);
        log(`Session reassessed: ${updated.status}`, updated);
      } else if (action === "terminate") {
        updated.active = false;
        updated.status = "TERMINATED";
        log("Session terminated", updated);
      }

      return updated;
    }));
  };

  const createSession = () => {
    const session = {
      id: `SES-${Date.now().toString().slice(-6)}`,
      user: "demo-user",
      device: "New-Endpoint",
      resource: "Security Dashboard",
      risk: 10,
      age: 0,
      active: true,
      status: "ALLOW"
    };

    setSessions(previous => [session, ...previous]);
    log("New demo session created", session);
  };

  const active = sessions.filter(s => s.active);
  const mfa = active.filter(s => decision(s.risk) === "MFA").length;
  const blocked = active.filter(s => decision(s.risk) === "BLOCK").length;

  const panel = {
    background: "#0B1120",
    border: "1px solid #263449",
    borderRadius: 9,
    padding: 14
  };

  return (
    <section style={{
      marginTop: 22,
      padding: 22,
      borderRadius: 14,
      background: "#111827",
      border: "1px solid #1E293B",
      color: "#E2E8F0"
    }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: 12
      }}>
        <h2 style={{ margin: 0, fontSize: 19 }}>
          <Activity size={19} style={{ verticalAlign: "middle", marginRight: 8 }} />
          Session Risk & Continuous Monitoring
        </h2>

        <button onClick={createSession} style={{
          ...buttonStyle,
          background: "#0E7490"
        }}>
          + Create demo session
        </button>
      </div>

      <p style={{ color: "#94A3B8", fontSize: 12 }}>
        Active session inventory, risk reassessment and adaptive access decisions.
      </p>

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
        gap: 12,
        marginTop: 16
      }}>
        {[
          ["ACTIVE SESSIONS", active.length, "#67E8F9"],
          ["MFA REQUIRED", mfa, "#FBBF24"],
          ["BLOCKED", blocked, "#F87171"]
        ].map(([label, value, color]) => (
          <div key={label} style={panel}>
            <div style={{ color: "#94A3B8", fontSize: 10, fontWeight: 800 }}>
              {label}
            </div>
            <div style={{ color, fontSize: 27, fontWeight: 800, marginTop: 7 }}>
              {value}
            </div>
          </div>
        ))}
      </div>

      <div style={{ overflowX: "auto", marginTop: 18 }}>
        <table style={{ width: "100%", minWidth: 720, borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ color: "#94A3B8", textAlign: "left" }}>
              {["SESSION / USER", "DEVICE", "RESOURCE", "RISK", "DECISION", "ACTIONS"].map(label => (
                <th key={label} style={{ padding: 10, borderBottom: "1px solid #334155" }}>
                  {label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sessions.map(session => {
              const status = session.active ? decision(session.risk) : "TERMINATED";

              return (
                <tr key={session.id}>
                  <td style={{ padding: 10, borderBottom: "1px solid #263449" }}>
                    <strong>{session.id}</strong>
                    <div style={{ color: "#94A3B8", marginTop: 4 }}>
                      {session.user} · {session.age} min
                    </div>
                  </td>
                  <td style={{ padding: 10, borderBottom: "1px solid #263449" }}>
                    {session.device}
                  </td>
                  <td style={{ padding: 10, borderBottom: "1px solid #263449" }}>
                    {session.resource}
                  </td>
                  <td style={{ padding: 10, borderBottom: "1px solid #263449", fontWeight: 800 }}>
                    {session.risk}/100
                  </td>
                  <td style={{
                    padding: 10,
                    borderBottom: "1px solid #263449",
                    color: colors[status],
                    fontWeight: 800
                  }}>
                    {status}
                  </td>
                  <td style={{ padding: 10, borderBottom: "1px solid #263449" }}>
                    {session.active ? (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                        <button onClick={() => updateSession(session.id, "reassess")}
                          style={{ ...buttonStyle, background: "#155E75" }}>
                          Reassess
                        </button>
                        <button onClick={() => updateSession(session.id, "risk")}
                          style={{ ...buttonStyle, background: "#92400E" }}>
                          Simulate risk
                        </button>
                        <button onClick={() => updateSession(session.id, "terminate")}
                          style={{ ...buttonStyle, background: "#991B1B" }}>
                          Terminate
                        </button>
                      </div>
                    ) : "Closed"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div style={{ ...panel, marginTop: 18 }}>
        <h3 style={{ margin: "0 0 10px", fontSize: 14 }}>Session Event History</h3>
        {history.length === 0 ? (
          <p style={{ color: "#94A3B8", fontSize: 12 }}>No session events yet.</p>
        ) : history.map(event => (
          <div key={event.id} style={{
            padding: "9px 0",
            borderBottom: "1px solid #263449",
            fontSize: 12
          }}>
            <strong>{event.message}</strong>
            <div style={{ color: "#94A3B8", marginTop: 4 }}>
              {event.user} · {event.time}
            </div>
          </div>
        ))}
      </div>

      <p style={{ color: "#64748B", fontSize: 11, lineHeight: 1.6 }}>
        Demo simulation: session age updates every 15 seconds while this page is
        open. Data is stored in this browser. These actions do not terminate real
        network connections or enforce backend access policies.
      </p>
    </section>
  );
}
