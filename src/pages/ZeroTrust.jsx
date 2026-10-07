import { useState } from "react";
import {
  ShieldCheck,
  UserCheck,
  MonitorCheck,
  MapPin,
  LockKeyhole,
  Activity,
  CheckCircle,
  AlertTriangle,
  XCircle,
  RefreshCw
} from "lucide-react";

const API = "https://sentinelai-wnno.onrender.com";

export default function ZeroTrust() {
  const [form, setForm] = useState({
    user: "admin",
    device: "MacBook-Air",
    resource: "Security Dashboard",
    location: "Bangalore",
    risk_score: 20,
    identity_verified: true,
    device_trusted: true
  });

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const evaluateAccess = async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API}/api/zero-trust/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          ...form,
          risk_score: Number(form.risk_score)
        })
      });

      if (!response.ok) {
        throw new Error("Zero Trust evaluation failed");
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      setError(
        "Unable to evaluate access. Make sure the SecureX AI backend is online."
      );
    } finally {
      setLoading(false);
    }
  };

  const decisionColor = (decision) => {
    if (decision === "ALLOW") return "#22C55E";
    if (decision === "MFA") return "#F59E0B";
    if (decision === "LIMIT") return "#F97316";
    return "#EF4444";
  };

  const decisionIcon = (decision) => {
    if (decision === "ALLOW") return <CheckCircle size={34} />;
    if (decision === "MFA") return <AlertTriangle size={34} />;
    if (decision === "LIMIT") return <LockKeyhole size={34} />;
    return <XCircle size={34} />;
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
              Zero Trust Center
            </h1>

            <p style={{ color: "#94A3B8", marginTop: "8px" }}>
              Continuous identity, device and risk-based access evaluation
            </p>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "10px 15px",
              borderRadius: "9px",
              background: "rgba(34,197,94,0.08)",
              border: "1px solid rgba(34,197,94,0.25)",
              color: "#22C55E",
              fontWeight: 700
            }}
          >
            <ShieldCheck size={18} />
            Zero Trust Active
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1.1fr 0.9fr",
            gap: "20px"
          }}
        >
          <section
            style={{
              background: "#111827",
              border: "1px solid #1E293B",
              borderRadius: "14px",
              padding: "24px"
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                marginBottom: "22px"
              }}
            >
              <Activity color="#00D4FF" />
              <div>
                <h2 style={{ margin: 0, fontSize: "19px" }}>
                  Access Evaluation
                </h2>
                <p
                  style={{
                    margin: "5px 0 0",
                    color: "#64748B",
                    fontSize: "13px"
                  }}
                >
                  Evaluate a user session against Zero Trust policies
                </p>
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "16px"
              }}
            >
              <Field
                icon={<UserCheck size={17} />}
                label="User"
                value={form.user}
                onChange={(value) =>
                  setForm({ ...form, user: value })
                }
              />

              <Field
                icon={<MonitorCheck size={17} />}
                label="Device"
                value={form.device}
                onChange={(value) =>
                  setForm({ ...form, device: value })
                }
              />

              <Field
                icon={<LockKeyhole size={17} />}
                label="Resource"
                value={form.resource}
                onChange={(value) =>
                  setForm({ ...form, resource: value })
                }
              />

              <Field
                icon={<MapPin size={17} />}
                label="Location"
                value={form.location}
                onChange={(value) =>
                  setForm({ ...form, location: value })
                }
              />
            </div>

            <div style={{ marginTop: "20px" }}>
              <label
                style={{
                  display: "block",
                  color: "#94A3B8",
                  fontSize: "12px",
                  fontWeight: 700,
                  marginBottom: "8px"
                }}
              >
                CURRENT RISK SCORE: {form.risk_score}/100
              </label>

              <input
                type="range"
                min="0"
                max="100"
                value={form.risk_score}
                onChange={(e) =>
                  setForm({
                    ...form,
                    risk_score: Number(e.target.value)
                  })
                }
                style={{
                  width: "100%",
                  accentColor: "#00D4FF"
                }}
              />

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  color: "#64748B",
                  fontSize: "11px"
                }}
              >
                <span>Trusted</span>
                <span>Suspicious</span>
                <span>Critical</span>
              </div>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "12px",
                marginTop: "22px"
              }}
            >
              <Toggle
                label="Identity Verified"
                checked={form.identity_verified}
                onChange={(value) =>
                  setForm({
                    ...form,
                    identity_verified: value
                  })
                }
              />

              <Toggle
                label="Device Trusted"
                checked={form.device_trusted}
                onChange={(value) =>
                  setForm({
                    ...form,
                    device_trusted: value
                  })
                }
              />
            </div>

            <button
              onClick={evaluateAccess}
              disabled={loading}
              style={{
                width: "100%",
                marginTop: "22px",
                padding: "14px",
                border: 0,
                borderRadius: "9px",
                background: "#00D4FF",
                color: "#06111C",
                fontWeight: 800,
                cursor: loading ? "wait" : "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "9px"
              }}
            >
              {loading ? (
                <>
                  <RefreshCw size={17} />
                  Evaluating...
                </>
              ) : (
                <>
                  <ShieldCheck size={18} />
                  Evaluate Access
                </>
              )}
            </button>

            {error && (
              <div
                style={{
                  marginTop: "15px",
                  padding: "12px",
                  borderRadius: "8px",
                  background: "rgba(239,68,68,0.08)",
                  border: "1px solid rgba(239,68,68,0.25)",
                  color: "#EF4444",
                  fontSize: "13px"
                }}
              >
                {error}
              </div>
            )}
          </section>

          <section
            style={{
              background: "#111827",
              border: "1px solid #1E293B",
              borderRadius: "14px",
              padding: "24px"
            }}
          >
            <h2 style={{ margin: 0, fontSize: "19px" }}>
              Zero Trust Decision
            </h2>

            <p
              style={{
                color: "#64748B",
                fontSize: "13px",
                marginTop: "6px"
              }}
            >
              AI risk + identity + device + context
            </p>

            {result ? (
              <div style={{ marginTop: "28px" }}>
                <div
                  style={{
                    padding: "25px",
                    borderRadius: "13px",
                    textAlign: "center",
                    background: `${decisionColor(result.decision)}10`,
                    border: `1px solid ${decisionColor(
                      result.decision
                    )}35`,
                    color: decisionColor(result.decision)
                  }}
                >
                  {decisionIcon(result.decision)}

                  <div
                    style={{
                      fontSize: "30px",
                      fontWeight: 900,
                      marginTop: "10px"
                    }}
                  >
                    {result.decision}
                  </div>

                  <div
                    style={{
                      color: "#94A3B8",
                      marginTop: "6px"
                    }}
                  >
                    Risk Score: {result.risk_score}/100
                  </div>
                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "12px",
                    marginTop: "18px"
                  }}
                >
                  <Result label="Identity" value={result.identity} />
                  <Result label="Device" value={result.device} />
                  <Result label="Context" value={result.context} />
                  <Result label="Decision" value={result.decision} />
                </div>

                <div
                  style={{
                    marginTop: "14px",
                    padding: "15px",
                    background: "#0B1120",
                    border: "1px solid #1E293B",
                    borderRadius: "9px"
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
                    POLICY EXPLANATION
                  </div>

                  <div
                    style={{
                      color: "#CBD5E1",
                      fontSize: "13px",
                      lineHeight: 1.6
                    }}
                  >
                    {result.reason}
                  </div>
                </div>
              </div>
            ) : (
              <div
                style={{
                  marginTop: "35px",
                  textAlign: "center",
                  padding: "55px 20px",
                  border: "1px dashed #263449",
                  borderRadius: "12px",
                  color: "#64748B"
                }}
              >
                <ShieldCheck
                  size={45}
                  color="#00D4FF"
                  style={{ marginBottom: "12px" }}
                />
                <div
                  style={{
                    color: "#CBD5E1",
                    fontWeight: 700
                  }}
                >
                  Ready for access evaluation
                </div>
                <div style={{ marginTop: "7px", fontSize: "13px" }}>
                  Configure the session and evaluate the request.
                </div>
              </div>
            )}
          </section>
        </div>

        <section
          style={{
            marginTop: "20px",
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "22px"
          }}
        >
          <h2 style={{ margin: 0, fontSize: "18px" }}>
            Zero Trust Principles
          </h2>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap: "14px",
              marginTop: "18px"
            }}
          >
            <Principle icon={<UserCheck />} title="Verify Identity" />
            <Principle icon={<MonitorCheck />} title="Trust Device" />
            <Principle icon={<Activity />} title="Assess Risk" />
            <Principle icon={<LockKeyhole />} title="Least Privilege" />
          </div>
        </section>
      </div>
    </div>
  );
}

function Field({ icon, label, value, onChange }) {
  return (
    <div>
      <label
        style={{
          display: "block",
          color: "#94A3B8",
          fontSize: "12px",
          fontWeight: 700,
          marginBottom: "7px"
        }}
      >
        {label}
      </label>

      <div style={{ position: "relative" }}>
        <span
          style={{
            position: "absolute",
            left: "12px",
            top: "50%",
            transform: "translateY(-50%)",
            color: "#64748B"
          }}
        >
          {icon}
        </span>

        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          style={{
            width: "100%",
            boxSizing: "border-box",
            background: "#0B1120",
            border: "1px solid #263449",
            borderRadius: "8px",
            padding: "11px 12px 11px 39px",
            color: "#F8FAFC",
            outline: "none"
          }}
        />
      </div>
    </div>
  );
}

function Toggle({ label, checked, onChange }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      style={{
        background: "#0B1120",
        border: "1px solid #263449",
        borderRadius: "9px",
        padding: "13px",
        color: "#CBD5E1",
        display: "flex",
        alignItems: "center",
        gap: "10px",
        cursor: "pointer",
        textAlign: "left"
      }}
    >
      <span
        style={{
          width: "19px",
          height: "19px",
          borderRadius: "5px",
          background: checked ? "#22C55E" : "#1E293B",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "#06111C",
          fontSize: "12px",
          fontWeight: 900
        }}
      >
        {checked ? "✓" : ""}
      </span>
      <span>{label}</span>
    </button>
  );
}

function Result({ label, value }) {
  return (
    <div
      style={{
        padding: "12px",
        background: "#0B1120",
        border: "1px solid #1E293B",
        borderRadius: "8px"
      }}
    >
      <div
        style={{
          color: "#64748B",
          fontSize: "10px",
          fontWeight: 800,
          marginBottom: "5px"
        }}
      >
        {label.toUpperCase()}
      </div>
      <div style={{ color: "#E2E8F0", fontSize: "13px" }}>
        {value ?? "N/A"}
      </div>
    </div>
  );
}

function Principle({ icon, title }) {
  return (
    <div
      style={{
        padding: "16px",
        borderRadius: "9px",
        background: "#0B1120",
        border: "1px solid #1E293B",
        display: "flex",
        alignItems: "center",
        gap: "10px",
        color: "#00D4FF"
      }}
    >
      {icon}
      <span style={{ color: "#CBD5E1", fontWeight: 700 }}>
        {title}
      </span>
    </div>
  );
}
