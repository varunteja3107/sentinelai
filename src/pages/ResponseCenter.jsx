import { useCallback, useEffect, useState } from "react";
import { ClipboardCheck, RefreshCw, ShieldAlert, RotateCcw } from "lucide-react";
import PageLayout from "../components/PageLayout";
import "./ResponseCenter.css";

const API = (
  import.meta.env.VITE_RESPONSE_API_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const initialForm = {
  threat_type: "PORT_SCAN",
  risk_score: 85,
  recommended_action: "Temporarily isolate the suspected device for investigation",
  requested_by: "admin",
};

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(sessionStorage.getItem("sentinelai_admin_token")
        ? {
            Authorization: `Bearer ${sessionStorage.getItem("sentinelai_admin_token")}`,
          }
        : {}),
      ...options.headers,
    },
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/api/auth/login")) {
      sessionStorage.removeItem("sentinelai_admin_token");
      window.dispatchEvent(new Event("sentinelai:auth-expired"));
    }

    const error = new Error(
      typeof data.detail === "string"
        ? data.detail
        : `Request failed with HTTP ${response.status}`
    );
    error.status = response.status;
    throw error;
  }

  return data;
}

function getItems(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.items)) return data.items;
  if (Array.isArray(data?.logs)) return data.logs;
  if (Array.isArray(data?.data)) return data.data;
  return [];
}

function formatDate(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function ResponseCenter() {
  const [actions, setActions] = useState([]);
  const [logs, setLogs] = useState([]);
  const [form, setForm] = useState(initialForm);
  const [reviewNotes, setReviewNotes] = useState({});
  const [reviewers, setReviewers] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [token, setToken] = useState(
    () => sessionStorage.getItem("sentinelai_admin_token") || ""
  );
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [loginLoading, setLoginLoading] = useState(false);

  async function handleLogin(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    setLoginLoading(true);

    try {
      const result = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(loginForm),
      });

      if (!result.access_token) {
        throw new Error("The server did not return an access token.");
      }

      sessionStorage.setItem("sentinelai_admin_token", result.access_token);
      setToken(result.access_token);
      setLoginForm({ username: "", password: "" });
      setMessage("Admin login successful.");
    } catch (err) {
      setError(err.message || "Login failed. Check your credentials.");
    } finally {
      setLoginLoading(false);
    }
  }

  async function handleLogout() {
    let serverRevoked = false;

    try {
      await apiRequest("/api/auth/logout", {
        method: "POST",
      });
      serverRevoked = true;
    } catch (err) {
      console.error("Server-side logout failed:", err.message);
    } finally {
      sessionStorage.removeItem("sentinelai_admin_token");
      setToken("");
      setActions([]);
      setLogs([]);
      setError("");
      setMessage(
        serverRevoked
          ? "You have been securely logged out."
          : "You have been logged out locally, but server-side revocation could not be confirmed. Please reconnect and check your session."
      );
    }
  }

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const [actionData, logData] = await Promise.all([
        apiRequest("/api/response-actions"),
        apiRequest("/api/logs"),
      ]);

      setActions(getItems(actionData));
      setLogs(getItems(logData).filter((log) =>
        String(log.event_type || "").startsWith("RESPONSE_ACTION_")
      ));
    } catch (err) {
      setError(`${err.message}. Check that the SentinelAI backend is running on port 8000.`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const expireSession = () => {
      setToken("");
      setActions([]);
      setLogs([]);
      setError("Your admin session has expired. Please sign in again.");
    };

    window.addEventListener("sentinelai:auth-expired", expireSession);

    if (token) {
      loadData();
    } else {
      setLoading(false);
    }

    return () => {
      window.removeEventListener("sentinelai:auth-expired", expireSession);
    };
  }, [token, loadData]);

  async function createAction(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setMessage("");

    try {
      await apiRequest("/api/response-actions", {
        method: "POST",
        body: JSON.stringify({
          ...form,
          risk_score: Number(form.risk_score),
          incident_id: null,
        }),
      });

      setMessage("Response recommendation created successfully.");
      setForm(initialForm);
      await loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  async function reviewAction(action, decision) {
    const reviewer = (reviewers[action.id] || "admin").trim();

    if (!reviewer) {
      setError("Enter a reviewer name before making a decision.");
      return;
    }

    const verb = decision === "APPROVED" ? "approve" : "reject";

    if (!window.confirm(`Are you sure you want to ${verb} action #${action.id}?`)) {
      return;
    }

    setSaving(true);
    setError("");
    setMessage("");

    try {
      await apiRequest(`/api/response-actions/${action.id}/review`, {
        method: "POST",
        body: JSON.stringify({
          reviewed_by: reviewer,
          decision,
          review_note: reviewNotes[action.id] || "",
        }),
      });

      setMessage(`Action #${action.id} marked ${decision}.`);
      await loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  async function rollbackAction(action) {
    const reviewer = (reviewers[action.id] || "admin").trim();

    if (!reviewer) {
      setError("Enter a reviewer name before requesting rollback.");
      return;
    }

    if (!window.confirm(`Record a simulated rollback for action #${action.id}?`)) {
      return;
    }

    setSaving(true);
    setError("");
    setMessage("");

    try {
      await apiRequest(`/api/response-actions/${action.id}/rollback`, {
        method: "POST",
        body: JSON.stringify({
          reviewed_by: reviewer,
          review_note: reviewNotes[action.id] || "Rollback requested from Response Center",
        }),
      });

      setMessage(`Simulated rollback recorded for action #${action.id}.`);
      await loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  if (!token) {
    return (
      <PageLayout
        title="Admin Login"
        subtitle="Sign in to access SentinelAI's protected Response Center."
      >
        <div className="response-center">
          <section className="response-panel" style={{ maxWidth: 480, margin: "40px auto" }}>
            <div className="response-panel-heading">
              <div>
                <h2>Administrator sign in</h2>
                <p>Use your configured SentinelAI admin credentials.</p>
              </div>
            </div>

            {error && <div className="response-notice error" role="alert">{error}</div>}
            {message && <div className="response-notice success" role="status">{message}</div>}

            <form className="response-form" onSubmit={handleLogin}>
              <label className="response-form-wide">
                Username
                <input
                  autoComplete="username"
                  required
                  maxLength={128}
                  value={loginForm.username}
                  onChange={(event) =>
                    setLoginForm({ ...loginForm, username: event.target.value })
                  }
                />
              </label>

              <label className="response-form-wide">
                Password
                <input
                  type="password"
                  autoComplete="current-password"
                  required
                  maxLength={1024}
                  value={loginForm.password}
                  onChange={(event) =>
                    setLoginForm({ ...loginForm, password: event.target.value })
                  }
                />
              </label>

              <div className="response-form-actions">
                <button type="submit" disabled={loginLoading}>
                  {loginLoading ? "Signing in..." : "Sign in"}
                </button>
              </div>
            </form>
          </section>
        </div>
      </PageLayout>
    );
  }

  const visibleActions = filter === "ALL"
    ? actions
    : actions.filter((action) => action.status === filter);

  const pendingCount = actions.filter((action) => action.status === "PENDING").length;
  const approvedCount = actions.filter((action) => action.status === "APPROVED").length;
  const rolledBackCount = actions.filter((action) => action.rollback_status === "ROLLED_BACK").length;

  return (
    <PageLayout
      title="Response Center"
      subtitle="Review AI recommendations, approve simulated actions, and track audit history."
    >
      <div className="response-center">
        <div className="response-panel-heading response-heading-row">
          <p>Signed in as administrator</p>
          <button className="response-refresh" onClick={handleLogout} disabled={saving}>
            Log out
          </button>
        </div>

        <div className="response-banner">
          <div className="response-banner-icon"><ShieldAlert size={23} /></div>
          <div>
            <strong>Simulation mode enabled</strong>
            <p>Actions are recorded for demonstration and auditing. No real firewall rules or network devices are changed.</p>
          </div>
          <span className="response-mode">SIMULATED</span>
        </div>

        {error && <div className="response-notice error" role="alert">{error}</div>}
        {message && <div className="response-notice success" role="status">{message}</div>}

        <div className="response-stats">
          <article className="response-stat">
            <span>Total actions</span>
            <strong>{actions.length}</strong>
          </article>
          <article className="response-stat">
            <span>Awaiting review</span>
            <strong>{pendingCount}</strong>
          </article>
          <article className="response-stat">
            <span>Approved</span>
            <strong>{approvedCount}</strong>
          </article>
          <article className="response-stat">
            <span>Rolled back</span>
            <strong>{rolledBackCount}</strong>
          </article>
        </div>

        <section className="response-panel">
          <div className="response-panel-heading">
            <div>
              <h2><ClipboardCheck size={19} /> Create a recommendation</h2>
              <p>Submit a proposed response for human review.</p>
            </div>
          </div>

          <form className="response-form" onSubmit={createAction}>
            <label>
              Threat type
              <select
                value={form.threat_type}
                onChange={(e) => setForm({ ...form, threat_type: e.target.value })}
              >
                <option value="PORT_SCAN">Port scan</option>
                <option value="DOS">DoS</option>
                <option value="DDOS">DDoS</option>
                <option value="BRUTE_FORCE">Brute force</option>
                <option value="SUSPICIOUS_TRAFFIC">Suspicious traffic</option>
                <option value="MALWARE">Malware</option>
                <option value="OTHER">Other</option>
              </select>
            </label>

            <label>
              Risk score (0–100)
              <input
                type="number"
                min="0"
                max="100"
                required
                value={form.risk_score}
                onChange={(e) => setForm({ ...form, risk_score: e.target.value })}
              />
            </label>

            <label className="response-form-wide">
              Recommended action
              <textarea
                required
                maxLength={500}
                value={form.recommended_action}
                onChange={(e) => setForm({ ...form, recommended_action: e.target.value })}
              />
            </label>

            <label>
              Requested by
              <input
                required
                maxLength={128}
                value={form.requested_by}
                onChange={(e) => setForm({ ...form, requested_by: e.target.value })}
              />
            </label>

            <div className="response-form-actions">
              <button type="submit" disabled={saving}>
                {saving ? "Please wait..." : "Create recommendation"}
              </button>
            </div>
          </form>
        </section>

        <section className="response-panel">
          <div className="response-panel-heading response-heading-row">
            <div>
              <h2>Response actions</h2>
              <p>Review each recommendation and its recorded status.</p>
            </div>
            <button className="response-refresh" onClick={loadData} disabled={loading || saving}>
              <RefreshCw size={15} /> Refresh
            </button>
          </div>

          <div className="response-filters">
            {["ALL", "PENDING", "APPROVED", "REJECTED"].map((status) => (
              <button
                key={status}
                className={filter === status ? "selected" : ""}
                onClick={() => setFilter(status)}
              >
                {status === "ALL" ? "All actions" : status}
              </button>
            ))}
          </div>

          {loading ? (
            <p className="response-empty">Loading response actions...</p>
          ) : visibleActions.length === 0 ? (
            <p className="response-empty">No actions in this view. Create a recommendation to get started.</p>
          ) : (
            <div className="response-action-list">
              {visibleActions.map((action) => (
                <article className="response-action" key={action.id}>
                  <div className="response-action-top">
                    <div>
                      <span className="response-action-id">ACTION #{action.id}</span>
                      <h3>{action.threat_type}</h3>
                    </div>
                    <span className={`response-status ${(action.status || "PENDING").toLowerCase()}`}>
                      {action.status || "PENDING"}
                    </span>
                  </div>

                  <p className="response-action-description">{action.recommended_action}</p>

                  <div className="response-action-meta">
                    <span>Risk <strong>{Number(action.risk_score || 0)}/100</strong></span>
                    <span>Requested by <strong>{action.requested_by || "system"}</strong></span>
                    <span>Created <strong>{formatDate(action.created_at)}</strong></span>
                  </div>

                  {action.reviewed_by && (
                    <p className="response-review-detail">
                      Reviewed by {action.reviewed_by}
                      {action.review_note ? ` · ${action.review_note}` : ""}
                    </p>
                  )}

                  {action.rollback_status === "ROLLED_BACK" && (
                    <p className="response-review-detail">
                      Simulated rollback recorded: {formatDate(action.rolled_back_at)}
                    </p>
                  )}

                  <div className="response-review-controls">
                    <input
                      aria-label={`Reviewer for action ${action.id}`}
                      placeholder="Reviewer name"
                      value={reviewers[action.id] ?? "admin"}
                      onChange={(e) => setReviewers({ ...reviewers, [action.id]: e.target.value })}
                    />
                    <input
                      aria-label={`Review note for action ${action.id}`}
                      placeholder="Review note (optional)"
                      value={reviewNotes[action.id] || ""}
                      onChange={(e) => setReviewNotes({ ...reviewNotes, [action.id]: e.target.value })}
                    />
                  </div>

                  <div className="response-action-buttons">
                    {action.status === "PENDING" && (
                      <>
                        <button disabled={saving} onClick={() => reviewAction(action, "APPROVED")}>
                          Approve
                        </button>
                        <button className="danger" disabled={saving} onClick={() => reviewAction(action, "REJECTED")}>
                          Reject
                        </button>
                      </>
                    )}
                    {action.status === "APPROVED" && action.rollback_status !== "ROLLED_BACK" && (
                      <button className="secondary" disabled={saving} onClick={() => rollbackAction(action)}>
                        <RotateCcw size={15} /> Record simulated rollback
                      </button>
                    )}
                    {action.rollback_status === "ROLLED_BACK" && (
                      <span className="response-rollback-label">Rollback recorded</span>
                    )}
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>

        <section className="response-panel">
          <div className="response-panel-heading">
            <div>
              <h2>Response audit trail</h2>
              <p>Recorded creation, review, and rollback events.</p>
            </div>
          </div>

          {logs.length === 0 ? (
            <p className="response-empty">No response audit events returned by the logs endpoint.</p>
          ) : (
            <div className="response-audit-list">
              {logs.slice(0, 30).map((log) => (
                <article className="response-audit-row" key={log.id ?? `${log.event_type}-${log.created_at}`}>
                  <span className="response-audit-dot" />
                  <div>
                    <strong>{log.event_type || "Security event"}</strong>
                    <p>{log.message || "No event description provided."}</p>
                    <small>{formatDate(log.created_at || log.timestamp)} · {log.severity || "INFO"}</small>
                  </div>
                  <span className="response-audit-action">{log.action || ""}</span>
                </article>
              ))}
            </div>
          )}
        </section>
      </div>
    </PageLayout>
  );
}

export default ResponseCenter;
