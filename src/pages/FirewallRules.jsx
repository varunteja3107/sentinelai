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
  const token = sessionStorage.getItem("sentinelai_admin_token");
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
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

  // Advanced firewall policy simulator and analytics
  const [policyInput, setPolicyInput] = useState({
    source_ip: "198.51.100.25",
    destination_ip: "",
    port: "443",
    protocol: "TCP",
  });
  const [policyResult, setPolicyResult] = useState(null);
  const [policyLoading, setPolicyLoading] = useState(false);
  const [firewallAnalytics, setFirewallAnalytics] = useState(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [advancedError, setAdvancedError] = useState("");
  // Advanced firewall rule management
  const [managedRules, setManagedRules] = useState([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [ruleSaving, setRuleSaving] = useState(false);
  const [editingRuleId, setEditingRuleId] = useState(null);
  const [ruleForm, setRuleForm] = useState({
    name: "",
    source: "Any",
    destination: "Any",
    port: "443",
    protocol: "TCP",
    action: "BLOCK",
    priority: 100,
    description: "",
  });



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
    loadManagedRules();
    const timer = setInterval(() => loadFirewall(false), 10000);
    return () => clearInterval(timer);
  }, [loadFirewall]);

  async function loadManagedRules(showSpinner = false) {
    if (showSpinner) setRulesLoading(true);
    try {
      const result = await apiRequest("/api/firewall/rules");
      setManagedRules(Array.isArray(result) ? result : []);
    } catch (err) {
      setAdvancedError(err.message || "Unable to load firewall rules.");
    } finally {
      setRulesLoading(false);
    }
  }

  async function saveFirewallRule(event) {
    event.preventDefault();
    setRuleSaving(true);
    setAdvancedError("");
    setNotice("");

    try {
      const payload = {
        ...ruleForm,
        name: ruleForm.name.trim(),
        source: ruleForm.source.trim() || "Any",
        destination: ruleForm.destination.trim() || "Any",
        port: String(ruleForm.port).trim(),
        protocol: ruleForm.protocol,
        action: ruleForm.action,
        priority: Number(ruleForm.priority),
        description: ruleForm.description.trim(),
      };

      const editing = editingRuleId !== null;
      await apiRequest(
        editing
          ? `/api/firewall/rules/${editingRuleId}`
          : "/api/firewall/rules",
        {
          method: editing ? "PUT" : "POST",
          body: JSON.stringify(payload),
        }
      );

      setNotice(editing ? "Firewall rule updated." : "Firewall rule created.");
      setEditingRuleId(null);
      setRuleForm({
        name: "",
        source: "Any",
        destination: "Any",
        port: "443",
        protocol: "TCP",
        action: "BLOCK",
        priority: 100,
        description: "",
      });
      await loadManagedRules(true);
    } catch (err) {
      setAdvancedError(err.message || "Unable to save firewall rule.");
    } finally {
      setRuleSaving(false);
    }
  }

  function editFirewallRule(rule) {
    if (!rule.custom) return;

    setEditingRuleId(rule.id);
    setRuleForm({
      name: rule.name || "",
      source: rule.source || "Any",
      destination: rule.destination || "Any",
      port: rule.port || "*",
      protocol: rule.protocol || "TCP",
      action: rule.action || "BLOCK",
      priority: Number(rule.priority) || 100,
      description: rule.description || "",
    });
    setAdvancedError("");
    setNotice("");
  }

  async function changeFirewallRuleStatus(rule) {
    try {
      setAdvancedError("");
      await apiRequest(
        `/api/firewall/rules/${rule.id}/status?enabled=${rule.status !== "ACTIVE"}`,
        { method: "POST" }
      );
      setNotice(`Rule "${rule.name}" status updated.`);
      await loadManagedRules();
    } catch (err) {
      setAdvancedError(err.message || "Unable to update rule status.");
    }
  }

  async function deleteFirewallRule(rule) {
    if (!rule.custom) return;
    if (!window.confirm(`Delete firewall rule "${rule.name}"?`)) return;

    try {
      setAdvancedError("");
      await apiRequest(`/api/firewall/rules/${rule.id}`, {
        method: "DELETE",
      });
      if (editingRuleId === rule.id) {
        setEditingRuleId(null);
      }
      setNotice(`Rule "${rule.name}" deleted.`);
      await loadManagedRules();
    } catch (err) {
      setAdvancedError(err.message || "Unable to delete firewall rule.");
    }
  }

  async function loadAdvancedFirewallData() {
    setAnalyticsLoading(true);
    try {
      const result = await apiRequest("/api/firewall/analytics");
      setFirewallAnalytics(result);
      setAdvancedError("");
    } catch (err) {
      setAdvancedError(err.message || "Unable to load firewall analytics.");
    } finally {
      setAnalyticsLoading(false);
    }
  }

  async function runPolicySimulation(event) {
    event.preventDefault();
    setPolicyLoading(true);
    setPolicyResult(null);
    setAdvancedError("");

    try {
      const params = new URLSearchParams({
        port: policyInput.port,
        protocol: policyInput.protocol,
      });

      if (policyInput.source_ip.trim()) {
        params.set("source_ip", policyInput.source_ip.trim());
      }

      if (policyInput.destination_ip.trim()) {
        params.set("destination_ip", policyInput.destination_ip.trim());
      }

      const result = await apiRequest(
        `/api/firewall/simulate?${params.toString()}`
      );

      setPolicyResult(result);
    } catch (err) {
      setAdvancedError(err.message || "Policy simulation failed.");
    } finally {
      setPolicyLoading(false);
    }
  }

  useEffect(() => {
    loadAdvancedFirewallData();
  }, []);

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

        <section style={{ ...panel, marginBottom: 20 }}>
  <div style={{
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    flexWrap: "wrap",
    gap: 12,
    marginBottom: 16,
  }}>
    <div>

        <section style={{ ...panel, marginBottom: 20 }}>
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 12,
            marginBottom: 18,
          }}>
            <div>
              <h2 style={{ margin: "0 0 6px", fontSize: 20 }}>
                <Shield size={20} color="#22D3EE" /> Advanced Rule Builder
              </h2>
              <p style={muted}>
                Create and manage persistent, priority-based firewall policies.
              </p>
            </div>
            <Badge color="#22D3EE">POLICY MANAGEMENT</Badge>
          </div>

          {advancedError && (
            <div role="alert" style={{
              padding: 12,
              marginBottom: 14,
              border: "1px solid #7F1D1D",
              borderRadius: 8,
              color: "#FCA5A5",
              background: "#450A0A33",
            }}>
              {advancedError}
            </div>
          )}

          <form onSubmit={saveFirewallRule}>
            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(190px,1fr))",
              gap: 13,
            }}>
              <label style={muted}>
                Rule name *
                <input
                  required
                  maxLength={128}
                  style={{ ...inputStyle, marginTop: 7 }}
                  value={ruleForm.name}
                  onChange={(e) => setRuleForm({
                    ...ruleForm, name: e.target.value,
                  })}
                  placeholder="Block suspicious traffic"
                />
              </label>

              <label style={muted}>
                Source IP / CIDR
                <input
                  style={{ ...inputStyle, marginTop: 7 }}
                  value={ruleForm.source}
                  onChange={(e) => setRuleForm({
                    ...ruleForm, source: e.target.value,
                  })}
                  placeholder="Any or 192.168.1.0/24"
                />
              </label>

              <label style={muted}>
                Destination IP / CIDR
                <input
                  style={{ ...inputStyle, marginTop: 7 }}
                  value={ruleForm.destination}
                  onChange={(e) => setRuleForm({
                    ...ruleForm, destination: e.target.value,
                  })}
                  placeholder="Any or 10.0.0.0/24"
                />
              </label>

              <label style={muted}>
                Destination port *
                <input
                  required
                  style={{ ...inputStyle, marginTop: 7 }}
                  value={ruleForm.port}
                  onChange={(e) => setRuleForm({
                    ...ruleForm, port: e.target.value,
                  })}
                  placeholder="443, 8000-8100, or *"
                />
              </label>

              <label style={muted}>
                Protocol
                <select
                  style={{ ...inputStyle, marginTop: 7 }}
                  value={ruleForm.protocol}
                  onChange={(e) => setRuleForm({
                    ...ruleForm, protocol: e.target.value,
                    port: e.target.value === "ICMP" ? "*" : ruleForm.port,
                  })}
                >
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                  <option value="ANY">ANY</option>
                </select>
              </label>

              <label style={muted}>
                Action
                <select
                  style={{ ...inputStyle, marginTop: 7 }}
                  value={ruleForm.action}
                  onChange={(e) => setRuleForm({
                    ...ruleForm, action: e.target.value,
                  })}
                >
                  <option value="ALLOW">ALLOW</option>
                  <option value="BLOCK">BLOCK</option>
                  <option value="MONITOR">MONITOR</option>
                </select>
              </label>

              <label style={muted}>
                Priority (1-1000)
                <input
                  required
                  type="number"
                  min="1"
                  max="1000"
                  style={{ ...inputStyle, marginTop: 7 }}
                  value={ruleForm.priority}
                  onChange={(e) => setRuleForm({
                    ...ruleForm, priority: e.target.value,
                  })}
                />
              </label>
            </div>

            <label style={{ ...muted, display: "block", marginTop: 13 }}>
              Description
              <textarea
                maxLength={500}
                rows={2}
                style={{ ...inputStyle, marginTop: 7, resize: "vertical" }}
                value={ruleForm.description}
                onChange={(e) => setRuleForm({
                  ...ruleForm, description: e.target.value,
                })}
                placeholder="Explain when and why this policy should apply."
              />
            </label>

            <div style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
              marginTop: 14,
            }}>
              <button type="submit" disabled={ruleSaving} style={cyanButton}>
                <ShieldCheck size={16} />
                {ruleSaving
                  ? "Saving..."
                  : editingRuleId !== null
                    ? "Update Rule"
                    : "Create Firewall Rule"}
              </button>

              {editingRuleId !== null && (
                <button
                  type="button"
                  style={buttonStyle}
                  onClick={() => {
                    setEditingRuleId(null);
                    setRuleForm({
                      name: "",
                      source: "Any",
                      destination: "Any",
                      port: "443",
                      protocol: "TCP",
                      action: "BLOCK",
                      priority: 100,
                      description: "",
                    });
                    setAdvancedError("");
                  }}
                >
                  Cancel Editing
                </button>
              )}

              <button
                type="button"
                style={buttonStyle}
                onClick={() => loadManagedRules(true)}
                disabled={rulesLoading}
              >
                <RefreshCw size={15} />
                {rulesLoading ? "Loading..." : "Refresh Rules"}
              </button>
            </div>
          </form>

          <div style={{
            borderTop: "1px solid #263449",
            marginTop: 22,
            paddingTop: 18,
          }}>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 10,
              marginBottom: 13,
            }}>
              <h3 style={{ margin: 0, fontSize: 17 }}>Firewall Policy List</h3>
              <span style={muted}>
                {managedRules.length} total rules
              </span>
            </div>

            {rulesLoading && <p style={muted}>Loading firewall rules...</p>}

            {!rulesLoading && managedRules.length === 0 && (
              <p style={muted}>No firewall rules returned by the API.</p>
            )}

            <div style={{ display: "grid", gap: 10 }}>
              {managedRules.map((rule) => (
                <div
                  key={`${rule.custom ? "custom" : "default"}-${rule.id}`}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "minmax(0,1fr) auto",
                    gap: 12,
                    alignItems: "center",
                    padding: 13,
                    border: "1px solid #263449",
                    borderRadius: 10,
                    background: "#0B1120",
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{
                      display: "flex",
                      gap: 8,
                      alignItems: "center",
                      flexWrap: "wrap",
                    }}>
                      <strong>{rule.name}</strong>
                      <Badge color={
                        rule.action === "BLOCK" ? "#F87171"
                          : rule.action === "ALLOW" ? "#4ADE80"
                          : "#FBBF24"
                      }>{rule.action}</Badge>
                      <Badge color={
                        rule.status === "ACTIVE" ? "#4ADE80" : "#94A3B8"
                      }>{rule.status}</Badge>
                      <span style={muted}>
                        {rule.custom ? "CUSTOM" : "BUILT-IN"}
                      </span>
                    </div>
                    <div style={{
                      ...muted,
                      marginTop: 7,
                      overflowWrap: "anywhere",
                    }}>
                      Source: {rule.source} · Destination: {rule.destination}
                      <br />
                      Port: {rule.port} · Protocol: {rule.protocol}
                      · Priority: {rule.priority}
                    </div>
                    {rule.description && (
                      <p style={{ ...muted, margin: "6px 0 0" }}>
                        {rule.description}
                      </p>
                    )}
                  </div>

                  {rule.custom && (
                    <div style={{
                      display: "flex",
                      gap: 7,
                      flexWrap: "wrap",
                      justifyContent: "flex-end",
                    }}>
                      <button
                        type="button"
                        style={buttonStyle}
                        onClick={() => editFirewallRule(rule)}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        style={buttonStyle}
                        onClick={() => changeFirewallRuleStatus(rule)}
                      >
                        {rule.status === "ACTIVE" ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        style={{
                          ...buttonStyle,
                          color: "#FCA5A5",
                          borderColor: "#7F1D1D",
                        }}
                        onClick={() => deleteFirewallRule(rule)}
                      >
                        Delete
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>

        <h2 style={{ margin: "0 0 6px", fontSize: 19 }}>
        <ShieldCheck size={19} color="#22D3EE" /> Policy Simulator
      </h2>
      <p style={muted}>
        Dry-run a traffic request against active firewall policies.
      </p>
    </div>
    <Badge color="#FBBF24">DRY RUN</Badge>
  </div>

  <form onSubmit={runPolicySimulation}>
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
      gap: 12,
      alignItems: "end",
    }}>
      <label style={muted}>
        Source IP
        <input
          style={{ ...inputStyle, marginTop: 7 }}
          value={policyInput.source_ip}
          onChange={(e) => setPolicyInput({
            ...policyInput,
            source_ip: e.target.value,
          })}
          placeholder="198.51.100.25"
        />
      </label>

            <label style={muted}>
        Destination IP
        <input
          style={{ ...inputStyle, marginTop: 7 }}
          value={policyInput.destination_ip}
          onChange={(e) => setPolicyInput({
            ...policyInput,
            destination_ip: e.target.value,
          })}
          placeholder="10.0.0.10 or 10.0.0.0/24"
        />
      </label>
<label style={muted}>
        Destination port
        <input
          style={{ ...inputStyle, marginTop: 7 }}
          type="number"
          min="1"
          max="65535"
          required
          value={policyInput.port}
          onChange={(e) => setPolicyInput({
            ...policyInput,
            port: e.target.value,
          })}
        />
      </label>

      <label style={muted}>
        Protocol
        <select
          style={{ ...inputStyle, marginTop: 7 }}
          value={policyInput.protocol}
          onChange={(e) => setPolicyInput({
            ...policyInput,
            protocol: e.target.value,
          })}
        >
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
        </select>
      </label>

      <button
        type="submit"
        disabled={policyLoading}
        style={cyanButton}
      >
        <Activity size={16} />
        {policyLoading ? "Simulating..." : "Simulate Policy"}
      </button>
    </div>
  </form>

  {policyResult && (
    <div style={{
      marginTop: 18,
      padding: 16,
      borderRadius: 10,
      border: "1px solid #334155",
      background: "#0B1120",
    }}>
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        flexWrap: "wrap",
        gap: 10,
      }}>
        <div>
          <div style={muted}>SIMULATED DECISION</div>
          <div style={{
            fontSize: 25,
            fontWeight: 900,
            marginTop: 5,
            color: policyResult.decision === "ALLOW"
              ? "#4ADE80"
              : policyResult.decision === "BLOCK"
                ? "#F87171"
                : "#FBBF24",
          }}>
            {policyResult.decision}
          </div>
        </div>
        <Badge color="#22D3EE">
          {policyResult.rule_type}
        </Badge>
      </div>

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
        gap: 12,
        marginTop: 15,
      }}>
        <div>
          <div style={muted}>WINNING RULE</div>
          <strong>
            {policyResult.winning_rule?.name || "Default Deny"}
          </strong>
        </div>
        <div>
          <div style={muted}>PRIORITY</div>
          <strong>{policyResult.priority}</strong>
        </div>
        <div>
          <div style={muted}>MATCHING RULES</div>
          <strong>{policyResult.matching_rule_count}</strong>
        </div>
      </div>

      <p style={{ ...muted, marginTop: 15 }}>
        {policyResult.explanation}
      </p>

      {policyResult.matching_rules?.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <strong style={{ fontSize: 13 }}>Matching policies</strong>
          {policyResult.matching_rules.map((rule, index) => (
            <div
              key={`${rule.id}-${index}`}
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 10,
                flexWrap: "wrap",
                padding: "10px 0",
                borderBottom: "1px solid #263449",
                fontSize: 13,
              }}
            >
              <span>{rule.name}</span>
              <span>
                {rule.action} · Priority {rule.priority}
              </span>
            </div>
          ))}
        </div>
      )}

      <p style={{ ...muted, fontSize: 11, marginBottom: 0 }}>
        {policyResult.note}
      </p>
    </div>
  )}
</section>

<section style={{ ...panel, marginBottom: 20 }}>
  <div style={{
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    flexWrap: "wrap",
    gap: 12,
    marginBottom: 16,
  }}>
    <div>
      <h2 style={{ margin: "0 0 6px", fontSize: 19 }}>
        <Activity size={19} color="#22D3EE" /> Rule Hit Analytics
      </h2>
      <p style={muted}>
        Historical firewall decisions from the security audit log.
      </p>
    </div>
    <button
      type="button"
      onClick={loadAdvancedFirewallData}
      disabled={analyticsLoading}
      style={buttonStyle}
    >
      <RefreshCw size={15} />
      {analyticsLoading ? "Loading..." : "Refresh analytics"}
    </button>
  </div>

  {advancedError && (
    <p role="alert" style={{ color: "#FCA5A5", fontSize: 13 }}>
      {advancedError}
    </p>
  )}

  {firewallAnalytics ? (
    <>
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
        gap: 12,
      }}>
        <Stat
          icon={Activity}
          title="Recorded Decisions"
          value={firewallAnalytics.total_decisions}
        />
        <Stat
          icon={ShieldCheck}
          title="Allowed"
          value={firewallAnalytics.actions?.ALLOW ?? 0}
          color="#4ADE80"
        />
        <Stat
          icon={Ban}
          title="Blocked"
          value={firewallAnalytics.actions?.BLOCK ?? 0}
          color="#F87171"
        />
        <Stat
          icon={AlertTriangle}
          title="Monitor"
          value={firewallAnalytics.actions?.MONITOR ?? 0}
          color="#FBBF24"
        />
      </div>

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
        gap: 20,
        marginTop: 22,
      }}>
        <div>
          <h3 style={{ fontSize: 15 }}>Top matching rules</h3>
          {(firewallAnalytics.top_rules || []).length ? (
            firewallAnalytics.top_rules.map((item) => (
              <div key={item.rule} style={{
                padding: "10px 0",
                borderBottom: "1px solid #263449",
                display: "flex",
                justifyContent: "space-between",
                gap: 10,
                fontSize: 13,
              }}>
                <span>{item.rule}</span>
                <strong>{item.hits}</strong>
              </div>
            ))
          ) : (
            <p style={muted}>No recorded rule hits yet.</p>
          )}
        </div>

        <div>
          <h3 style={{ fontSize: 15 }}>Top source IPs</h3>
          {(firewallAnalytics.top_sources || []).length ? (
            firewallAnalytics.top_sources.map((item) => (
              <div key={item.source_ip} style={{
                padding: "10px 0",
                borderBottom: "1px solid #263449",
                display: "flex",
                justifyContent: "space-between",
                gap: 10,
                fontSize: 13,
              }}>
                <code>{item.source_ip}</code>
                <strong>{item.hits}</strong>
              </div>
            ))
          ) : (
            <p style={muted}>No source IP records yet.</p>
          )}
        </div>
      </div>

      <p style={{ ...muted, marginTop: 15, fontSize: 11 }}>
        Based on up to {firewallAnalytics.sample_limit} recent recorded
        firewall decisions. These are audit-log counts, not live packet
        counters.
      </p>
    </>
  ) : (
    !advancedError && (
      <p style={muted}>
        {analyticsLoading ? "Loading firewall analytics..." : "No analytics available."}
      </p>
    )
  )}
</section>

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
