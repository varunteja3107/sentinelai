from pathlib import Path
import shutil

path = Path("src/pages/FirewallRules.jsx")
source = path.read_text()

backup = Path("backups/feature_sprint/firewall_advanced")
backup.mkdir(parents=True, exist_ok=True)
shutil.copy2(path, backup / "FirewallRules.jsx.before")

if "loadAdvancedFirewallData" in source:
    print("Advanced firewall frontend already installed.")
    raise SystemExit(0)

old_api = '''async function apiRequest(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });'''

new_api = '''async function apiRequest(path, options = {}) {
  const token = sessionStorage.getItem("sentinelai_admin_token");
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });'''

if old_api not in source:
    raise SystemExit("Could not find API helper. No changes made.")

source = source.replace(old_api, new_api, 1)

state_marker = '''  const [simulating, setSimulating] = useState(false);'''

state_addition = '''  const [simulating, setSimulating] = useState(false);

  // Advanced firewall policy simulator and analytics
  const [policyInput, setPolicyInput] = useState({
    source_ip: "198.51.100.25",
    port: "443",
    protocol: "TCP",
  });
  const [policyResult, setPolicyResult] = useState(null);
  const [policyLoading, setPolicyLoading] = useState(false);
  const [firewallAnalytics, setFirewallAnalytics] = useState(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [advancedError, setAdvancedError] = useState("");'''

if state_marker not in source:
    raise SystemExit("Could not find state insertion point. No changes made.")

source = source.replace(state_marker, state_addition, 1)

function_marker = '''  const blockedThreats = threats.filter('''

functions = '''  async function loadAdvancedFirewallData() {
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

''' + function_marker

if function_marker not in source:
    raise SystemExit("Could not find function insertion point. No changes made.")

source = source.replace(function_marker, functions, 1)

# Insert the new panels immediately before Active Temporary Blocks.
heading = "Active Temporary Blocks"
heading_index = source.find(heading)

if heading_index < 0:
    raise SystemExit("Could not locate Active Temporary Blocks. No changes made.")

section_index = source.rfind("<section", 0, heading_index)

if section_index < 0:
    raise SystemExit("Could not locate the section insertion point. No changes made.")

ui = r'''<section style={{ ...panel, marginBottom: 20 }}>
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

'''

source = source[:section_index] + ui + source[section_index:]

path.write_text(source)
print("Firewall frontend upgraded successfully.")
print("Added policy simulator panel.")
print("Added rule hit analytics panel.")
print("Admin token is now attached to API requests.")
print("Backup saved.")
