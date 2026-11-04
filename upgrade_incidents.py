from pathlib import Path
import shutil

path = Path("src/pages/Incidents.jsx")
source = path.read_text()

backup = Path("backups/feature_sprint/incidents")
backup.mkdir(parents=True, exist_ok=True)
shutil.copy2(path, backup / "Incidents.jsx.before")

if "incidentAnalyticsPanel" in source:
    print("Incident analytics already installed.")
    raise SystemExit(0)

# Add icons
source = source.replace(
    "  Search,\n  X",
    "  Search,\n  Download,\n  BarChart3,\n  Network,\n  X",
    1
)

# Add analytics calculations before return
marker = '  const open = incidents.length - resolved;\n\n  return ('

addition = '''  const open = incidents.length - resolved;

  const statusCounts = incidents.reduce((counts, incident) => {
    const status = String(incident.status || "OPEN").toUpperCase();
    counts[status] = (counts[status] || 0) + 1;
    return counts;
  }, {});

  const severityCounts = incidents.reduce((counts, incident) => {
    const severity = String(incident.severity || "UNKNOWN").toUpperCase();
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, {});

  const riskGroups = {
    Critical: incidents.filter(i => Number(i.risk_score || 0) >= 80).length,
    High: incidents.filter(i => Number(i.risk_score || 0) >= 60 && Number(i.risk_score || 0) < 80).length,
    Medium: incidents.filter(i => Number(i.risk_score || 0) >= 30 && Number(i.risk_score || 0) < 60).length,
    Low: incidents.filter(i => Number(i.risk_score || 0) < 30).length,
  };

  const averageRisk = incidents.length
    ? Math.round(
        incidents.reduce((sum, item) => sum + Number(item.risk_score || 0), 0) /
        incidents.length
      )
    : 0;

  const sourceCounts = incidents.reduce((counts, incident) => {
    const ip = incident.source_ip;
    if (ip) counts[ip] = (counts[ip] || 0) + 1;
    return counts;
  }, {});

  const repeatedSources = Object.entries(sourceCounts)
    .filter(([, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  function exportIncidents() {
    const rows = incidents.map(item => ({
      id: item.id,
      title: item.title,
      severity: item.severity,
      status: item.status,
      risk_score: item.risk_score,
      threat_type: item.threat_type,
      source_ip: item.source_ip,
      destination_ip: item.destination_ip,
      created_at: item.created_at,
      notes: item.notes,
    }));

    const columns = Object.keys(rows[0] || {
      id: "", title: "", severity: "", status: "",
      risk_score: "", threat_type: "", source_ip: "",
      destination_ip: "", created_at: "", notes: "",
    });

    const escapeCsv = value =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const csv = [
      columns.join(","),
      ...rows.map(row =>
        columns.map(column => escapeCsv(row[column])).join(",")
      ),
    ].join("\\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "sentinelai-incident-report.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  return ('''

if marker not in source:
    raise SystemExit("Could not find analytics calculation insertion point.")

source = source.replace(marker, addition, 1)

# Insert analytics dashboard before the Active Incidents section
section_marker = '''        <section
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            overflow: "hidden"
          }}
        >'''

analytics_ui = '''        <section
          data-section="incidentAnalyticsPanel"
          style={{
            background: "#111827",
            border: "1px solid #1E293B",
            borderRadius: "14px",
            padding: "20px",
            marginBottom: "20px"
          }}
        >
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "12px",
            marginBottom: "18px"
          }}>
            <div>
              <h2 style={{ margin: 0, fontSize: "19px" }}>
                <BarChart3 size={19} color="#22D3EE" /> Incident Analytics
              </h2>
              <p style={{ color: "#94A3B8", fontSize: "12px" }}>
                Risk distribution, investigation status and source correlation
              </p>
            </div>
            <button
              type="button"
              onClick={exportIncidents}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "10px 13px",
                borderRadius: "8px",
                background: "#172337",
                border: "1px solid #334155",
                color: "#E2E8F0",
                cursor: "pointer",
                fontWeight: 700
              }}
            >
              <Download size={15} /> Export Incident CSV
            </button>
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))",
            gap: "12px",
            marginBottom: "20px"
          }}>
            {[
              ["Average Risk", averageRisk, "#22D3EE"],
              ["Critical Risk", riskGroups.Critical, "#F87171"],
              ["Investigating", statusCounts.INVESTIGATING || 0, "#FBBF24"],
              ["False Positives", statusCounts.FALSE_POSITIVE || 0, "#A78BFA"]
            ].map(([label, value, color]) => (
              <div key={label} style={{
                background: "#0B1120",
                border: "1px solid #263449",
                borderRadius: "10px",
                padding: "14px"
              }}>
                <div style={{ color: "#94A3B8", fontSize: "12px" }}>{label}</div>
                <div style={{
                  color,
                  fontSize: "25px",
                  fontWeight: 900,
                  marginTop: "8px"
                }}>{value}</div>
              </div>
            ))}
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(230px,1fr))",
            gap: "22px"
          }}>
            <div>
              <h3 style={{ fontSize: "14px" }}>Risk Score Distribution</h3>
              {Object.entries(riskGroups).map(([label, count]) => {
                const color = {
                  Critical: "#F87171",
                  High: "#FB923C",
                  Medium: "#FBBF24",
                  Low: "#4ADE80"
                }[label];

                const percent = incidents.length
                  ? (count / incidents.length) * 100
                  : 0;

                return (
                  <div key={label} style={{ marginBottom: "13px" }}>
                    <div style={{
                      display: "flex",
                      justifyContent: "space-between",
                      fontSize: "12px",
                      marginBottom: "6px"
                    }}>
                      <span>{label}</span>
                      <strong>{count}</strong>
                    </div>
                    <div style={{
                      height: "8px",
                      background: "#263449",
                      borderRadius: "20px",
                      overflow: "hidden"
                    }}>
                      <div style={{
                        width: `${percent}%`,
                        height: "100%",
                        background: color,
                        borderRadius: "20px"
                      }} />
                    </div>
                  </div>
                );
              })}
              <p style={{ color: "#64748B", fontSize: "11px" }}>
                Risk bands: Critical ≥80, High 60–79, Medium 30–59, Low below 30.
              </p>
            </div>

            <div>
              <h3 style={{ fontSize: "14px" }}>Investigation Status</h3>
              {["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map(status => (
                <div key={status} style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "10px 0",
                  borderBottom: "1px solid #263449",
                  fontSize: "13px"
                }}>
                  <span>{status.replaceAll("_", " ")}</span>
                  <strong>{statusCounts[status] || 0}</strong>
                </div>
              ))}
            </div>

            <div>
              <h3 style={{ fontSize: "14px" }}>
                <Network size={16} color="#22D3EE" /> Repeated Source IPs
              </h3>
              {repeatedSources.length === 0 ? (
                <p style={{ color: "#94A3B8", fontSize: "12px" }}>
                  No repeated source IPs found in current incidents.
                </p>
              ) : repeatedSources.map(([ip, count]) => (
                <div key={ip} style={{
                  display: "flex",
                  justifyContent: "space-between",
                  gap: "10px",
                  padding: "10px 0",
                  borderBottom: "1px solid #263449",
                  fontSize: "12px"
                }}>
                  <code>{ip}</code>
                  <strong style={{ color: "#FBBF24" }}>{count} incidents</strong>
                </div>
              ))}
              <p style={{ color: "#64748B", fontSize: "11px" }}>
                Repeated sources are investigation leads, not confirmed attackers.
              </p>
            </div>
          </div>
        </section>

''' + section_marker

if section_marker not in source:
    raise SystemExit("Could not find Active Incidents section. No changes made.")

source = source.replace(section_marker, analytics_ui, 1)

# Send the admin token when loading protected audit logs.
source = source.replace(
    'const response = await fetch(`${API}/api/logs`);',
    '''const token = sessionStorage.getItem("sentinelai_admin_token");
      const response = await fetch(`${API}/api/logs`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });''',
    1
)

# Send the token with incident updates as well.
source = source.replace(
    'headers: { "Content-Type": "application/json" },',
    '''headers: {
            "Content-Type": "application/json",
            ...(sessionStorage.getItem("sentinelai_admin_token")
              ? { Authorization: `Bearer ${sessionStorage.getItem("sentinelai_admin_token")}` }
              : {}),
          },''',
    1
)

path.write_text(source)
print("Incident analytics upgrade applied.")
print("Added risk distribution and average risk.")
print("Added investigation status analytics.")
print("Added repeated source IP correlation.")
print("Added CSV incident export.")
print("Added admin token to audit and update requests.")
print("Backup saved.")
