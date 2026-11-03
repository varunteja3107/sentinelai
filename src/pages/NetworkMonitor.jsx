import { API_BASE as API } from "../api";
import { lazy, Suspense, useEffect, useRef, useState } from "react";
import {
  Activity,
  Server,
  Wifi,
  ArrowUp,
  ArrowDown,
} from "lucide-react";
import PageLayout from "../components/PageLayout";
const NetworkTopology = lazy(
  () => import("../components/network/NetworkTopology")
);

function formatTrafficRate(bytesPerSecond) {
  if (bytesPerSecond === null || bytesPerSecond === undefined) {
    return "Measuring...";
  }

  if (bytesPerSecond >= 1024 * 1024) {
    return `${(bytesPerSecond / (1024 * 1024)).toFixed(2)} MB/s`;
  }

  if (bytesPerSecond >= 1024) {
    return `${(bytesPerSecond / 1024).toFixed(2)} KB/s`;
  }

  return `${bytesPerSecond.toFixed(0)} B/s`;
}

function NetworkMonitor() {
  const [devices, setDevices] = useState([]);
  const [telemetry, setTelemetry] = useState(null);

  const [networkRates, setNetworkRates] = useState({
    inbound: null,
    outbound: null,
  });

  const [trafficSamples, setTrafficSamples] = useState([]);
  const previousNetworkSample = useRef(null);

  // Security intelligence from existing backend APIs
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [selectedIP, setSelectedIP] = useState(null);
  const [threatSearch, setThreatSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [actionFilter, setActionFilter] = useState("ALL");
  const [threatSort, setThreatSort] = useState("newest");

  const [securityData, setSecurityData] = useState({
    dashboard: null,
    threats: [],
    firewall: null,
    incidents: [],
    loading: true,
    error: "",
  });

  useEffect(() => {
    let active = true;

    const loadSecurityData = async () => {
      try {
        const endpoints = [
          `${API}/api/dashboard`,
          `${API}/api/threats/recent?limit=200`,
          `${API}/api/firewall/status`,
          `${API}/api/incidents`,
        ];

        const responses = await Promise.all(
          endpoints.map((url) => fetch(url))
        );

        if (responses.some((response) => !response.ok)) {
          throw new Error("One or more security APIs are unavailable.");
        }

        const [dashboard, threats, firewall, incidents] =
          await Promise.all(responses.map((response) => response.json()));

        if (!active) return;

        setSecurityData({
          dashboard,
          threats: Array.isArray(threats) ? threats : [],
          firewall,
          incidents: Array.isArray(incidents) ? incidents : [],
          loading: false,
          error: "",
        });
      } catch (error) {
        if (!active) return;
        setSecurityData((previous) => ({
          ...previous,
          loading: false,
          error: error.message || "Unable to load security information.",
        }));
      }
    };

    loadSecurityData();
    const interval = setInterval(loadSecurityData, 10000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  const highRiskIPs = [
    ...new Set(
      securityData.threats
        .filter((threat) =>
          ["CRITICAL", "HIGH"].includes(
            String(threat.severity || "").toUpperCase()
          )
        )
        .map((threat) => threat.source_ip)
        .filter(Boolean)
    ),
  ];

  const filteredThreats = securityData.threats
    .filter((event) => {
      const search = threatSearch.trim().toLowerCase();
      const matchesSearch = !search ||
        [event.source_ip, event.destination_ip, event.threat_type]
          .some((value) => String(value || "").toLowerCase().includes(search));
      const matchesSeverity = severityFilter === "ALL" ||
        String(event.severity || "").toUpperCase() === severityFilter;
      const matchesAction = actionFilter === "ALL" ||
        String(event.action || "").toUpperCase() === actionFilter;
      return matchesSearch && matchesSeverity && matchesAction;
    })
    .sort((a, b) => {
      if (threatSort === "risk") {
        return (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0);
      }
      return new Date(b.created_at || 0) - new Date(a.created_at || 0);
    });

  const recentSecurityEvents = filteredThreats;

  const exportThreatsCSV = () => {
    const columns = [
      "id", "threat_type", "source_ip", "destination_ip",
      "severity", "risk_score", "anomaly_score", "protocol",
      "port", "action", "status", "created_at"
    ];

    const escapeCSV = (value) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const csv = [
      columns.join(","),
      ...filteredThreats.map((event) =>
        columns.map((column) => escapeCSV(event[column])).join(",")
      )
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "sentinelai-threat-investigation.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const selectedIPEvents = selectedIP
    ? securityData.threats.filter(
        (event) => event.source_ip === selectedIP
      )
    : [];

  const selectedIPSeverity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
    (severity) => ({
      severity,
      count: selectedIPEvents.filter(
        (event) => String(event.severity || "").toUpperCase() === severity
      ).length,
    })
  );



  // Load registered devices
  useEffect(() => {
    let active = true;

    const loadDevices = async () => {
      try {
        const response = await fetch(`${API}/api/devices`);

        if (!response.ok) {
          throw new Error(`Device request failed: ${response.status}`);
        }

        const data = await response.json();

        if (active) {
          setDevices(Array.isArray(data) ? data : []);
        }
      } catch (error) {
        console.error("Device loading error:", error);
      }
    };

    loadDevices();

    return () => {
      active = false;
    };
  }, []);

  // Collect live network telemetry every two seconds
  useEffect(() => {
    let active = true;

    const loadNetworkTelemetry = async () => {
      try {
        const response = await fetch(`${API}/api/live/system`);

        if (!response.ok) {
          throw new Error(`Telemetry request failed: ${response.status}`);
        }

        const data = await response.json();

        if (!active || !data.network_io) return;

        const now = Date.now();
        const previous = previousNetworkSample.current;

        setTelemetry(data);

        if (previous) {
          const elapsedSeconds = (now - previous.time) / 1000;

          if (elapsedSeconds > 0) {
            const receivedDelta =
              data.network_io.bytes_received - previous.received;

            const sentDelta =
              data.network_io.bytes_sent - previous.sent;

            const inbound =
              Math.max(0, receivedDelta) / elapsedSeconds;

            const outbound =
              Math.max(0, sentDelta) / elapsedSeconds;

            setNetworkRates({ inbound, outbound });

            setTrafficSamples((samples) => [
              ...samples,
              {
                time: now,
                inbound,
                outbound,
              },
            ].slice(-30));
          }
        }

        previousNetworkSample.current = {
          received: data.network_io.bytes_received,
          sent: data.network_io.bytes_sent,
          time: now,
        };
      } catch (error) {
        console.error("Network telemetry error:", error);
      }
    };

    loadNetworkTelemetry();

    const interval = setInterval(loadNetworkTelemetry, 2000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  // Calculate protocol distribution from observed connections
  const connections = telemetry?.connections || [];

  const protocolCounts = {
    TCP: connections.filter(
      (connection) => connection.protocol === "TCP"
    ).length,

    UDP: connections.filter(
      (connection) => connection.protocol === "UDP"
    ).length,

    OTHER: connections.filter(
      (connection) =>
        connection.protocol !== "TCP" &&
        connection.protocol !== "UDP"
    ).length,
  };

  const totalProtocols =
    protocolCounts.TCP +
    protocolCounts.UDP +
    protocolCounts.OTHER;

  const protocolPercentage = (count) => {
    if (!totalProtocols) return "0.0";
    return ((count / totalProtocols) * 100).toFixed(1);
  };

  const maxTrafficRate = Math.max(
    1,
    ...trafficSamples.flatMap((sample) => [
      sample.inbound,
      sample.outbound,
    ])
  );

  const interfaceCount = Object.keys(
    telemetry?.network_interfaces || {}
  ).length;

  return (
    <PageLayout
      title="Network Monitor"
      subtitle="Real-time network traffic and device monitoring"
    >
      <div className="monitor-page">

        <Suspense fallback={<div className="monitor-page">Loading network topology...</div>}>
          <NetworkTopology />
        </Suspense>

        {/* Network summary cards */}
        <div className="monitor-stats">

          <div className="monitor-stat">
            <div className="monitor-icon blue">
              <Activity size={21} />
            </div>
            <div>
              <strong>
                {telemetry ? interfaceCount : "—"}
              </strong>
              <span>Network Interfaces</span>
            </div>
          </div>

          <div className="monitor-stat">
            <div className="monitor-icon green">
              <Wifi size={21} />
            </div>
            <div>
              <strong>{devices.length}</strong>
              <span>Registered Devices</span>
            </div>
          </div>

          <div className="monitor-stat">
            <div className="monitor-icon purple">
              <ArrowUp size={21} />
            </div>
            <div>
              <strong>
                {formatTrafficRate(networkRates.inbound)}
              </strong>
              <span>Inbound Traffic</span>
            </div>
          </div>

          <div className="monitor-stat">
            <div className="monitor-icon orange">
              <ArrowDown size={21} />
            </div>
            <div>
              <strong>
                {formatTrafficRate(networkRates.outbound)}
              </strong>
              <span>Outbound Traffic</span>
            </div>
          </div>

        </div>


        {/* Real-time security intelligence */}
        <section className="monitor-card security-intelligence">
          <div className="monitor-card-header">
            <div>
              <h2>Network Threat Intelligence</h2>
              <p>Security events and firewall status from SentinelAI</p>
            </div>
            <span className="live-pill"><i></i> AUTO REFRESH · 10s</span>
          </div>

          {securityData.error && (
            <p className="monitor-empty">
              Security data unavailable: {securityData.error}
            </p>
          )}

          <div className="monitor-stats">
            <div className="monitor-stat">
              <div className="monitor-icon orange">
                <Activity size={21} />
              </div>
              <div>
                <strong>
                  {securityData.loading
                    ? "—"
                    : securityData.dashboard?.active_threats ?? 0}
                </strong>
                <span>Open Threat Events</span>
              </div>
            </div>

            <div className="monitor-stat">
              <div className="monitor-icon purple">
                <Server size={21} />
              </div>
              <div>
                <strong>
                  {securityData.loading ? "—" : highRiskIPs.length}
                </strong>
                <span>High-Risk Source IPs</span>
              </div>
            </div>

            <div className="monitor-stat">
              <div className="monitor-icon blue">
                <Activity size={21} />
              </div>
              <div>
                <strong>
                  {securityData.loading
                    ? "—"
                    : securityData.firewall?.blocked_connections ?? 0}
                </strong>
                <span>Recorded Firewall Blocks</span>
              </div>
            </div>

            <div className="monitor-stat">
              <div className="monitor-icon green">
                <Wifi size={21} />
              </div>
              <div>
                <strong>
                  {securityData.loading
                    ? "—"
                    : securityData.dashboard?.security_alerts ?? 0}
                </strong>
                <span>Open Security Alerts</span>
              </div>
            </div>
          </div>

          <div className="monitor-card-header">
            <div>
              <h2>Recent Security Events</h2>
              <p>Latest recorded threat detections</p>
            </div>
          </div>
          <div className="threat-investigation-controls">
            <input
              type="search"
              className="threat-filter-input"
              placeholder="Search source IP, destination IP or threat..."
              value={threatSearch}
              onChange={(event) => setThreatSearch(event.target.value)}
              aria-label="Search threat records"
            />

            <select
              className="threat-filter-select"
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
              aria-label="Filter by severity"
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              className="threat-filter-select"
              value={actionFilter}
              onChange={(event) => setActionFilter(event.target.value)}
              aria-label="Filter by action"
            >
              <option value="ALL">All actions</option>
              <option value="BLOCK">Block</option>
              <option value="ALLOW">Allow</option>
              <option value="MFA">MFA</option>
            </select>

            <select
              className="threat-filter-select"
              value={threatSort}
              onChange={(event) => setThreatSort(event.target.value)}
              aria-label="Sort threat records"
            >
              <option value="newest">Newest first</option>
              <option value="risk">Highest risk first</option>
            </select>

            <button
              type="button"
              className="threat-export-button"
              onClick={exportThreatsCSV}
              disabled={filteredThreats.length === 0}
            >
              Export CSV ({filteredThreats.length})
            </button>
          </div>

          {securityData.loading ? (
            <div className="monitor-empty">Loading security events...</div>
          ) : recentSecurityEvents.length === 0 ? (
            <div className="monitor-empty">No recorded threat events found.</div>
          ) : (
            <div className="security-event-list">
              {recentSecurityEvents.map((event) => (
                <button
                  type="button"
                  className="security-event-row"
                  key={event.id}
                  onClick={() => setSelectedThreat(event)}
                  aria-label={`Investigate ${event.threat_type || "security event"}`}
                >
                  <div>
                    <strong>{event.threat_type || "Unknown threat"}</strong>
                    <span>
                      {event.source_ip || "Unknown source"} ·{" "}
                      {event.severity || "Unclassified"}
                    </span>
                  </div>
                  <div>
                    <strong>{event.action || "RECORDED"}</strong>
                    <span>{event.status || "Unknown status"}</span>
                  </div>
                </button>
              ))}
            </div>
          )}

          {selectedThreat && (
            <div className="threat-modal-backdrop">
              <section
                className="threat-investigation-modal"
                role="dialog"
                aria-modal="true"
                aria-labelledby="threat-modal-title"
              >
                <div className="monitor-card-header">
                  <div>
                    <h2 id="threat-modal-title">Threat Investigation</h2>
                    <p>Recorded security event details</p>
                  </div>
                  <button
                    type="button"
                    className="threat-modal-close"
                    onClick={() => setSelectedThreat(null)}
                    aria-label="Close investigation"
                  >
                    ×
                  </button>
                </div>

                <div className="threat-detail-grid">
                  <div>
                    <span>Threat type</span>
                    <strong>{selectedThreat.threat_type || "Unknown"}</strong>
                  </div>
                  <div>
                    <span>Severity</span>
                    <strong>{selectedThreat.severity || "Unclassified"}</strong>
                  </div>
                  <div>
                    <span>Source IP</span>
                    {selectedThreat.source_ip ? (
                      <button
                        type="button"
                        className="ip-intelligence-link"
                        onClick={() => setSelectedIP(selectedThreat.source_ip)}
                      >
                        {selectedThreat.source_ip} · View IP Intelligence
                      </button>
                    ) : (
                      <strong>Unavailable</strong>
                    )}
                  </div>
                  <div>
                    <span>Destination IP</span>
                    <strong>{selectedThreat.destination_ip || "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Risk score</span>
                    <strong>{selectedThreat.risk_score ?? "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Anomaly score</span>
                    <strong>{selectedThreat.anomaly_score ?? "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Protocol</span>
                    <strong>{selectedThreat.protocol || "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Destination port</span>
                    <strong>{selectedThreat.port ?? "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Response action</span>
                    <strong>{selectedThreat.action || "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Event status</span>
                    <strong>{selectedThreat.status || "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Packets</span>
                    <strong>{selectedThreat.packets ?? "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Bytes transferred</span>
                    <strong>{selectedThreat.bytes_transferred ?? "Unavailable"}</strong>
                  </div>
                  <div className="threat-detail-wide">
                    <span>Detection time</span>
                    <strong>
                      {selectedThreat.created_at
                        ? new Date(selectedThreat.created_at).toLocaleString()
                        : "Unavailable"}
                    </strong>
                  </div>
                </div>

                <p className="monitor-empty">
                  This view shows stored threat-event data. It does not verify
                  that the source IP is currently active or reachable.
                </p>
              </section>
            </div>
          )}

          {selectedIP && (
            <div className="threat-modal-backdrop">
              <section
                className="threat-investigation-modal ip-history-modal"
                role="dialog"
                aria-modal="true"
                aria-labelledby="ip-history-title"
              >
                <div className="monitor-card-header">
                  <div>
                    <h2 id="ip-history-title">IP Intelligence</h2>
                    <p>Recorded threat history for {selectedIP}</p>
                  </div>
                  <button
                    type="button"
                    className="threat-modal-close"
                    onClick={() => setSelectedIP(null)}
                    aria-label="Close IP Intelligence"
                  >
                    ×
                  </button>
                </div>

                <div className="threat-detail-grid">
                  <div>
                    <span>Source IP</span>
                    <strong>{selectedIP}</strong>
                  </div>
                  <div>
                    <span>Recorded detections</span>
                    <strong>{selectedIPEvents.length}</strong>
                  </div>
                  <div>
                    <span>Recorded BLOCK actions</span>
                    <strong>
                      {selectedIPEvents.filter(
                        (event) => event.action === "BLOCK"
                      ).length}
                    </strong>
                  </div>
                  <div>
                    <span>Highest recorded risk score</span>
                    <strong>
                      {selectedIPEvents.some(
                        (event) => event.risk_score != null
                      )
                        ? Math.max(
                            ...selectedIPEvents
                              .map((event) => Number(event.risk_score))
                              .filter(Number.isFinite)
                          )
                        : "Unavailable"}
                    </strong>
                  </div>
                </div>

                <h3 className="ip-history-heading">Severity distribution</h3>
                <div className="ip-severity-list">
                  {selectedIPSeverity.map((item) => (
                    <div key={item.severity}>
                      <span>{item.severity}</span>
                      <strong>{item.count}</strong>
                    </div>
                  ))}
                </div>

                <h3 className="ip-history-heading">Recorded event timeline</h3>
                {selectedIPEvents.length === 0 ? (
                  <p className="monitor-empty">No matching records found.</p>
                ) : (
                  <div className="security-event-list">
                    {selectedIPEvents.map((event) => (
                      <div className="security-event-row" key={event.id}>
                        <div>
                          <strong>{event.threat_type || "Unknown threat"}</strong>
                          <span>
                            {event.severity || "Unclassified"} ·{" "}
                            {event.protocol || "Unknown protocol"} · Port{" "}
                            {event.port ?? "Unavailable"}
                          </span>
                          <span>
                            {event.created_at
                              ? new Date(event.created_at).toLocaleString()
                              : "Time unavailable"}
                          </span>
                        </div>
                        <div>
                          <strong>{event.action || "RECORDED"}</strong>
                          <span>{event.status || "Unknown status"}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <p className="monitor-empty">
                  Based on up to 200 recent stored threat records. This is
                  historical application data, not external IP reputation
                  or proof that this IP is currently active.
                </p>
              </section>
            </div>
          )}

          <p className="monitor-empty">
            Firewall block counts are recorded in simulation mode. High-risk
            IPs are derived from recent threat records, not live connection
            verification.
          </p>
        </section>

        <div className="monitor-grid">

          {/* Live traffic graph */}
          <section className="monitor-card traffic-panel">

            <div className="monitor-card-header">
              <div>
                <h2>Live Traffic</h2>
                <p>Measured throughput over the latest 60 seconds</p>
              </div>

              <span className="live-pill">
                <i></i> LIVE
              </span>
            </div>

            <div className="traffic-visual">

              {trafficSamples.length === 0 ? (
                <div className="monitor-empty">
                  Collecting live network samples...
                </div>
              ) : (
                <>
                  <div className="traffic-bars">

                    {trafficSamples.map((sample, index) => (
                      <div
                        key={sample.time}
                        title={
                          `${new Date(sample.time).toLocaleTimeString()} | ` +
                          `Inbound: ${formatTrafficRate(sample.inbound)} | ` +
                          `Outbound: ${formatTrafficRate(sample.outbound)}`
                        }
                        style={{
                          display: "flex",
                          flex: 1,
                          minWidth: 0,
                          height: "100%",
                          alignItems: "flex-end",
                          gap: "2px",
                        }}
                      >
                        <div
                          className="traffic-bar"
                          style={{
                            flex: 1,
                            height: `${Math.max(
                              2,
                              (sample.inbound / maxTrafficRate) * 100
                            )}%`,
                          }}
                        />

                        <div
                          className="traffic-bar"
                          style={{
                            flex: 1,
                            opacity: 0.55,
                            height: `${Math.max(
                              2,
                              (sample.outbound / maxTrafficRate) * 100
                            )}%`,
                          }}
                        />
                      </div>
                    ))}

                  </div>

                  <div className="traffic-axis">
                    <span>Oldest sample</span>
                    <span>Latest sample</span>
                  </div>
                </>
              )}

            </div>

            <p className="traffic-legend">
              Inbound · Outbound
            </p>

          </section>

          {/* Live protocol distribution */}
          <section className="monitor-card">

            <div className="monitor-card-header">
              <div>
                <h2>Protocol Distribution</h2>
                <p>Currently observed network connections</p>
              </div>
            </div>

            {!telemetry ? (
              <div className="monitor-empty">
                Loading protocol information...
              </div>
            ) : connections.length === 0 ? (
              <div className="monitor-empty">
                No connection protocol data is currently available.
              </div>
            ) : (
              <div className="protocol-list">

                {["TCP", "UDP", "OTHER"].map((protocol) => {
                  const count = protocolCounts[protocol];
                  const percentage = protocolPercentage(count);

                  return (
                    <div key={protocol}>
                      <div>
                        <span>{protocol}</span>
                        <strong>
                          {percentage}% ({count})
                        </strong>
                      </div>

                      <div className="protocol-line">
                        <i
                          style={{
                            width: `${percentage}%`,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}

              </div>
            )}

            {telemetry?.connection_access === "permission_limited" && (
              <p className="monitor-empty">
                Percentages use visible connections only.
                macOS restricts access to some processes.
              </p>
            )}

          </section>

        </div>

        {/* Registered devices */}
        <section className="monitor-card devices-card">

          <div className="monitor-card-header">
            <div>
              <h2>Connected Devices</h2>
              <p>
                Registered devices. Their online status is not
                independently verified by this list.
              </p>
            </div>

            <span className="device-count">
              {devices.length} devices
            </span>
          </div>

          {devices.length === 0 ? (
            <div className="monitor-empty">
              No registered devices found.
            </div>
          ) : (
            <div className="device-grid">

              {devices.map((device) => (
                <div className="device-card" key={device.id}>

                  <div className="device-card-top">
                    <div className="device-icon">
                      <Server size={20} />
                    </div>

                    <span className="online-status">
                      <i></i>
                      {device.status}
                    </span>
                  </div>

                  <h3>{device.name}</h3>
                  <p>{device.device_type}</p>

                  <div className="device-ip">
                    {device.ip_address}
                  </div>

                  <div className="trust-row">
                    <span>Trust Score</span>
                    <strong>{device.trust_score}%</strong>
                  </div>

                  <div className="trust-bar">
                    <i
                      style={{
                        width: `${device.trust_score}%`,
                      }}
                    />
                  </div>

                </div>
              ))}

            </div>
          )}

        </section>

      </div>
    </PageLayout>
  );
}

export default NetworkMonitor;
