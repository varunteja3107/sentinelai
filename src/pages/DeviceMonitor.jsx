import { useCallback, useEffect, useRef, useState } from "react";
import { Activity, BatteryCharging, CheckCircle2, Cpu, HardDrive, Laptop, LockKeyhole, MapPin, RefreshCw, ShieldAlert, Wifi } from "lucide-react";
import PageLayout from "../components/PageLayout";

const API = (import.meta.env.VITE_API_URL || "https://sentinelai-wnno.onrender.com").replace(/\/+$/, "");
const panel = { background: "#0F172A", border: "1px solid #263449", borderRadius: 14, padding: 20, minWidth: 0, color: "#E2E8F0" };
const muted = { color: "#94A3B8", fontSize: 13 };
const button = { display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8, padding: "10px 14px", borderRadius: 9, border: "1px solid #2C4962", background: "#132238", color: "#E2E8F0", fontWeight: 700, cursor: "pointer" };

function Metric({ icon: Icon, label, value, suffix = "" }) {
  return <div style={panel}>
    <div style={{ display: "flex", gap: 8, alignItems: "center", color: "#22D3EE", fontSize: 13 }}><Icon size={17} />{label}</div>
    <div style={{ fontSize: 28, fontWeight: 800, marginTop: 14 }}>{value ?? "--"}{value !== null && value !== undefined ? suffix : ""}</div>
  </div>;
}

export default function DeviceMonitor() {
  const [token, setToken] = useState("");
  const [connectedToken, setConnectedToken] = useState("");
  const [device, setDevice] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [locationConsent, setLocationConsent] = useState(false);
  const [sharingLocation, setSharingLocation] = useState(false);
  const [statusMessage, setStatusMessage] = useState("Enter your device-monitor token to connect.");
  const watchId = useRef(null);

  const refresh = useCallback(async (authToken = connectedToken) => {
    if (!authToken) return;
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/device-monitor/latest`, {
        headers: { Authorization: `Bearer ${authToken}` },
        cache: "no-store",
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail || `Monitor API returned ${res.status}`);
      setDevice(body.device || null);
      setError("");
      setStatusMessage(body.device ? "Connected to your laptop monitor." : "Token accepted. Start the monitor agent on your Mac.");
    } catch (e) {
      setError(e.message || "Could not connect to the monitor service.");
      setStatusMessage("Connection needs attention.");
    } finally {
      setLoading(false);
    }
  }, [connectedToken]);

  useEffect(() => {
    if (!connectedToken) return undefined;
    refresh(connectedToken);
    const timer = setInterval(() => refresh(connectedToken), 5000);
    return () => clearInterval(timer);
  }, [connectedToken, refresh]);

  useEffect(() => () => {
    if (watchId.current !== null && navigator.geolocation) navigator.geolocation.clearWatch(watchId.current);
  }, []);

  function connect(e) {
    e.preventDefault();
    const clean = token.trim();
    if (!clean) { setError("Paste the DEVICE_MONITOR_TOKEN you configured in Render."); return; }
    setDevice(null);
    setError("");
    setConnectedToken(clean);
    setStatusMessage("Connecting to the laptop monitor…");
  }

  function startLocationSharing() {
    if (!device?.device_id) { setError("Wait until the laptop agent reports online before starting location sharing."); return; }
    if (!locationConsent) { setError("Confirm that this browser is open on the Mac you intend to locate."); return; }
    if (!navigator.geolocation) { setError("This browser does not support geolocation."); return; }
    if (watchId.current !== null) navigator.geolocation.clearWatch(watchId.current);
    setError("");
    setStatusMessage("Requesting browser location permission…");
    watchId.current = navigator.geolocation.watchPosition(async (pos) => {
      try {
        const res = await fetch(`${API}/api/device-monitor/location`, {
          method: "POST",
          headers: { Authorization: `Bearer ${connectedToken}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            device_id: device.device_id,
            latitude: pos.coords.latitude,
            longitude: pos.coords.longitude,
            accuracy_m: pos.coords.accuracy,
          }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.detail || `Location update failed (${res.status})`);
        setStatusMessage("Location sharing is active on this browser.");
        await refresh(connectedToken);
      } catch (e) { setError(e.message || "Location update failed."); }
    }, (e) => {
      setError(e.message || "Location permission was denied or unavailable.");
      setSharingLocation(false);
    }, { enableHighAccuracy: true, maximumAge: 5000, timeout: 20000 });
    setSharingLocation(true);
    setStatusMessage("Location sharing requested. Approve the browser permission prompt.");
  }

  function stopLocationSharing() {
    if (watchId.current !== null && navigator.geolocation) navigator.geolocation.clearWatch(watchId.current);
    watchId.current = null;
    setSharingLocation(false);
    setStatusMessage("Location sharing stopped. The last saved coordinates remain visible until replaced or the service restarts.");
  }

  const lastSeenMs = device?.last_seen ? Date.now() - new Date(device.last_seen).getTime() : Infinity;
  const online = Boolean(device) && lastSeenMs < 45000;
  const location = device?.location;
  const mapUrl = location ? `https://www.openstreetmap.org/?mlat=${location.latitude}&mlon=${location.longitude}#map=16/${location.latitude}/${location.longitude}` : null;
  const lastSeenLabel = device?.last_seen ? new Date(device.last_seen).toLocaleString() : "No report yet";

  return <PageLayout title="Live Laptop Monitor" subtitle="Monitor your Mac's health and optionally share its location">
    <div style={{ display: "grid", gap: 18, color: "#E2E8F0" }}>
      <section style={{ ...panel, background: "linear-gradient(135deg,#0F172A,#102A3A)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
          <div style={{ padding: 12, borderRadius: 12, background: "#083344", color: "#22D3EE" }}><Laptop size={25} /></div>
          <div style={{ flex: 1 }}>
            <h2 style={{ margin: 0, fontSize: 20 }}>Device connection</h2>
            <p style={{ ...muted, margin: "5px 0 0" }}>A background agent on your Mac sends health metrics to SentinelAI every 15 seconds.</p>
          </div>
          <span style={{ color: online ? "#4ADE80" : "#FBBF24", fontWeight: 800, fontSize: 12 }}>{online ? "● ONLINE" : "● WAITING"}</span>
        </div>
        <form onSubmit={connect} style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <input aria-label="Device monitor token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} placeholder="Paste device-monitor token" style={{ flex: "1 1 280px", minWidth: 0, background: "#081626", color: "#E2E8F0", border: "1px solid #334155", borderRadius: 8, padding: 12 }} />
          <button type="submit" style={button}><LockKeyhole size={16} /> Connect</button>
          <button type="button" onClick={() => refresh()} style={button} disabled={!connectedToken || loading}><RefreshCw size={16} /> Refresh</button>
          {connectedToken && <button type="button" onClick={() => { stopLocationSharing(); setConnectedToken(""); setDevice(null); setToken(""); setStatusMessage("Disconnected."); }} style={button}>Disconnect</button>}
        </form>
        <p style={{ ...muted, marginBottom: 0 }}>{statusMessage}</p>
        {error && <p role="alert" style={{ marginBottom: 0, color: "#FCA5A5" }}>{error}</p>}
      </section>

      {device && <>
        <section style={{ ...panel, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12, justifyContent: "space-between" }}>
          <div><h2 style={{ margin: 0, fontSize: 20 }}>{device.device_name}</h2><p style={{ ...muted, margin: "5px 0 0" }}>{device.platform || "Mac"} · {device.os_version || "OS version unavailable"} · Local IP {device.local_ip || "unavailable"}</p></div>
          <div style={muted}>Last heartbeat: {lastSeenLabel}</div>
        </section>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 12 }}>
          <Metric icon={Cpu} label="CPU usage" value={device.cpu_percent ?? null} suffix="%" />
          <Metric icon={Activity} label="Memory used" value={device.memory_percent ?? null} suffix="%" />
          <Metric icon={HardDrive} label="Disk used" value={device.disk_percent ?? null} suffix="%" />
          <Metric icon={BatteryCharging} label="Battery" value={device.battery_percent ?? null} suffix="%" />
          <Metric icon={Wifi} label="Network sent" value={device.network_sent_mb ?? null} suffix=" MB" />
          <Metric icon={Wifi} label="Network received" value={device.network_recv_mb ?? null} suffix=" MB" />
        </div>
        <section style={panel}>
          <h2 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: 8 }}><MapPin color="#22D3EE" /> Physical location</h2>
          <p style={muted}>Location updates require permission and are sent only while sharing is active in a browser on the Mac you want to track. On another laptop, view the map but do not start sharing location there.</p>
          {location ? <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
            <div style={{ flex: "1 1 260px" }}><strong>Latitude:</strong> {Number(location.latitude).toFixed(6)}<br /><strong>Longitude:</strong> {Number(location.longitude).toFixed(6)}<br /><span style={muted}>Accuracy: approximately {Math.round(location.accuracy_m || 0)} metres · Updated {location.updated_at ? new Date(location.updated_at).toLocaleString() : "unknown"}</span></div>
            <a href={mapUrl} target="_blank" rel="noreferrer" style={{ ...button, textDecoration: "none" }}>Open map</a>
          </div> : <p style={muted}>No location received yet. Start location sharing on the target Mac below.</p>}
          <label style={{ display: "flex", gap: 9, alignItems: "flex-start", margin: "18px 0 12px", fontSize: 13, lineHeight: 1.5 }}>
            <input type="checkbox" checked={locationConsent} onChange={e => setLocationConsent(e.target.checked)} style={{ marginTop: 3 }} />
            I am using this browser on the Mac I want to locate, and I consent to sharing its location with my SentinelAI dashboard.
          </label>
          {!sharingLocation ? <button type="button" style={button} onClick={startLocationSharing}><MapPin size={16} /> Start location sharing on this Mac</button> : <button type="button" style={{ ...button, color: "#FCA5A5", borderColor: "#7F1D1D" }} onClick={stopLocationSharing}>Stop location sharing</button>}
        </section>
        <section style={panel}>
          <h2 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: 8 }}><ShieldAlert color="#22D3EE" /> Privacy and status</h2>
          <p style={muted}>The agent reports device health to the configured backend. Location is optional and uses the browser's location permission. The shared token protects report access; keep it private. Health monitoring stops when the Mac is shut down or cannot reach the internet.</p>
        </section>
      </>}
      {!device && connectedToken && !error && <section style={panel}><h2 style={{ marginTop: 0 }}>Waiting for your Mac</h2><p style={muted}>Install and start the companion agent on the Mac you want to monitor. This page will refresh automatically.</p><div style={{ color: "#22D3EE", display: "flex", gap: 8, alignItems: "center" }}><RefreshCw size={16} /> Checking for reports every 5 seconds</div></section>}
    </div>
  </PageLayout>;
}
