import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const ThreatDetection = lazy(() => import("./pages/ThreatDetection"));
const NetworkMonitor = lazy(() => import("./pages/NetworkMonitor"));
const ZeroTrust = lazy(() => import("./pages/ZeroTrust"));
const FirewallRules = lazy(() => import("./pages/FirewallRules"));
const SecurityLogs = lazy(() => import("./pages/SecurityLogs"));
const Analytics = lazy(() => import("./pages/Analytics"));
const Incidents = lazy(() => import("./pages/Incidents"));
const Assistant = lazy(() => import("./pages/Assistant"));
const Settings = lazy(() => import("./pages/Settings"));
const DatasetLab = lazy(() => import("./pages/DatasetLab"));
const DeviceMonitor = lazy(() => import("./pages/DeviceMonitor"));
const ResponseCenter = lazy(() => import("./pages/ResponseCenter"));

function App() {
  return (
    <BrowserRouter>
      <Suspense
        fallback={
          <div
            style={{
              minHeight: "100vh",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "#0b1120",
              color: "#ffffff",
              fontSize: "16px",
            }}
          >
            Loading SentinelAI...
          </div>
        }
      >
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/threats" element={<ThreatDetection />} />
          <Route path="/network" element={<NetworkMonitor />} />
          <Route path="/zero-trust" element={<ZeroTrust />} />
          <Route path="/firewall" element={<FirewallRules />} />
          <Route path="/logs" element={<SecurityLogs />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/assistant" element={<Assistant />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/dataset-lab" element={<DatasetLab />} />
          <Route path="/device-monitor" element={<DeviceMonitor />} />
          <Route path="/response-center" element={<ResponseCenter />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}

export default App;
