import { BrowserRouter, Routes, Route } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import ThreatDetection from "./pages/ThreatDetection";
import NetworkMonitor from "./pages/NetworkMonitor";
import ZeroTrust from "./pages/ZeroTrust";
import FirewallRules from "./pages/FirewallRules";
import SecurityLogs from "./pages/SecurityLogs";
import Analytics from "./pages/Analytics";
import Incidents from "./pages/Incidents";
import Assistant from "./pages/Assistant";
import Settings from "./pages/Settings";

function App() {
  return (
    <BrowserRouter>
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

      </Routes>
    </BrowserRouter>
  );
}

export default App;
