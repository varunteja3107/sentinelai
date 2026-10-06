import { useEffect, useState } from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  Network,
  ShieldCheck,
  Shield,
  FileText,
  BarChart3,
  AlertTriangle,
  Settings,
  Bot,
  Zap,
  Activity,
  Server,
  Lock,
  RefreshCw,
  Play,
  CheckCircle,
} from "lucide-react";
import { Link } from "react-router-dom";

const API = "https://sentinelai-wnno.onrender.com";

const navItems = [
  { name: "Dashboard", path: "/", icon: LayoutDashboard },
  { name: "Threat Detection", path: "/threats", icon: ShieldAlert },
  { name: "Network Monitor", path: "/network", icon: Network },
  { name: "Zero Trust", path: "/zero-trust", icon: ShieldCheck },
  { name: "Firewall", path: "/firewall", icon: Shield },
  { name: "Security Logs", path: "/logs", icon: FileText },
  { name: "Analytics", path: "/analytics", icon: BarChart3 },
  { name: "Incidents", path: "/incidents", icon: AlertTriangle },
  { name: "AI Assistant", path: "/assistant", icon: Bot },
  { name: "Settings", path: "/settings", icon: Settings },
];

function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [message, setMessage] = useState("");

  const loadDashboard = async () => {
    try {
      const response = await fetch(`${API}/api/dashboard`);
      const result = await response.json();
      setData(result);
    } catch (error) {
      console.error(error);
      setMessage("Unable to connect to SecureX AI backend.");
    } finally {
      setLoading(false);
    }
  };

  const simulateAttack = async () => {
    setSimulating(true);
    setMessage("");

    try {
      const response = await fetch(`${API}/api/demo/attack`, {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error("Attack simulation failed");
      }

      const result = await response.json();

      setMessage(
        `Threat detected: ${result.threat_type || "Port Scan"} | Risk ${result.risk_score} | ${result.action}`
      );

      await loadDashboard();
    } catch (error) {
      console.error(error);
      setMessage("Unable to run attack simulation.");
    } finally {
      setSimulating(false);
    }
  };

  useEffect(() => {
    loadDashboard();

    const interval = setInterval(loadDashboard, 15000);

    return () => clearInterval(interval);
  }, []);

  const securityScore = data?.security_score ?? 100;

  return (
    <div className="min-h-screen bg-[#0B1120] text-[#F8FAFC] flex">

      {/* SIDEBAR */}
      <aside className="hidden lg:flex w-64 min-h-screen bg-[#0F172A] border-r border-slate-800 flex-col fixed left-0 top-0">

        <div className="px-6 py-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-400/10 border border-cyan-400/30 flex items-center justify-center">
              <Shield className="text-cyan-400" size={22} />
            </div>

            <div>
              <h1 className="font-bold text-lg">SecureX AI</h1>
              <p className="text-[10px] text-slate-400 tracking-widest">
                SECURITY PLATFORM
              </p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;

            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition ${
                  item.path === "/"
                    ? "bg-cyan-400/10 text-cyan-400 border border-cyan-400/20"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <Icon size={18} />
                <span className="text-sm">{item.name}</span>
              </Link>
            );
          })}
        </nav>

        <div className="p-4">
          <div className="rounded-xl bg-emerald-400/5 border border-emerald-400/20 p-4">
            <div className="flex items-center gap-2 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-semibold">SYSTEM OPERATIONAL</span>
            </div>

            <p className="text-xs text-slate-500 mt-2">
              AI monitoring is active
            </p>
          </div>
        </div>
      </aside>

      {/* MAIN */}
      <main className="flex-1 lg:ml-64">

        {/* HEADER */}
        <header className="sticky top-0 z-20 bg-[#0B1120]/90 backdrop-blur-xl border-b border-slate-800">
          <div className="px-5 lg:px-8 py-4 flex items-center justify-between">

            <div>
              <p className="text-xs text-slate-500 uppercase tracking-widest">
                Security Console
              </p>
              <h2 className="text-xl font-bold mt-1">
                Threat Intelligence Dashboard
              </h2>
            </div>

            <button
              onClick={loadDashboard}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm transition"
            >
              <RefreshCw size={15} />
              Refresh
            </button>
          </div>
        </header>

        <div className="p-5 lg:p-8">

          {/* STATUS BANNER */}
          <div className="mb-6 rounded-2xl border border-cyan-400/20 bg-gradient-to-r from-cyan-400/10 to-blue-500/5 p-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">

              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-cyan-400/10 flex items-center justify-center">
                  <Activity className="text-cyan-400" size={25} />
                </div>

                <div>
                  <h3 className="font-semibold">
                    SecureX AI Protection Active
                  </h3>
                  <p className="text-sm text-slate-400 mt-1">
                    AI threat detection and Zero Trust monitoring are running.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 text-emerald-400 text-sm">
                <CheckCircle size={17} />
                All systems operational
              </div>
            </div>
          </div>

          {/* STAT CARDS */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">

            <StatCard
              icon={ShieldAlert}
              title="Active Threats"
              value={data?.active_threats ?? 0}
              color="text-red-400"
              bg="bg-red-400/10"
            />

            <StatCard
              icon={Lock}
              title="Blocked Attacks"
              value={data?.blocked_attacks ?? 0}
              color="text-orange-400"
              bg="bg-orange-400/10"
            />

            <StatCard
              icon={AlertTriangle}
              title="Security Alerts"
              value={data?.security_alerts ?? 0}
              color="text-yellow-400"
              bg="bg-yellow-400/10"
            />

            <StatCard
              icon={ShieldCheck}
              title="Security Score"
              value={`${securityScore}%`}
              color="text-emerald-400"
              bg="bg-emerald-400/10"
            />

          </div>

          {/* SYSTEM STATUS + SCORE */}
          <div className="grid lg:grid-cols-3 gap-5 mt-5">

            <div className="lg:col-span-2 rounded-2xl bg-[#111827] border border-slate-800 p-6">

              <div className="flex items-center justify-between mb-6">
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-widest">
                    Protection Engine
                  </p>
                  <h3 className="text-lg font-semibold mt-1">
                    Security Infrastructure
                  </h3>
                </div>

                <Server className="text-cyan-400" size={22} />
              </div>

              <div className="grid sm:grid-cols-2 gap-4">

                <StatusItem
                  name="AI Detection Engine"
                  value="Online"
                  good
                />

                <StatusItem
                  name="Threat Monitoring"
                  value="Active"
                  good
                />

                <StatusItem
                  name="Zero Trust Engine"
                  value="Enabled"
                  good
                />

                <StatusItem
                  name="Backend API"
                  value="Connected"
                  good
                />

              </div>
            </div>

            <div className="rounded-2xl bg-[#111827] border border-slate-800 p-6">

              <p className="text-xs text-slate-500 uppercase tracking-widest">
                Security Score
              </p>

              <div className="flex justify-center py-5">
                <div className="w-36 h-36 rounded-full border-[10px] border-cyan-400/20 flex items-center justify-center relative">
                  <div className="absolute inset-0 rounded-full border-[10px] border-transparent border-t-cyan-400 border-r-cyan-400 rotate-45" />
                  <div className="text-center">
                    <div className="text-3xl font-bold">
                      {securityScore}
                    </div>
                    <div className="text-xs text-slate-500">
                      OUT OF 100
                    </div>
                  </div>
                </div>
              </div>

              <div className="text-center text-sm text-slate-400">
                Overall security posture
              </div>
            </div>

          </div>

          {/* ATTACK SIMULATOR */}
          <div className="mt-5 rounded-2xl border border-red-400/20 bg-gradient-to-br from-[#111827] to-[#160f18] p-6">

            <div className="flex flex-col md:flex-row md:items-center justify-between gap-5">

              <div>
                <div className="flex items-center gap-2">
                  <Zap className="text-red-400" size={21} />
                  <p className="text-xs text-red-400 uppercase tracking-widest font-semibold">
                    Security Lab
                  </p>
                </div>

                <h3 className="text-xl font-bold mt-2">
                  Attack Simulator
                </h3>

                <p className="text-sm text-slate-400 mt-1 max-w-xl">
                  Generate an authorized simulated threat and observe the
                  complete SecureX AI detection and response pipeline.
                </p>
              </div>

              <button
                onClick={simulateAttack}
                disabled={simulating}
                className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-red-500 hover:bg-red-400 disabled:opacity-50 font-semibold transition"
              >
                <Play size={17} />
                {simulating ? "Analyzing..." : "Simulate Port Scan"}
              </button>

            </div>

            {message && (
              <div className="mt-5 rounded-xl bg-black/30 border border-slate-700 p-4 text-sm">
                <span className="text-cyan-400 font-semibold">
                  AI Response:
                </span>{" "}
                {message}
              </div>
            )}

          </div>

          {/* PIPELINE */}
          <div className="mt-5 rounded-2xl bg-[#111827] border border-slate-800 p-6">

            <p className="text-xs text-slate-500 uppercase tracking-widest">
              Detection Pipeline
            </p>

            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-5">

              {[
                ["01", "Traffic"],
                ["02", "AI Detection"],
                ["03", "Risk Score"],
                ["04", "Zero Trust"],
                ["05", "Response"],
              ].map(([number, name]) => (
                <div
                  key={number}
                  className="rounded-xl bg-slate-900 border border-slate-800 p-4"
                >
                  <div className="text-xs text-cyan-400 font-bold">
                    {number}
                  </div>

                  <div className="font-semibold mt-2 text-sm">
                    {name}
                  </div>

                  <div className="h-1 bg-slate-800 rounded mt-3">
                    <div className="h-1 bg-cyan-400 rounded w-full" />
                  </div>
                </div>
              ))}

            </div>
          </div>

          <footer className="text-center text-xs text-slate-600 py-8">
            SecureX AI • AI-Powered Threat Detection & Zero Trust Security
          </footer>

        </div>
      </main>
    </div>
  );
}

function StatCard({ icon: Icon, title, value, color, bg }) {
  return (
    <div className="rounded-2xl bg-[#111827] border border-slate-800 p-5 hover:border-slate-700 transition">

      <div className="flex items-center justify-between">
        <div className={`w-10 h-10 rounded-xl ${bg} flex items-center justify-center`}>
          <Icon size={20} className={color} />
        </div>

        <Activity size={16} className="text-slate-700" />
      </div>

      <p className="text-sm text-slate-400 mt-5">
        {title}
      </p>

      <p className="text-3xl font-bold mt-1">
        {value}
      </p>
    </div>
  );
}

function StatusItem({ name, value, good }) {
  return (
    <div className="flex items-center justify-between rounded-xl bg-slate-900/70 border border-slate-800 p-4">

      <div className="flex items-center gap-3">
        <span
          className={`w-2 h-2 rounded-full ${
            good ? "bg-emerald-400 shadow-[0_0_10px_#22C55E]" : "bg-red-400"
          }`}
        />

        <span className="text-sm text-slate-300">
          {name}
        </span>
      </div>

      <span className="text-xs font-semibold text-emerald-400">
        {value}
      </span>

    </div>
  );
}

export default Dashboard;
