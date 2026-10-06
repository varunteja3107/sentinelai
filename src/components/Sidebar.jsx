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
} from "lucide-react";

import { NavLink } from "react-router-dom";

const navigation = [
  {
    name: "Dashboard",
    path: "/",
    icon: LayoutDashboard,
  },
  {
    name: "Threat Detection",
    path: "/threats",
    icon: ShieldAlert,
  },
  {
    name: "Network Monitor",
    path: "/network",
    icon: Network,
  },
  {
    name: "Zero Trust",
    path: "/zero-trust",
    icon: ShieldCheck,
  },
  {
    name: "Firewall Rules",
    path: "/firewall",
    icon: Shield,
  },
  {
    name: "Security Logs",
    path: "/logs",
    icon: FileText,
  },
  {
    name: "Analytics",
    path: "/analytics",
    icon: BarChart3,
  },
  {
    name: "Incidents",
    path: "/incidents",
    icon: AlertTriangle,
  },
  {
    name: "AI Assistant",
    path: "/assistant",
    icon: Bot,
  },
  {
    name: "Settings",
    path: "/settings",
    icon: Settings,
  },
];

function Sidebar() {
  return (
    <aside className="sidebar">

      <div className="sidebar-brand">

        <div className="brand-icon">
          <Shield size={25} />
        </div>

        <div>
          <div className="brand-name">
            SentinelAI
          </div>

          <div className="brand-subtitle">
            Next-Gen Firewall
          </div>
        </div>

      </div>

      <nav className="sidebar-nav">

        {navigation.map((item) => {

          const Icon = item.icon;

          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `nav-item ${isActive ? "active" : ""}`
              }
            >

              <Icon
                className="nav-icon"
                size={19}
              />

              <span>{item.name}</span>

            </NavLink>
          );
        })}

      </nav>

      <div className="sidebar-footer">

        <span className="system-dot"></span>

        <span>
          System Operational
        </span>

      </div>

    </aside>
  );
}

export default Sidebar;
