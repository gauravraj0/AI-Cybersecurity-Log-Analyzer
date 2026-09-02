import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  FileBarChart,
  LayoutDashboard,
  LogOut,
  Radar,
  Search,
  ShieldAlert,
  Upload,
  Users,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useAuth } from "../AuthContext.jsx";
import { api } from "../api.js";

const LINKS = [
  { to: "/console", label: "Command Center", icon: LayoutDashboard },
  { to: "/monitor", label: "Live Monitor", icon: Activity },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/anomalies", label: "Anomalies", icon: Radar },
  { to: "/intel", label: "IP Intelligence", icon: AlertTriangle },
  { to: "/ingest", label: "Log Ingest", icon: Upload },
  { to: "/reports", label: "Reports", icon: FileBarChart },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const [clock, setClock] = useState(new Date());
  const [threat, setThreat] = useState("GUARDED");
  const [q, setQ] = useState("");

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    api("/api/dashboard")
      .then((d) => setThreat(d.kpis.threat_level))
      .catch(() => {});
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img src="/logo.png" alt="AEGIS" />
          <div>
            <div className="name">AEGIS</div>
            <div className="sub">SOC Console</div>
          </div>
        </div>
        <div className="nav-label">Operations</div>
        {LINKS.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}>
            <Icon />
            {label}
          </NavLink>
        ))}
        {user?.role === "admin" && (
          <>
            <div className="nav-label">Admin</div>
            <NavLink to="/users" className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}>
              <Users />
              Access Control
            </NavLink>
          </>
        )}
        <div className="sidebar-foot">
          <div className="tl">Global threat posture</div>
          <div className={`threat-pill ${threat}`}>{threat}</div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <form
            className="search"
            onSubmit={(e) => {
              e.preventDefault();
              if (q.trim()) nav(`/monitor?q=${encodeURIComponent(q.trim())}`);
            }}
          >
            <Search size={16} />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search logs, IPs, users, paths…"
            />
          </form>
          <div className="top-meta">
            <div className="clock mono">{clock.toISOString().replace("T", " ").slice(0, 19)} UTC</div>
            <div className="userchip">
              <div className="avatar">{(user?.full_name || "A").slice(0, 1)}</div>
              <div>
                {user?.full_name}
                <small>
                  {user?.role} · {user?.department}
                </small>
              </div>
            </div>
            <button
              className="ghost"
              onClick={() => {
                logout();
                nav("/");
              }}
            >
              <LogOut size={14} />
            </button>
          </div>
        </header>
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
