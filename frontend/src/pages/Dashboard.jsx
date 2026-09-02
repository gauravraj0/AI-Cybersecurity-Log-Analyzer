import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, Bell, ShieldAlert, Siren } from "lucide-react";
import { api } from "../api.js";

const COLORS = {
  critical: "#ff3b5c",
  high: "#ff9f1c",
  medium: "#ffd166",
  low: "#00e5ff",
};

function lonLatToPct(lon, lat) {
  const x = ((lon + 180) / 360) * 100;
  const y = ((90 - lat) / 180) * 100;
  return { left: `${Math.min(96, Math.max(4, x))}%`, top: `${Math.min(90, Math.max(8, y))}%` };
}

export default function Dashboard() {
  const [data, setData] = useState(null);
  const nav = useNavigate();

  useEffect(() => {
    api("/api/dashboard").then(setData).catch(() => {});
    const t = setInterval(() => api("/api/dashboard").then(setData).catch(() => {}), 12000);
    return () => clearInterval(t);
  }, []);

  if (!data) return <div className="empty">Correlating telemetry…</div>;
  const { kpis } = data;
  const pie = Object.entries(data.severity).map(([name, value]) => ({ name, value }));

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">Command center</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Security operations</h1>
          <p>Live posture across ingested logs, ML anomalies, and open incidents.</p>
        </div>
        <div className="live-flag">
          <span className="pulse" /> THREAT LEVEL {kpis.threat_level}
        </div>
      </div>

      <div className="grid kpis">
        <div className="card">
          <div className="kpi-icon">
            <Activity size={16} />
          </div>
          <h3>Events (24h)</h3>
          <div className="stat">{kpis.logs_24h.toLocaleString()}</div>
          <div className="stat-sub">{kpis.total_logs.toLocaleString()} in retained window</div>
        </div>
        <div className="card">
          <div className="kpi-icon warn">
            <RadarIcon />
          </div>
          <h3>Anomalies</h3>
          <div className="stat">{kpis.anomalies.toLocaleString()}</div>
          <div className="stat-sub">Isolation Forest + signatures</div>
        </div>
        <div className="card">
          <div className="kpi-icon bad">
            <ShieldAlert size={16} />
          </div>
          <h3>Open incidents</h3>
          <div className="stat">{kpis.open_incidents}</div>
          <div className="stat-sub">{kpis.critical_open} critical still active</div>
        </div>
        <div className="card">
          <div className="kpi-icon ok">
            <Bell size={16} />
          </div>
          <h3>Unacked alerts</h3>
          <div className="stat">{kpis.alerts_unack}</div>
          <div className="stat-sub">Queue for the duty analyst</div>
        </div>
      </div>

      <div className="grid two">
        <div className="card">
          <h3>Log volume · last 24h</h3>
          <div style={{ height: 240, marginTop: 12 }}>
            <ResponsiveContainer>
              <AreaChart data={data.volume}>
                <defs>
                  <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00e5ff" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#00e5ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="g2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff3b5c" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#ff3b5c" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(0,229,255,0.06)" vertical={false} />
                <XAxis dataKey="hour" stroke="#4d6274" fontSize={11} tickLine={false} />
                <YAxis stroke="#4d6274" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "#0d141f", border: "1px solid rgba(0,229,255,0.2)" }} />
                <Area type="monotone" dataKey="logs" stroke="#00e5ff" fill="url(#g1)" strokeWidth={2} />
                <Area type="monotone" dataKey="threats" stroke="#ff3b5c" fill="url(#g2)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <h3>Incident severity mix</h3>
          <div style={{ height: 240, marginTop: 12 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie data={pie} dataKey="value" nameKey="name" innerRadius={58} outerRadius={86} paddingAngle={3}>
                  {pie.map((e) => (
                    <Cell key={e.name} fill={COLORS[e.name] || "#4c8dff"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#0d141f", border: "1px solid rgba(0,229,255,0.2)" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="row" style={{ justifyContent: "center" }}>
            {pie.map((e) => (
              <span key={e.name} className={`badge ${e.name}`}>
                {e.name} {e.value}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="grid two">
        <div className="card" style={{ padding: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", padding: "4px 6px 10px" }}>
            <h3>Global threat picture</h3>
            <Siren size={16} color="#ff3b5c" />
          </div>
          <div className="map-wrap">
            <img src="/threat-map.jpg" alt="Threat map" />
            {data.map_points.map((p) => (
              <div
                key={p.ip}
                className={`map-pin ${p.threat_level}`}
                style={lonLatToPct(p.lon, p.lat)}
                title={`${p.ip} · ${p.city}, ${p.country}`}
              />
            ))}
          </div>
        </div>
        <div className="card">
          <h3>Latest alerts</h3>
          {data.alerts.map((a) => (
            <div
              className="alert-item row-link"
              key={a.id}
              onClick={() => a.incident_id && nav(`/incidents/${a.incident_id}`)}
            >
              <span className={`dot ${a.severity}`} />
              <div>
                <strong>{a.title}</strong>
                <p>
                  {a.message} · {new Date(a.created_at).toLocaleString()}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid two">
        <div className="card">
          <h3>Lowest-reputation IPs</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Geo</th>
                  <th>Rep</th>
                  <th>Anomalies</th>
                </tr>
              </thead>
              <tbody>
                {data.top_ips.map((p) => (
                  <tr key={p.ip} className="row-link" onClick={() => nav(`/intel?ip=${p.ip}`)}>
                    <td className="mono">{p.ip}</td>
                    <td>
                      {p.city}, {p.country}
                    </td>
                    <td>
                      <div className="score">
                        <span style={{ width: `${p.reputation}%` }} />
                      </div>
                      <span className="small muted">{p.reputation}</span>
                    </td>
                    <td>{p.anomaly_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <h3>Attack families</h3>
          {data.threat_types.map((t) => (
            <div key={t.type} style={{ display: "flex", justifyContent: "space-between", padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
              <span className="mono">{t.type.replaceAll("_", " ")}</span>
              <strong>{t.count}</strong>
            </div>
          ))}
          <h3 style={{ marginTop: 16 }}>Error classification</h3>
          {data.errors.map((e) => (
            <div key={e.class} className="small muted" style={{ display: "flex", justifyContent: "space-between", padding: "6px 0" }}>
              <span>{e.class.replaceAll("_", " ")}</span>
              <span>{e.count}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function RadarIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M2 12a10 10 0 1 0 20 0" />
      <path d="M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0" />
      <path d="M12 2v4" />
    </svg>
  );
}
