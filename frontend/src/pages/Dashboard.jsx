import React, { useEffect, useState } from 'react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid,
  PieChart, Pie, Cell, Legend, BarChart, Bar,
} from 'recharts';
import { api } from '../api.js';
import { Kpi, SevBadge, pct, fmtTime, fmtType } from '../components/ui.jsx';

const SEV_COLORS = { CRITICAL: '#f43f5e', HIGH: '#fb923c', MEDIUM: '#facc15', LOW: '#60a5fa', INFO: '#94a3b8' };

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api('/api/analytics/dashboard').then(setStats).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error-msg">Failed to load dashboard: {error}</div>;
  if (!stats) return <div className="muted">Loading security overview…</div>;

  const sevData = stats.severity_breakdown.filter((s) => s.count > 0);

  return (
    <div className="grid" style={{ gap: 14 }}>
      <div className="grid kpis">
        <Kpi label="Log events (24h)" value={stats.logs_24h.toLocaleString()} accent="accent-cyan" />
        <Kpi label="High/Critical (24h)" value={stats.critical_events.toLocaleString()} accent="accent-red" />
        <Kpi label="Open incidents" value={stats.open_incidents} accent="accent-red" />
        <Kpi label="Unack alerts" value={stats.unacknowledged_alerts} accent="accent-amber" />
        <Kpi label="Malicious IPs" value={stats.malicious_ips} accent="accent-purple" />
        <Kpi label="Error rate" value={pct(stats.error_rate)} accent="accent-amber" sub={`${stats.total_logs.toLocaleString()} total events`} />
      </div>

      <div className="grid two-col">
        <div className="panel">
          <h3>Event volume & threats — last 24h</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={stats.logs_per_hour}>
              <defs>
                <linearGradient id="gCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="gThreat" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.6} />
                  <stop offset="100%" stopColor="#f43f5e" stopOpacity={0.03} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#22304d" strokeDasharray="3 3" />
              <XAxis dataKey="hour" tick={{ fill: '#8ea0bd', fontSize: 11 }} />
              <YAxis tick={{ fill: '#8ea0bd', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#16233c', border: '1px solid #22304d', borderRadius: 8, color: '#e2e8f0' }} />
              <Area type="monotone" dataKey="count" name="events" stroke="#38bdf8" fill="url(#gCount)" strokeWidth={2} />
              <Area type="monotone" dataKey="threats" name="high/critical" stroke="#f43f5e" fill="url(#gThreat)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="panel">
          <h3>Severity distribution</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={sevData} dataKey="count" nameKey="severity" innerRadius={58} outerRadius={92} paddingAngle={3}>
                {sevData.map((s) => <Cell key={s.severity} fill={SEV_COLORS[s.severity] || '#94a3b8'} stroke="#0b1120" />)}
              </Pie>
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Tooltip contentStyle={{ background: '#16233c', border: '1px solid #22304d', borderRadius: 8, color: '#e2e8f0' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid two-col">
        <div className="panel">
          <h3>Top attack / threat signatures</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={stats.top_attack_types} layout="vertical" margin={{ left: 40 }}>
              <CartesianGrid stroke="#22304d" strokeDasharray="3 3" />
              <XAxis type="number" tick={{ fill: '#8ea0bd', fontSize: 11 }} />
              <YAxis type="category" dataKey="type" width={150} tickFormatter={fmtType}
                     tick={{ fill: '#8ea0bd', fontSize: 10.5 }} />
              <Tooltip contentStyle={{ background: '#16233c', border: '1px solid #22304d', borderRadius: 8, color: '#e2e8f0' }} />
              <Bar dataKey="count" name="events" fill="#fb923c" radius={[0, 5, 5, 0]} barSize={14} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="panel">
          <h3>Top risky source IPs</h3>
          <table className="data">
            <thead><tr><th>IP</th><th>Threat</th><th>Requests</th><th>Failed logins</th><th>Labels</th></tr></thead>
            <tbody>
              {stats.top_risky_ips.map((ip) => (
                <tr key={ip.ip}>
                  <td className="mono">{ip.ip} {ip.is_malicious && <span className="badge critical">mal</span>}</td>
                  <td><b style={{ color: ip.threat_score >= 70 ? 'var(--critical)' : ip.threat_score >= 40 ? 'var(--medium)' : 'var(--ok)' }}>{ip.threat_score}</b></td>
                  <td>{ip.total_requests}</td>
                  <td>{ip.failed_logins}</td>
                  <td>{(ip.labels || []).slice(0, 2).map((l) => <span key={l} className="badge tag" style={{ marginRight: 4 }}>{l}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid two-col">
        <div className="panel">
          <h3>Recent alerts</h3>
          <table className="data">
            <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Message</th></tr></thead>
            <tbody>
              {stats.recent_alerts.length === 0 && <tr><td colSpan={4} className="muted">No alerts yet.</td></tr>}
              {stats.recent_alerts.map((a) => (
                <tr key={a.id}>
                  <td className="mono muted">{fmtTime(a.created_at).slice(11)}</td>
                  <td><SevBadge severity={a.severity} /></td>
                  <td className="mono">{a.rule_id}</td>
                  <td className="truncate">{a.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="panel">
          <h3>Events by source category</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={stats.category_breakdown}>
              <CartesianGrid stroke="#22304d" strokeDasharray="3 3" />
              <XAxis dataKey="category" tick={{ fill: '#8ea0bd', fontSize: 11 }} />
              <YAxis tick={{ fill: '#8ea0bd', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#16233c', border: '1px solid #22304d', borderRadius: 8, color: '#e2e8f0' }} />
              <Bar dataKey="count" name="events" fill="#38bdf8" radius={[5, 5, 0, 0]} barSize={30} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
