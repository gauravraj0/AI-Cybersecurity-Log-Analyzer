import React, { useCallback, useEffect, useState } from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { api } from '../api.js';
import { SevBadge, fmtTime } from '../components/ui.jsx';

export default function IpAnalysis() {
  const [onlyMal, setOnlyMal] = useState(false);
  const [profiles, setProfiles] = useState(null);
  const [detail, setDetail] = useState(null);

  const load = useCallback(() => {
    api(`/api/analytics/ips?only_malicious=${onlyMal}&limit=100`).then(setProfiles).catch(() => {});
  }, [onlyMal]);
  useEffect(load, [load]);

  async function open(ip) { setDetail(await api(`/api/analytics/ips/${encodeURIComponent(ip)}`)); }

  return (
    <div>
      <div className="panel" style={{ marginBottom: 14 }}>
        <div className="controls" style={{ marginBottom: 0 }}>
          <label style={{ fontSize: 13, color: 'var(--muted)' }}>
            <input type="checkbox" checked={onlyMal} onChange={(e) => setOnlyMal(e.target.checked)} /> Only malicious IPs
          </label>
          <div className="toolbar-right"><button className="btn-sm" onClick={load}>↻ Refresh</button></div>
        </div>
      </div>

      <div className="panel">
        <table className="data">
          <thead><tr><th style={{ width: 150 }}>IP</th><th style={{ width: 80 }}>Threat</th><th style={{ width: 100 }}>Requests</th><th style={{ width: 110 }}>Failed logins</th><th style={{ width: 80 }}>Errors</th><th style={{ width: 150 }}>Last seen</th><th>Behavioural labels</th></tr></thead>
          <tbody>
            {!profiles && <tr><td colSpan={7} className="muted">Loading…</td></tr>}
            {profiles?.length === 0 && <tr><td colSpan={7} className="muted">No IP activity recorded.</td></tr>}
            {profiles?.map((p) => (
              <tr key={p.ip} className="clickable" onClick={() => open(p.ip)}>
                <td className="mono">{p.ip} {p.is_malicious && <span className="badge critical">malicious</span>}</td>
                <td><b style={{ color: p.threat_score >= 70 ? 'var(--critical)' : p.threat_score >= 40 ? 'var(--medium)' : 'var(--ok)' }}>{p.threat_score}/100</b></td>
                <td>{p.total_requests}</td>
                <td>{p.failed_logins}</td>
                <td>{p.error_count}</td>
                <td className="mono muted">{fmtTime(p.last_seen)}</td>
                <td>{(p.labels || []).map((l) => <span key={l} className="badge tag" style={{ marginRight: 4 }}>{l}</span>)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {detail && (
        <>
          <div className="drawer-overlay" onClick={() => setDetail(null)} />
          <div className="drawer">
            <button className="close btn-sm" onClick={() => setDetail(null)}>✕ Close</button>
            <h2 className="mono">{detail.profile?.ip || 'Unknown IP'}</h2>
            <div style={{ display: 'flex', gap: 6, margin: '8px 0' }}>
              {detail.profile?.is_malicious ? <span className="badge critical">malicious</span> : <span className="badge ok">clean</span>}
              <span className="ai-chip">threat {detail.profile?.threat_score ?? 0}/100</span>
              <span className="badge tag">{detail.event_count} recent events</span>
            </div>

            <div className="section">
              <h3 style={{ color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase', margin: '0 0 6px' }}>Activity timeline</h3>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={detail.timeline}>
                  <defs>
                    <linearGradient id="gIp" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#a78bfa" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="#a78bfa" stopOpacity={0.03} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#22304d" strokeDasharray="3 3" />
                  <XAxis dataKey="hour" tick={{ fill: '#8ea0bd', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#8ea0bd', fontSize: 10 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#16233c', border: '1px solid #22304d', borderRadius: 8, color: '#e2e8f0' }} />
                  <Area type="monotone" dataKey="count" name="events" stroke="#a78bfa" fill="url(#gIp)" strokeWidth={2} />
                  <Area type="monotone" dataKey="threats" name="threats" stroke="#f43f5e" fill="transparent" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="section kv-list">
              <div className="kv"><div className="k">Top event types</div><div className="v">{detail.event_types.slice(0, 5).map(([t, c]) => `${t} (${c})`).join(', ') || '—'}</div></div>
              <div className="kv"><div className="k">Top paths</div><div className="v mono" style={{ wordBreak: 'break-all' }}>{detail.top_paths.slice(0, 4).map(([t, c]) => `${t} (${c})`).join(', ') || '—'}</div></div>
              <div className="kv"><div className="k">Users</div><div className="v">{detail.users.map(([u, c]) => `${u} (${c})`).join(', ') || '—'}</div></div>
              <div className="kv"><div className="k">Status codes</div><div className="v">{detail.status_codes.map(([s, c]) => `${s}×${c}`).join(', ') || '—'}</div></div>
            </div>

            <div className="section">
              <h3 style={{ color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase', margin: '0 0 6px' }}>Recent events</h3>
              <table className="data">
                <thead><tr><th style={{ width: 145 }}>Time</th><th style={{ width: 85 }}>Severity</th><th>Message</th></tr></thead>
                <tbody>
                  {detail.recent_logs.map((l, i) => (
                    <tr key={`${l.id}-${i}`}>
                      <td className="mono muted">{fmtTime(l.timestamp)}</td>
                      <td><SevBadge severity={l.severity} /></td>
                      <td className="truncate">{l.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
