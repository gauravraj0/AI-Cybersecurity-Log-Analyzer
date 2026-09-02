import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { SevBadge, fmtTime, fmtType } from '../components/ui.jsx';

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive'];
const role = JSON.parse(localStorage.getItem('sentinel_user') || '{}')?.role;
const canEdit = role === 'admin' || role === 'analyst';

export default function Incidents() {
  const [incidents, setIncidents] = useState(null);
  const [history, setHistory] = useState(null);
  const [filters, setFilters] = useState({ status: '', severity: '', search: '' });
  const [selected, setSelected] = useState(null);
  const [regenerating, setRegenerating] = useState(false);

  const load = useCallback(() => {
    const p = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => { if (v) p.set(k, v); });
    api(`/api/incidents?${p.toString()}`).then(setIncidents).catch(() => {});
  }, [filters]);

  useEffect(() => {
    const t = setTimeout(load, 200);
    return () => clearTimeout(t);
  }, [load]);
  useEffect(() => { api('/api/incidents/history').then(setHistory).catch(() => {}); }, []);

  async function open(id) {
    const detail = await api(`/api/incidents/${id}`);
    setSelected(detail);
  }

  async function setStatus(id, status) {
    await api(`/api/incidents/${id}/status`, { method: 'PATCH', body: { status } });
    await open(id); load();
  }

  async function regenerate(id) {
    setRegenerating(true);
    try { await api(`/api/incidents/${id}/summarize`, { method: 'POST' }); await open(id); }
    catch (e) { alert(e.message); }
    finally { setRegenerating(false); }
  }

  return (
    <div>
      {history && (
        <div className="grid kpis" style={{ marginBottom: 14 }}>
          <div className="kpi"><div className="num">{history.total_incidents}</div><div className="lbl">Total incidents (historical)</div></div>
          <div className="kpi accent-red"><div className="num">{history.open}</div><div className="lbl">Currently open</div></div>
          <div className="kpi accent-purple"><div className="num">{fmtType(history.most_common_type || '—')}</div><div className="lbl">Most common type</div></div>
          <div className="kpi accent-cyan"><div className="num">{history.mean_time_to_resolve_minutes != null ? `${history.mean_time_to_resolve_minutes} min` : '—'}</div><div className="lbl">Mean time to resolve</div></div>
        </div>
      )}

      <div className="panel" style={{ marginBottom: 14 }}>
        <div className="controls" style={{ marginBottom: 0 }}>
          <select value={filters.status} onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}>
            <option value="">Status: all</option>
            {STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={filters.severity} onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}>
            <option value="">Severity: all</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => <option key={s}>{s}</option>)}
          </select>
          <input style={{ minWidth: 220 }} placeholder="Search title / AI summary…" value={filters.search}
                 onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))} />
          <div className="toolbar-right">
            <button className="btn-sm" onClick={load}>↻ Refresh</button>
          </div>
        </div>
      </div>

      <div className="panel">
        <table className="data">
          <thead><tr><th style={{ width: 55 }}>ID</th><th>Title</th><th style={{ width: 95 }}>Severity</th><th style={{ width: 115 }}>Status</th><th style={{ width: 85 }}>Score</th><th style={{ width: 80 }}>Events</th><th style={{ width: 150 }}>Last seen</th></tr></thead>
          <tbody>
            {!incidents && <tr><td colSpan={7} className="muted">Loading…</td></tr>}
            {incidents?.length === 0 && <tr><td colSpan={7} className="muted">No incidents match. Try the simulator or anomaly detection.</td></tr>}
            {incidents?.map((i) => (
              <tr key={i.id} className="clickable" onClick={() => open(i.id)}>
                <td className="mono muted">#{i.id}</td>
                <td>
                  <div>{i.title}</div>
                  <div className="muted" style={{ fontSize: 11.5 }}>{fmtType(i.incident_type)} · {i.detection_method === 'ml_anomaly' ? '🤖 ML anomaly' : '📏 rules'} {i.mitre_tactic && `· ${i.mitre_tactic}`}</div>
                </td>
                <td><SevBadge severity={i.severity} /></td>
                <td><span className="badge tag">{i.status}</span></td>
                <td><b style={{ color: i.threat_score >= 70 ? 'var(--critical)' : 'var(--medium)' }}>{i.threat_score}</b></td>
                <td>{i.event_count}</td>
                <td className="mono muted">{fmtTime(i.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <>
          <div className="drawer-overlay" onClick={() => setSelected(null)} />
          <div className="drawer">
            <button className="close btn-sm" onClick={() => setSelected(null)}>✕ Close</button>
            <h2>{selected.title}</h2>
            <div style={{ display: 'flex', gap: 6, margin: '8px 0', flexWrap: 'wrap' }}>
              <SevBadge severity={selected.severity} />
              <span className="badge tag">{selected.status}</span>
              <span className="ai-chip">AI summary via {selected.ai_provider}</span>
              <span className="badge tag">threat {selected.threat_score}/100</span>
              {selected.mitre_tactic && <span className="badge tag">{selected.mitre_tactic}</span>}
            </div>

            <div className="section">
              <h3 style={{ color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase', margin: '0 0 6px' }}>🤖 AI incident summary</h3>
              <div className="summary-box">{selected.summary || 'No summary generated yet.'}</div>
              {selected.recommendation && (
                <>
                  <h3 style={{ color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase', margin: '12px 0 6px' }}>Recommended actions</h3>
                  <div className="summary-box" style={{ borderLeftColor: 'var(--accent)' }}>{selected.recommendation}</div>
                </>
              )}
              {canEdit && (
                <button className="btn-sm" style={{ marginTop: 10 }} onClick={() => regenerate(selected.id)} disabled={regenerating}>
                  {regenerating ? 'Generating…' : '↻ Regenerate AI summary'}
                </button>
              )}
            </div>

            <div className="section kv-list">
              <div className="kv"><div className="k">First seen</div><div className="v mono">{fmtTime(selected.first_seen)}</div></div>
              <div className="kv"><div className="k">Last seen</div><div className="v mono">{fmtTime(selected.last_seen)}</div></div>
              <div className="kv"><div className="k">Events</div><div className="v">{selected.event_count}</div></div>
              <div className="kv"><div className="k">Source IPs</div><div className="v mono">{(selected.source_ips || []).join(', ') || '—'}</div></div>
              <div className="kv"><div className="k">Targets</div><div className="v">{(selected.targets || []).slice(0, 4).join(', ') || '—'}</div></div>
              <div className="kv"><div className="k">Detection</div><div className="v">{selected.detection_method}</div></div>
            </div>

            {canEdit && (
              <div className="section" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {STATUSES.filter((s) => s !== selected.status).map((s) => (
                  <button key={s} className="btn-sm" onClick={() => setStatus(selected.id, s)}>→ {s}</button>
                ))}
              </div>
            )}

            <div className="section">
              <h3 style={{ color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase', margin: '0 0 6px' }}>Evidence trail ({selected.events.length} events)</h3>
              <table className="data">
                <thead><tr><th style={{ width: 145 }}>Time</th><th style={{ width: 85 }}>Severity</th><th style={{ width: 120 }}>IP</th><th>Message</th></tr></thead>
                <tbody>
                  {selected.events.map((l) => (
                    <tr key={l.id}>
                      <td className="mono muted">{fmtTime(l.timestamp)}</td>
                      <td><SevBadge severity={l.severity} /></td>
                      <td className="mono">{l.ip_address || '—'}</td>
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
