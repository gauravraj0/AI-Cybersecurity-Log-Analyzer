import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { SevBadge, fmtTime } from '../components/ui.jsx';

const role = JSON.parse(localStorage.getItem('sentinel_user') || '{}')?.role;
const canEdit = role === 'admin' || role === 'analyst';

export default function Alerts() {
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [ack, setAck] = useState('');

  const load = useCallback(() => {
    const p = new URLSearchParams({ page: String(page), page_size: '50' });
    if (severity) p.set('severity', severity);
    if (ack !== '') p.set('acknowledged', ack);
    api(`/api/alerts?${p}`).then(setData).catch(() => {});
  }, [page, severity, ack]);

  useEffect(() => {
    const t = setTimeout(load, 200);
    return () => clearTimeout(t);
  }, [load]);

  async function toggleAck(a) {
    await api(`/api/alerts/${a.id}/${a.acknowledged ? 'unack' : 'ack'}`, { method: 'POST' });
    load();
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div className="panel">
      <div className="controls">
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">Severity: all</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={ack} onChange={(e) => { setAck(e.target.value); setPage(1); }}>
          <option value="">Acknowledged: all</option>
          <option value="false">Unacknowledged</option>
          <option value="true">Acknowledged</option>
        </select>
        <div className="toolbar-right"><button className="btn-sm" onClick={load}>↻ Refresh</button></div>
      </div>

      <table className="data">
        <thead><tr><th style={{ width: 150 }}>Time</th><th style={{ width: 90 }}>Severity</th><th style={{ width: 150 }}>Rule</th><th>Message</th><th style={{ width: 120 }}>IP</th><th style={{ width: 110 }}>Incident</th><th style={{ width: 130 }}>State</th></tr></thead>
        <tbody>
          {!data && <tr><td colSpan={7} className="muted">Loading…</td></tr>}
          {data?.items.length === 0 && <tr><td colSpan={7} className="muted">No alerts match.</td></tr>}
          {data?.items.map((a) => (
            <tr key={a.id} style={!a.acknowledged && a.severity === 'CRITICAL' ? { background: 'rgba(244,63,94,.06)' } : undefined}>
              <td className="mono muted">{fmtTime(a.created_at)}</td>
              <td><SevBadge severity={a.severity} /></td>
              <td className="mono truncate" style={{ maxWidth: 150 }}>{a.rule_id} · {a.rule_name}</td>
              <td className="truncate">{a.message}</td>
              <td className="mono">{a.ip_address || '—'}</td>
              <td>{a.incident_id ? <a href="#/incidents" className="mono">#{a.incident_id}</a> : '—'}</td>
              <td>
                {a.acknowledged
                  ? <span className="badge ok">ack by {a.acknowledged_by}</span>
                  : canEdit ? <button className="btn-sm" onClick={() => toggleAck(a)}>Acknowledge</button>
                  : <span className="badge medium">pending</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="pager">
        <button className="btn-sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>← Prev</button>
        <span>page {page} / {totalPages} — {data?.total ?? '…'} alerts</span>
        <button className="btn-sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next →</button>
      </div>
    </div>
  );
}
