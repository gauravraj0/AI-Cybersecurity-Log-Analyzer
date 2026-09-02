import React, { useCallback, useEffect, useState } from 'react';
import { api, downloadFile } from '../api.js';
import { SevBadge, fmtBytes, fmtTime, fmtType } from '../components/ui.jsx';

const EMPTY_FILTERS = { search: '', level: '', severity: '', category: '', event_type: '', ip: '', hours: '' };

export default function LogsExplorer() {
  const [filters, setFilters] = useState({ ...EMPTY_FILTERS });
  const [facets, setFacets] = useState(null);
  const [page, setPage] = useState(1);
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState('');

  const qs = useCallback((extra = {}) => {
    const p = new URLSearchParams();
    Object.entries({ ...filters, ...extra }).forEach(([k, v]) => { if (v) p.set(k, v); });
    return p.toString();
  }, [filters]);

  useEffect(() => { api('/api/logs/facets').then(setFacets).catch(() => {}); }, []);
  useEffect(() => {
    const t = setTimeout(() => {
      api(`/api/logs?page=${page}&page_size=50&${qs()}`).then(setData).catch((e) => setError(e.message));
    }, 250);
    return () => clearTimeout(t);
  }, [page, qs]);

  function set(k, v) { setFilters((f) => ({ ...f, [k]: v })); setPage(1); }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <div>
      <div className="panel" style={{ marginBottom: 14 }}>
        <div className="controls">
          <input style={{ minWidth: 250 }} placeholder="🔍 Search message, path, IP, user…" value={filters.search}
                 onChange={(e) => set('search', e.target.value)} />
          <select value={filters.level} onChange={(e) => set('level', e.target.value)}>
            <option value="">Level: all</option>
            {facets?.levels?.map((l) => <option key={l}>{l}</option>)}
          </select>
          <select value={filters.severity} onChange={(e) => set('severity', e.target.value)}>
            <option value="">Severity: all</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={filters.category} onChange={(e) => set('category', e.target.value)}>
            <option value="">Category: all</option>
            {facets?.categories?.map((c) => <option key={c}>{c}</option>)}
          </select>
          <select value={filters.event_type} onChange={(e) => set('event_type', e.target.value)}>
            <option value="">Event type: all</option>
            {facets?.event_types?.map((t) => <option key={t}>{t}</option>)}
          </select>
          <input style={{ width: 130 }} placeholder="IP address" value={filters.ip} onChange={(e) => set('ip', e.target.value)} />
          <select value={filters.hours} onChange={(e) => set('hours', e.target.value)}>
            <option value="">Time: all</option>
            <option value="1">Last hour</option>
            <option value="6">Last 6h</option>
            <option value="24">Last 24h</option>
            <option value="72">Last 3 days</option>
            <option value="168">Last 7 days</option>
          </select>
          <button className="btn-sm ghost" onClick={() => { setFilters({ ...EMPTY_FILTERS }); setPage(1); }}>Reset</button>
          <div className="toolbar-right">
            <button className="btn-sm" onClick={() => downloadFile(`/api/reports/logs.csv?${qs()}`, 'sentinellens_logs.csv')}>⬇ Export CSV</button>
          </div>
        </div>
      </div>

      {error && <div className="error-msg">{error}</div>}

      <div className="panel">
        {data && <div className="muted" style={{ marginBottom: 8 }}>{data.total.toLocaleString()} matching events</div>}
        <table className="data">
          <thead><tr><th style={{ width: 150 }}>Timestamp</th><th style={{ width: 90 }}>Level</th><th style={{ width: 90 }}>Severity</th><th style={{ width: 160 }}>Type</th><th style={{ width: 120 }}>Source</th><th style={{ width: 120 }}>IP</th><th>Message</th></tr></thead>
          <tbody>
            {!data && <tr><td colSpan={7} className="muted">Loading…</td></tr>}
            {data?.items.length === 0 && <tr><td colSpan={7} className="muted">No events match the filters.</td></tr>}
            {data?.items.map((l) => (
              <tr key={l.id} className="clickable" onClick={() => setSelected(l)}>
                <td className="mono muted">{fmtTime(l.timestamp)}</td>
                <td>{l.level}</td>
                <td><SevBadge severity={l.severity} /></td>
                <td className="truncate" style={{ maxWidth: 160 }}>{fmtType(l.event_type)}</td>
                <td className="mono">{l.source}</td>
                <td className="mono">{l.ip_address || '—'}</td>
                <td className="truncate">{l.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="pager">
          <button className="btn-sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>← Prev</button>
          <span>page {page} / {totalPages}</span>
          <button className="btn-sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next →</button>
        </div>
      </div>

      {selected && (
        <>
          <div className="drawer-overlay" onClick={() => setSelected(null)} />
          <div className="drawer">
            <button className="close btn-sm" onClick={() => setSelected(null)}>✕ Close</button>
            <h2>Event #{selected.id}</h2>
            <div style={{ margin: '6px 0 12px', display: 'flex', gap: 6 }}>
              <SevBadge severity={selected.severity} />
              <span className="badge tag">{selected.level}</span>
              <span className="badge tag">{fmtType(selected.event_type)}</span>
              <span className="ai-chip">threat {selected.threat_score}/100</span>
            </div>
            <div className="kv-list">
              <div className="kv"><div className="k">Timestamp</div><div className="v mono">{fmtTime(selected.timestamp)}</div></div>
              <div className="kv"><div className="k">Source</div><div className="v">{selected.source} @ {selected.host || '—'}</div></div>
              <div className="kv"><div className="k">IP address</div><div className="v mono">{selected.ip_address || '—'}</div></div>
              <div className="kv"><div className="k">User</div><div className="v mono">{selected.username || '—'}</div></div>
              <div className="kv"><div className="k">HTTP</div><div className="v mono">{selected.method || '—'} {selected.path || ''} {selected.status_code ?? ''}</div></div>
              <div className="kv"><div className="k">Bytes</div><div className="v">{fmtBytes(selected.bytes_sent)}</div></div>
            </div>
            {selected.labels?.length > 0 && (
              <div className="section" style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {selected.labels.map((l) => <span key={l} className="badge tag">{l}</span>)}
              </div>
            )}
            <div className="section">
              <h3 style={{ margin: '0 0 6px', color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase' }}>Message</h3>
              <div className="summary-box">{selected.message}</div>
            </div>
            <div className="section">
              <h3 style={{ margin: '0 0 6px', color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase' }}>Raw log line</h3>
              <div className="summary-box mono" style={{ borderLeftColor: 'var(--accent)' }}>{selected.raw || selected.message}</div>
            </div>
            {Object.keys(selected.meta || {}).length > 0 && (
              <div className="section">
                <h3 style={{ margin: '0 0 6px', color: 'var(--muted)', fontSize: 12, textTransform: 'uppercase' }}>Metadata</h3>
                <pre className="summary-box mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(selected.meta, null, 2)}</pre>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
