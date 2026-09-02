import React, { useEffect, useState } from 'react';
import { api, downloadFile, openReport } from '../api.js';
import { Kpi, pct, fmtType } from '../components/ui.jsx';

export default function Reports() {
  const [report, setReport] = useState(null);
  const [hours, setHours] = useState(24);
  const [busy, setBusy] = useState('');
  const role = JSON.parse(localStorage.getItem('sentinel_user') || '{}')?.role;
  const canExport = role === 'admin' || role === 'analyst';

  useEffect(() => { setReport(null); api(`/api/reports/executive?hours=${hours}`).then(setReport).catch(() => {}); }, [hours]);

  async function guard(fn, name) {
    setBusy(name);
    try { await fn(); } catch (e) { alert(e.message); } finally { setBusy(''); }
  }

  return (
    <div>
      <div className="panel" style={{ marginBottom: 14 }}>
        <div className="controls" style={{ marginBottom: 0 }}>
          <b>Exportable reports</b>
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            <option value={24}>Last 24 hours</option>
            <option value={72}>Last 3 days</option>
            <option value={168}>Last 7 days</option>
            <option value={720}>Last 30 days</option>
          </select>
          <div className="toolbar-right" style={{ flexWrap: 'wrap' }}>
            <button disabled={!canExport} onClick={() => guard(() => downloadFile('/api/reports/logs.csv?hours=' + hours, 'sentinellens_logs.csv'), 'logs')}>
              {busy === 'logs' ? '…' : '⬇ Logs CSV'}
            </button>
            <button disabled={!canExport} onClick={() => guard(() => downloadFile('/api/reports/incidents.csv', 'sentinellens_incidents.csv'), 'inc')}>
              {busy === 'inc' ? '…' : '⬇ Incidents CSV'}
            </button>
            <button disabled={!canExport} onClick={() => guard(() => downloadFile('/api/reports/incidents.json', 'sentinellens_incidents.json'), 'incj')}>
              {busy === 'incj' ? '…' : '⬇ Incidents JSON'}
            </button>
            <button disabled={!canExport} onClick={() => guard(() => downloadFile('/api/reports/alerts.csv', 'sentinellens_alerts.csv'), 'alerts')}>
              {busy === 'alerts' ? '…' : '⬇ Alerts CSV'}
            </button>
            <button className="primary" disabled={!canExport} onClick={() => guard(() => openReport(`/api/reports/executive.html?hours=${hours}`), 'exec')}>
              {busy === 'exec' ? '…' : '🖨 Executive report (HTML / print)'}
            </button>
          </div>
        </div>
        {!canExport && <div className="muted" style={{ marginTop: 8 }}>Exports require the analyst or admin role.</div>}
      </div>

      {!report && <div className="panel muted">Generating executive summary…</div>}
      {report && (
        <>
          <div className="grid kpis" style={{ marginBottom: 14 }}>
            <Kpi label="Log events in window" value={report.kpi.total_events.toLocaleString()} accent="accent-cyan" />
            <Kpi label="Incidents" value={report.kpi.incidents} accent="accent-purple" />
            <Kpi label="Critical incidents" value={report.kpi.critical_incidents} accent="accent-red" />
            <Kpi label="Alerts" value={report.kpi.alerts} accent="accent-amber" />
            <Kpi label="Error rate" value={pct(report.kpi.error_rate)} />
            <Kpi label="Top threat" value={fmtType(report.kpi.top_attack_type || '—')} accent="accent-red" />
          </div>

          <div className="grid two-col">
            <div className="panel">
              <h3>Severity distribution</h3>
              {Object.entries(report.severity_breakdown).map(([s, c]) => (
                <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '8px 0' }}>
                  <span className={`badge ${s.toLowerCase()}`} style={{ width: 86, textAlign: 'center' }}>{s}</span>
                  <div style={{ flex: 1, background: 'var(--panel-2)', borderRadius: 6, height: 10 }}>
                    <div style={{ width: `${Math.min(100, (c / (report.kpi.total_events || 1)) * 100)}%`, height: '100%', borderRadius: 6, background: 'linear-gradient(90deg,#38bdf8,#2563eb)' }} />
                  </div>
                  <span className="mono muted">{c.toLocaleString()}</span>
                </div>
              ))}
              <h3 style={{ marginTop: 18 }}>Top threat sources</h3>
              {report.top_ips.map(([ip, c]) => (
                <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', margin: '5px 0' }}>
                  <code>{ip}</code><span className="muted">{c} events</span>
                </div>
              ))}
            </div>
            <div className="panel">
              <h3>Incident register (AI-analysed)</h3>
              {report.incidents.length === 0 && <div className="muted">No incidents in this window.</div>}
              {report.incidents.map((i) => (
                <div key={i.id} className="kv" style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span className={`badge ${i.severity.toLowerCase()}`}>{i.severity}</span>
                    <b>#{i.id} {i.title}</b>
                    <span className="muted">· {i.event_count} events · {i.status}</span>
                  </div>
                  <div className="muted" style={{ marginTop: 6, fontSize: 12.5, lineHeight: 1.55 }}>{i.summary?.slice(0, 260)}{(i.summary || '').length > 260 ? '…' : ''}</div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
