import React, { useEffect, useRef, useState } from 'react';
import { api, wsUrl } from '../api.js';
import { SevBadge, fmtTime, fmtType } from '../components/ui.jsx';

const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export default function LiveLogs() {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [simRunning, setSimRunning] = useState(false);
  const [simCount, setSimCount] = useState(0);
  const [minSev, setMinSev] = useState('INFO');
  const [onlyThreats, setOnlyThreats] = useState(false);
  const wsRef = useRef(null);
  const bufferRef = useRef([]);
  const role = JSON.parse(localStorage.getItem('sentinel_user') || '{}')?.role;
  const canControl = role === 'admin' || role === 'analyst';

  useEffect(() => {
    api('/api/simulator/status').then((s) => { setSimRunning(s.running); setSimCount(s.events_generated); }).catch(() => {});
    const ws = new WebSocket(wsUrl());
    wsRef.current = ws;
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        if (data.type === 'logs') {
          if (!paused) {
            bufferRef.current = [...data.payload, ...bufferRef.current].slice(0, 300);
            setEvents(bufferRef.current);
          }
        } else if (data.type === 'alert') {
          // toast-style ticker handled via events sidebar; add to feed as synthetic marker
          bufferRef.current = [{ _alert: true, ...data.payload }, ...bufferRef.current].slice(0, 300);
          setEvents(bufferRef.current);
        } else if (data.type === 'incident') {
          // refresh sim counter opportunistically
        }
      } catch { /* ignore */ }
    };
    return () => ws.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const t = setInterval(() => {
      api('/api/simulator/status').then((s) => { setSimRunning(s.running); setSimCount(s.events_generated); }).catch(() => {});
    }, 5000);
    return () => clearInterval(t);
  }, []);

  function toggleSim() {
    api(`/api/simulator/${simRunning ? 'stop' : 'start'}`, { method: 'POST' })
      .then((s) => { setSimRunning(s.running); setSimCount(s.events_generated); })
      .catch((e) => alert(e.message));
  }

  const visible = events.filter((e) => {
    if (e._alert) return true;
    if (SEV_RANK[e.severity] < SEV_RANK[minSev]) return false;
    if (onlyThreats && SEV_RANK[e.severity] < SEV_RANK.MEDIUM) return false;
    return true;
  });

  return (
    <div className="panel">
      <div className="controls" style={{ marginBottom: 10 }}>
        <span><span className={`live-dot ${connected ? 'on' : 'off'}`} />{connected ? 'WebSocket connected' : 'Disconnected'}</span>
        {canControl && (
          <button className={simRunning ? 'danger' : 'primary'} onClick={toggleSim}>
            {simRunning ? '⏹ Stop traffic simulator' : '▶ Start traffic simulator'}
          </button>
        )}
        <span className="muted">simulator events: {simCount.toLocaleString()}</span>
        <div className="toolbar-right">
          <select value={minSev} onChange={(e) => setMinSev(e.target.value)}>
            {['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
          </select>
          <label style={{ fontSize: 12.5, color: 'var(--muted)' }}>
            <input type="checkbox" checked={onlyThreats} onChange={(e) => setOnlyThreats(e.target.checked)} /> threats only
          </label>
          <button className="btn-sm" onClick={() => setPaused(!paused)}>{paused ? '▶ Resume' : '⏸ Pause'}</button>
          <button className="btn-sm ghost" onClick={() => { bufferRef.current = []; setEvents([]); }}>Clear</button>
        </div>
      </div>

      <div className="feed">
        <table className="data">
          <thead><tr><th style={{ width: 90 }}>Time</th><th style={{ width: 90 }}>Severity</th><th style={{ width: 150 }}>Type</th><th style={{ width: 120 }}>Source</th><th style={{ width: 120 }}>IP</th><th>Message</th></tr></thead>
          <tbody>
            {visible.length === 0 && <tr><td colSpan={6} className="muted">Waiting for events… start the simulator to see the live stream.</td></tr>}
            {visible.map((e, i) => e._alert ? (
              <tr key={`a${e.id}-${i}`} style={{ background: 'rgba(244,63,94,.07)' }}>
                <td className="mono muted">{fmtTime(e.created_at).slice(11)}</td>
                <td><SevBadge severity={e.severity} /></td>
                <td className="mono" style={{ color: 'var(--critical)' }}>⚠ {e.rule_id}</td>
                <td className="mono">{e.ip_address || '—'}</td>
                <td colSpan={2}>{e.message}</td>
              </tr>
            ) : (
              <tr key={`${e.id}-${i}`}>
                <td className="mono muted">{fmtTime(e.timestamp).slice(11)}</td>
                <td><SevBadge severity={e.severity} /></td>
                <td className="truncate" style={{ maxWidth: 160 }}>{fmtType(e.event_type)}</td>
                <td className="mono">{e.source}</td>
                <td className="mono">{e.ip_address || '—'}</td>
                <td className="truncate">{e.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {paused && <div className="muted" style={{ marginTop: 8 }}>Feed paused — events continue to buffer in the background.</div>}
    </div>
  );
}
