import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api.js";

export default function LiveMonitor() {
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get("q") || "");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState("");
  const [anomalies, setAnomalies] = useState(false);
  const [live, setLive] = useState(true);
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ items: [], total: 0, sources: [] });

  const query = useMemo(() => {
    const p = new URLSearchParams({ page, page_size: 40 });
    if (q) p.set("q", q);
    if (source) p.set("source", source);
    if (severity) p.set("severity", severity);
    if (anomalies) p.set("anomalies", "true");
    return `/api/logs?${p.toString()}`;
  }, [q, source, severity, anomalies, page]);

  async function load() {
    const d = await api(query);
    setData(d);
  }

  useEffect(() => {
    load().catch(() => {});
  }, [query]);

  useEffect(() => {
    if (!live) return;
    const t = setInterval(() => load().catch(() => {}), 4000);
    return () => clearInterval(t);
  }, [live, query]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">Real-time monitoring</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Live log stream</h1>
          <p>Search, filter, and watch newly ingested events. Anomalous rows are highlighted.</p>
        </div>
        <div className="row">
          {live && (
            <span className="live-flag">
              <span className="pulse" /> LIVE
            </span>
          )}
          <button className="ghost" onClick={() => setLive((v) => !v)}>
            {live ? "Pause" : "Resume"}
          </button>
        </div>
      </div>

      <div className="filters">
        <input value={q} onChange={(e) => { setPage(1); setQ(e.target.value); }} placeholder="Filter message / IP / path" />
        <select value={source} onChange={(e) => { setPage(1); setSource(e.target.value); }}>
          <option value="">All sources</option>
          {data.sources.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select value={severity} onChange={(e) => { setPage(1); setSeverity(e.target.value); }}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <button className={anomalies ? "btn" : "ghost"} onClick={() => { setPage(1); setAnomalies((v) => !v); }}>
          Anomalies only
        </button>
        <span className="muted small">{data.total.toLocaleString()} matching</span>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Src</th>
                <th>Sev</th>
                <th>IP</th>
                <th>Event</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((l) => (
                <tr key={l.id} style={l.is_anomaly ? { background: "rgba(255,59,92,0.05)" } : undefined}>
                  <td className="mono small">{l.timestamp?.replace("T", " ").slice(0, 19)}</td>
                  <td>{l.source}</td>
                  <td>
                    <span className={`badge ${l.severity}`}>{l.severity}</span>
                  </td>
                  <td className="mono">
                    {l.ip_address || "—"}
                    <div className="small muted">{l.country}</div>
                  </td>
                  <td>
                    <div className="log-msg">
                      <span className={`dot ${l.level}`} />
                      {l.message}
                    </div>
                    {l.threat_type && <div className="small muted">{l.threat_type.replaceAll("_", " ")} · {l.path || l.host}</div>}
                  </td>
                  <td className="mono small">{l.is_anomaly ? l.anomaly_score.toFixed(2) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="pager">
        <button className="ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
          Prev
        </button>
        <span>Page {page}</span>
        <button className="ghost" disabled={page * 40 >= data.total} onClick={() => setPage((p) => p + 1)}>
          Next
        </button>
      </div>
    </>
  );
}
