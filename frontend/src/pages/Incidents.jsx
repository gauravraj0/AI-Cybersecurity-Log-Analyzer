import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";

export default function Incidents() {
  const [items, setItems] = useState([]);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const nav = useNavigate();

  useEffect(() => {
    const p = new URLSearchParams();
    if (status) p.set("status", status);
    if (severity) p.set("severity", severity);
    if (q) p.set("q", q);
    api(`/api/incidents?${p}`).then((d) => setItems(d.items)).catch(() => {});
  }, [status, severity, q]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">Incident response</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Correlated incidents</h1>
          <p>Signature hits and ML outliers clustered by tactic and source IP, each with an AI-written brief.</p>
        </div>
      </div>
      <div className="filters">
        <input placeholder="Search title / tactic" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {["open", "investigating", "contained", "resolved"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </div>
      <div className="grid split">
        {items.map((i) => (
          <article className="card row-link" key={i.id} onClick={() => nav(`/incidents/${i.id}`)}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className={`badge ${i.severity}`}>{i.severity}</span>
              <span className={`badge ${i.status}`}>{i.status}</span>
            </div>
            <h2 style={{ fontSize: 18, margin: "12px 0 8px" }}>{i.title}</h2>
            <p className="muted small">
              {i.threat_type.replaceAll("_", " ")} · {i.event_count} events · conf {Math.round(i.confidence * 100)}%
            </p>
            <p className="muted small" style={{ marginTop: 8 }}>
              {i.source_ips.join(", ")} · last {i.last_seen?.replace("T", " ").slice(0, 16)} UTC
            </p>
          </article>
        ))}
      </div>
      {!items.length && <div className="empty">No incidents match filters.</div>}
    </>
  );
}
