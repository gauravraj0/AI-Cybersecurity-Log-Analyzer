import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useAuth } from "../AuthContext.jsx";
import { api } from "../api.js";

export default function IncidentDetail() {
  const { id } = useParams();
  const { user, notify } = useAuth();
  const nav = useNavigate();
  const [inc, setInc] = useState(null);
  const writable = user.role !== "viewer";

  async function load() {
    const d = await api(`/api/incidents/${id}`);
    setInc(d);
  }

  useEffect(() => {
    load().catch(() => nav("/incidents"));
  }, [id]);

  async function patch(body) {
    try {
      const d = await api(`/api/incidents/${id}`, { method: "PATCH", body });
      setInc((prev) => ({ ...prev, ...d }));
      notify("Incident updated", "ok");
    } catch (e) {
      notify(e.message, "bad");
    }
  }

  if (!inc) return <div className="empty">Loading incident…</div>;

  return (
    <>
      <div className="page-head">
        <div>
          <button className="ghost" onClick={() => nav("/incidents")}>
            ← Queue
          </button>
          <h1 style={{ fontSize: 28, marginTop: 12 }}>{inc.title}</h1>
          <p>
            First seen {inc.first_seen?.replace("T", " ").slice(0, 16)} UTC · {inc.event_count} correlated events
          </p>
        </div>
        <div className="row">
          <span className={`badge ${inc.severity}`}>{inc.severity}</span>
          <span className={`badge ${inc.status}`}>{inc.status}</span>
        </div>
      </div>

      <div className="grid two">
        <div className="card">
          <h3>AI-generated summary</h3>
          <div className="markdown">{inc.ai_summary}</div>
        </div>
        <div className="card">
          <h3>Response workflow</h3>
          <div className="row" style={{ marginTop: 12 }}>
            {["open", "investigating", "contained", "resolved"].map((s) => (
              <button key={s} className={inc.status === s ? "btn" : "ghost"} disabled={!writable} onClick={() => patch({ status: s })}>
                {s}
              </button>
            ))}
          </div>
          <p className="muted small" style={{ marginTop: 14 }}>
            Assigned to {inc.assigned_to || "unassigned"} · confidence {Math.round(inc.confidence * 100)}%
          </p>
          {writable && (
            <button className="ghost" style={{ marginTop: 10 }} onClick={() => patch({ assigned_to: user.full_name })}>
              Assign to me
            </button>
          )}
          <h3 style={{ marginTop: 22 }}>MITRE ATT&CK</h3>
          <ul className="actions">
            {(inc.mitre || []).map((item, idx) => {
              const code = Array.isArray(item) ? item[0] : item?.id || item;
              const name = Array.isArray(item) ? item[1] : item?.name || "";
              return (
                <li key={`${code}-${idx}`}>
                  <span className="mono">{code}</span> — {name}
                </li>
              );
            })}
          </ul>
          <h3>Indicators</h3>
          <div className="row" style={{ marginTop: 8 }}>
            {inc.indicators.map((x) => (
              <span key={x} className="chip">
                {x}
              </span>
            ))}
          </div>
          <h3 style={{ marginTop: 18 }}>Recommended actions</h3>
          <ol className="actions">
            {inc.recommended_actions.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ol>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: 16 }}>
          <h3>Related logs</h3>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>IP</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {(inc.logs || []).map((l) => (
                <tr key={l.id}>
                  <td className="mono small">{l.timestamp?.replace("T", " ").slice(0, 19)}</td>
                  <td>{l.source}</td>
                  <td className="mono">{l.ip_address}</td>
                  <td className="log-msg">{l.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
