import { useEffect, useState } from "react";
import { api, download } from "../api.js";
import { useAuth } from "../AuthContext.jsx";

export default function Reports() {
  const { notify } = useAuth();
  const [sum, setSum] = useState(null);

  useEffect(() => {
    api("/api/reports/summary").then(setSum).catch(() => {});
  }, []);

  async function exp(fmt) {
    try {
      await download(`/api/reports/export?fmt=${fmt}`, `aegis-incidents.${fmt}`);
      notify(`Exported ${fmt.toUpperCase()}`, "ok");
    } catch (e) {
      notify(e.message, "bad");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">Exportable reports</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Weekly threat brief</h1>
          <p>Generative narrative over the retained window, plus machine-readable incident exports.</p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => exp("csv")}>
            Export CSV
          </button>
          <button className="ghost" onClick={() => exp("json")}>
            Export JSON
          </button>
        </div>
      </div>
      {!sum ? (
        <div className="empty">Compiling brief…</div>
      ) : (
        <div className="grid two">
          <div className="card">
            <h3>AI narrative</h3>
            <p style={{ marginTop: 12, lineHeight: 1.7 }}>{sum.narrative}</p>
            <p className="muted small" style={{ marginTop: 16 }}>
              Generated {sum.generated_at?.replace("T", " ").slice(0, 19)} UTC
            </p>
          </div>
          <div className="card">
            <h3>Window KPIs</h3>
            <div className="grid split" style={{ marginTop: 12 }}>
              <div>
                <div className="small muted">Logs</div>
                <div className="stat">{sum.logs.toLocaleString()}</div>
              </div>
              <div>
                <div className="small muted">Incidents</div>
                <div className="stat">{sum.incidents}</div>
              </div>
            </div>
            <h3 style={{ marginTop: 16 }}>By severity</h3>
            {Object.entries(sum.by_severity).map(([k, v]) => (
              <div key={k} className="row" style={{ justifyContent: "space-between", padding: "8px 0" }}>
                <span className={`badge ${k}`}>{k}</span>
                <strong>{v}</strong>
              </div>
            ))}
            <h3 style={{ marginTop: 8 }}>By status</h3>
            {Object.entries(sum.by_status).map(([k, v]) => (
              <div key={k} className="row" style={{ justifyContent: "space-between", padding: "6px 0" }}>
                <span className={`badge ${k}`}>{k}</span>
                <span>{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
