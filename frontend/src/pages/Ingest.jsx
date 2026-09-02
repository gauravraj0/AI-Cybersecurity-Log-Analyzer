import { useState } from "react";
import { useAuth } from "../AuthContext.jsx";
import { api } from "../api.js";

const SAMPLE = `185.220.101.77 - - [02/Sep/2026:11:04:11 +0000] "GET /api/v2/users?id=1' OR 1=1-- HTTP/1.1" 403 312
45.155.205.201 - - [02/Sep/2026:11:04:12 +0000] "GET /api/v2/users?id=1 UNION SELECT password FROM users-- HTTP/1.1" 403 298
{"timestamp":"2026-09-02T11:04:15Z","source":"sshd","message":"Failed password for root from 103.45.12.90 port 44112 ssh2","ip":"103.45.12.90","user":"root"}
Sep  2 11:04:18 auth-01 sshd: Failed password for admin from 103.45.12.90 port 44118 ssh2
10.0.0.22 - - [02/Sep/2026:11:04:20 +0000] "GET /health HTTP/1.1" 200 87
`;

export default function Ingest() {
  const { user, notify } = useAuth();
  const [text, setText] = useState(SAMPLE);
  const [source, setSource] = useState("upload");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const writable = user.role !== "viewer";

  async function ingest() {
    setBusy(true);
    try {
      const d = await api("/api/logs/ingest", { method: "POST", body: { text, source } });
      setResult(d);
      notify(`Ingested ${d.ingested} events · ${d.anomalies} anomalies`, "ok");
    } catch (e) {
      notify(e.message, "bad");
    } finally {
      setBusy(false);
    }
  }

  async function upload(file) {
    const fd = new FormData();
    fd.append("file", file);
    setBusy(true);
    try {
      const d = await api("/api/logs/upload", { method: "POST", body: fd, isForm: true });
      setResult(d);
      notify(`Uploaded ${d.ingested} events`, "ok");
    } catch (e) {
      notify(e.message, "bad");
    } finally {
      setBusy(false);
    }
  }

  async function simulate() {
    setBusy(true);
    try {
      const d = await api("/api/demo/simulate", { method: "POST" });
      setResult(d);
      notify(`Simulated ${d.kind} from ${d.ip}`, "ok");
    } catch (e) {
      notify(e.message, "bad");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">Log ingestion</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Bring your own telemetry</h1>
          <p>Paste combined Apache/nginx lines, syslog, or JSON. AEGIS parses, enriches, scores, and may open incidents.</p>
        </div>
        {writable && (
          <button className="btn-danger" onClick={simulate} disabled={busy}>
            Simulate live attack
          </button>
        )}
      </div>
      {!writable && <div className="card">Viewer role is read-only. Ask an analyst to ingest.</div>}
      <div className="grid two">
        <div className="card">
          <div className="filters" style={{ marginBottom: 10 }}>
            <input className="field" value={source} onChange={(e) => setSource(e.target.value)} placeholder="source label" />
            <label className="ghost" style={{ cursor: "pointer" }}>
              Upload file
              <input
                type="file"
                hidden
                accept=".log,.txt,.json,.jsonl"
                onChange={(e) => e.target.files[0] && upload(e.target.files[0])}
                disabled={!writable}
              />
            </label>
          </div>
          <textarea className="field" value={text} onChange={(e) => setText(e.target.value)} disabled={!writable} />
          <button className="btn" style={{ marginTop: 12 }} disabled={!writable || busy} onClick={ingest}>
            {busy ? "Analyzing…" : "Ingest & analyze"}
          </button>
        </div>
        <div className="card">
          <h3>Last analysis</h3>
          {!result ? (
            <p className="muted" style={{ marginTop: 12 }}>
              Run an ingest to see anomaly counts and any incidents the correlator opened.
            </p>
          ) : (
            <>
              <div className="stat">{result.ingested}</div>
              <div className="stat-sub">events ingested · {result.anomalies} flagged anomalous</div>
              <h3 style={{ marginTop: 18 }}>Incidents touched</h3>
              {(result.incidents || []).length === 0 && <p className="muted small">No new clusters (need repeated hostile events).</p>}
              {(result.incidents || []).map((i) => (
                <div key={i.id} className="alert-item">
                  <span className={`dot ${i.severity}`} />
                  <div>
                    <strong>{i.title}</strong>
                    <p>{i.threat_type} · {i.event_count} events</p>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </>
  );
}
