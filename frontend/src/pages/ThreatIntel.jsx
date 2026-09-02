import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api.js";

export default function ThreatIntel() {
  const [params] = useSearchParams();
  const [items, setItems] = useState([]);
  const [q, setQ] = useState(params.get("ip") || "");
  const [sel, setSel] = useState(null);

  useEffect(() => {
    api(`/api/ips${q ? `?q=${encodeURIComponent(q)}` : ""}`)
      .then((d) => {
        setItems(d.items);
        const match = d.items.find((i) => i.ip === params.get("ip")) || d.items[0];
        if (match) loadIp(match.ip);
      })
      .catch(() => {});
  }, [q]);

  async function loadIp(ip) {
    const d = await api(`/api/ips/${ip}`);
    setSel(d);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">IP / activity analysis</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Threat intelligence</h1>
          <p>Reputation is derived from failure ratio, anomaly count, TOR/scanner tags, and volume.</p>
        </div>
      </div>
      <div className="filters">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter IP / country / city" />
      </div>
      <div className="grid two">
        <div className="card" style={{ padding: 0 }}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Geo</th>
                  <th>Level</th>
                  <th>Rep</th>
                </tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr key={p.ip} className="row-link" onClick={() => loadIp(p.ip)}>
                    <td className="mono">{p.ip}</td>
                    <td>
                      {p.city}, {p.country}
                    </td>
                    <td>
                      <span className={`badge ${p.threat_level}`}>{p.threat_level}</span>
                    </td>
                    <td>{p.reputation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          {!sel ? (
            <div className="empty">Select an IP</div>
          ) : (
            <>
              <div className="mono" style={{ color: "var(--cyan)", fontSize: 20 }}>
                {sel.ip}
              </div>
              <p className="muted">
                {sel.city}, {sel.country} · {sel.asn}
              </p>
              <div className="row" style={{ marginTop: 12 }}>
                {(sel.tags || []).map((t) => (
                  <span className="chip" key={t}>
                    {t}
                  </span>
                ))}
              </div>
              <div className="grid split" style={{ marginTop: 16 }}>
                <div>
                  <div className="small muted">Requests</div>
                  <div className="stat" style={{ fontSize: 24 }}>
                    {sel.total_requests}
                  </div>
                </div>
                <div>
                  <div className="small muted">Failures</div>
                  <div className="stat" style={{ fontSize: 24 }}>
                    {sel.failed_requests}
                  </div>
                </div>
              </div>
              <p className="muted small" style={{ marginTop: 10 }}>{sel.notes}</p>
              <h3 style={{ marginTop: 18 }}>Recent activity</h3>
              {(sel.logs || []).slice(0, 12).map((l) => (
                <div key={l.id} className="alert-item">
                  <span className={`dot ${l.severity}`} />
                  <div>
                    <div className="log-msg">{l.message}</div>
                    <p>{l.timestamp?.replace("T", " ").slice(0, 19)}</p>
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
