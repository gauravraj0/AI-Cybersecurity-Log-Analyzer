import { useEffect, useState } from "react";
import { api } from "../api.js";

export default function Anomalies() {
  const [data, setData] = useState({ items: [], model: "", trained: false });

  useEffect(() => {
    api("/api/anomalies").then(setData).catch(() => {});
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">Machine learning</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Anomaly detection</h1>
          <p>
            Model: {data.model || "loading"} {data.trained ? "· trained on current window" : ""} — features include hour-of-day,
            request volume, failure ratio, unique paths, byte volume, and signature density.
          </p>
        </div>
      </div>
      <div className="card" style={{ padding: 0 }}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Score</th>
                <th>Time</th>
                <th>IP</th>
                <th>Type</th>
                <th>Event</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((l) => (
                <tr key={l.id}>
                  <td className="mono">{l.anomaly_score.toFixed(3)}</td>
                  <td className="mono small">{l.timestamp?.replace("T", " ").slice(0, 19)}</td>
                  <td className="mono">{l.ip_address}</td>
                  <td>
                    <span className={`badge ${l.severity}`}>{l.threat_type || "behavioral"}</span>
                  </td>
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
