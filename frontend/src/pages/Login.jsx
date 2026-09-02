import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext.jsx";

const DEMOS = [
  { username: "admin", password: "Aegis#2026", label: "Maya Chen · admin" },
  { username: "analyst", password: "Analyst#2026", label: "Jordan Hale · analyst" },
  { username: "viewer", password: "Viewer#2026", label: "Riley Okonkwo · viewer" },
];

export default function Login() {
  const { user, login, notify } = useAuth();
  const nav = useNavigate();
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("Analyst#2026");
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/console" replace />;

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await login(username, password);
      notify("Secure session established", "ok");
      nav("/console");
    } catch (err) {
      notify(err.message || "Login failed", "bad");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="landing">
      <div className="hero-bg" style={{ backgroundImage: "url(/hero-soc.jpg)" }} />
      <nav className="nav-public">
        <Link to="/" className="brand" style={{ padding: 0 }}>
          <img src="/logo.png" alt="" />
          <div>
            <div className="name">AEGIS</div>
            <div className="sub">Sign in</div>
          </div>
        </Link>
      </nav>
      <section className="hero" style={{ maxWidth: 1080, margin: "0 auto" }}>
        <div>
          <div className="kicker">Restricted console</div>
          <h1>
            Authenticate
            <br />
            <span>to the SOC.</span>
          </h1>
          <p className="lede">Role-based access. Every action is attributed. Demo credentials are listed on the right.</p>
        </div>
        <form className="login-card" onSubmit={onSubmit}>
          <h2>Console login</h2>
          <p>Use a seeded identity to explore detections, AI summaries, and reports.</p>
          <label>Username</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          <button className="btn" style={{ width: "100%", marginTop: 16 }} disabled={busy}>
            {busy ? "Verifying…" : "Establish session"}
          </button>
          <div className="demo-creds">
            {DEMOS.map((d) => (
              <button
                type="button"
                key={d.username}
                onClick={() => {
                  setUsername(d.username);
                  setPassword(d.password);
                }}
              >
                {d.label}
                <div className="mono muted">
                  {d.username} / {d.password}
                </div>
              </button>
            ))}
          </div>
        </form>
      </section>
    </div>
  );
}
