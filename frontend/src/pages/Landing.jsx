import { Link, useNavigate } from "react-router-dom";
import { Activity, Brain, Lock, Radar, Shield, Siren } from "lucide-react";
import { useAuth } from "../AuthContext.jsx";

const FEATURES = [
  { icon: Activity, title: "Log ingestion & live tail", body: "Parse nginx, syslog, JSON, and app traces. Stream new events into a single timeline." },
  { icon: Radar, title: "Anomaly detection", body: "Isolation Forest scores IP behavior — hour, failure ratio, path diversity, byte volume." },
  { icon: Siren, title: "Suspicious activity IDs", body: "SQLi, XSS, brute force, path traversal, scanners, exfil bursts, ransomware precursors." },
  { icon: Brain, title: "Generative incident summaries", body: "Every cluster gets a MITRE-mapped narrative, confidence, and a response playbook." },
];

export default function Landing() {
  const { user } = useAuth();
  const nav = useNavigate();
  return (
    <div className="landing">
      <div className="hero-bg" style={{ backgroundImage: "url(/hero-soc.jpg)" }} />
      <nav className="nav-public">
        <div className="brand" style={{ padding: 0 }}>
          <img src="/logo.png" alt="" />
          <div>
            <div className="name">AEGIS</div>
            <div className="sub">Cyber defense</div>
          </div>
        </div>
        <div className="row">
          <Link className="ghost" to="/login">
            Console login
          </Link>
          <button className="btn" onClick={() => nav(user ? "/console" : "/login")}>
            {user ? "Open console" : "Launch demo"}
          </button>
        </div>
      </nav>

      <section className="hero">
        <div>
          <div className="kicker">AI Cybersecurity Log Analyzer</div>
          <h1>
            See every threat.
            <br />
            <span>Stop every breach.</span>
          </h1>
          <p className="lede">
            AEGIS is an AI-assisted security monitoring platform. It ingests application and server logs,
            scores anomalies in real time, and writes analyst-grade incident summaries so your SOC can
            respond in minutes — not hours.
          </p>
          <div className="hero-cta">
            <button className="btn" onClick={() => nav("/login")}>
              Access the SOC console
            </button>
            <a className="ghost" href="#how">
              How detection works
            </a>
          </div>
          <div className="tech">
            {["Python", "React", "FastAPI", "PostgreSQL / SQL", "scikit-learn", "Generative AI", "REST APIs", "Docker"].map(
              (t) => (
                <span className="chip" key={t}>
                  {t}
                </span>
              )
            )}
          </div>
        </div>
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <img src="/threat-map.jpg" alt="Global threat map" style={{ width: "100%", display: "block", minHeight: 280, objectFit: "cover" }} />
          <div style={{ padding: 16 }}>
            <div className="live-flag">
              <span className="pulse" /> LIVE TELEMETRY
            </div>
            <p className="muted small" style={{ marginTop: 8 }}>
              Signature hits, Isolation Forest outliers, and IP reputation fused into a single threat picture.
            </p>
          </div>
        </div>
      </section>

      <div className="feature-row">
        {FEATURES.map(({ icon: Icon, title, body }) => (
          <div className="feature" key={title}>
            <Icon size={18} color="#00e5ff" />
            <h3>{title}</h3>
            <p>{body}</p>
          </div>
        ))}
      </div>

      <section className="section" id="how">
        <div className="kicker">Pipeline</div>
        <h2>From raw logs to a decision.</h2>
        <p className="muted" style={{ maxWidth: 640 }}>
          Built for portfolio-grade demonstration of a full SOC workflow: ingest, detect, classify, summarize, alert, report.
        </p>
        <div className="how">
          {[
            ["01", "Ingest", "Upload files or paste combined / JSON / syslog. Parsers normalize to a common schema."],
            ["02", "Detect", "Regex signatures + Isolation Forest + burst clustering (brute force, scans, exfil)."],
            ["03", "Classify", "Severity, error class, MITRE ATT&CK, IP reputation, geo, and role-aware views."],
            ["04", "Respond", "AI narrative, recommended actions, status workflow, CSV/JSON exportable reports."],
          ].map(([n, t, b]) => (
            <div className="step" key={n}>
              <div className="n">{n}</div>
              <h3 style={{ margin: "8px 0" }}>{t}</h3>
              <p className="muted small">{b}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="section">
        <div className="grid split">
          <div className="card">
            <Lock size={18} color="#3dffc6" />
            <h3 style={{ margin: "10px 0", textTransform: "none", letterSpacing: "-0.03em", fontFamily: "Syne, sans-serif", color: "var(--text)", fontSize: 22 }}>
              Authentication & RBAC
            </h3>
            <p className="muted">
              JWT sessions with admin, analyst, and viewer roles. Viewers are read-only; analysts ingest and triage;
              admins manage identities.
            </p>
          </div>
          <div className="card">
            <Shield size={18} color="#00e5ff" />
            <h3 style={{ margin: "10px 0", textTransform: "none", letterSpacing: "-0.03em", fontFamily: "Syne, sans-serif", color: "var(--text)", fontSize: 22 }}>
              Historical incident analysis
            </h3>
            <p className="muted">
              Seven days of seeded production-like telemetry — SSH guessing from TOR, SQLi campaigns, XSS, recon,
              command injection, and a ransomware-precursor file sweep.
            </p>
          </div>
        </div>
      </section>

      <footer className="footer-pub">
        <span>AEGIS · AI Cybersecurity Log Analyzer</span>
        <span>Demo environment · synthetic telemetry</span>
      </footer>
    </div>
  );
}
