import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login, setSession } from '../api.js';

export default function Login() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      const res = await login(username, password);
      setSession(res.access_token, { username: res.username, role: res.role });
      nav('/', { replace: true });
      window.location.reload();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h2>🛡️ SentinelLens</h2>
        <div className="tagline">AI Cybersecurity Log Analyzer — sign in to the SOC console</div>
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <div className="error-msg">{error}</div>}
        <button className="primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <div className="demo-hint">
          Demo accounts (RBAC):<br />
          <code>admin / admin123</code> · <code>analyst / analyst123</code> · <code>viewer / viewer123</code>
        </div>
      </form>
    </div>
  );
}
