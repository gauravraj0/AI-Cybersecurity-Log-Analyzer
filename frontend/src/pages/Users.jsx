import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { fmtTime } from '../components/ui.jsx';

export default function Users() {
  const [users, setUsers] = useState(null);
  const [form, setForm] = useState({ username: '', password: '', email: '', role: 'viewer' });
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  const load = useCallback(() => { api('/api/auth/users').then(setUsers).catch((e) => setErr(e.message)); }, []);
  useEffect(load, [load]);

  async function create(e) {
    e.preventDefault(); setErr(''); setMsg('');
    try {
      await api('/api/auth/users', { method: 'POST', body: form });
      setMsg(`User "${form.username}" created`);
      setForm({ username: '', password: '', email: '', role: 'viewer' });
      load();
    } catch (ex) { setErr(ex.message); }
  }

  async function toggle(u) {
    try { await api(`/api/auth/users/${u.id}/toggle`, { method: 'PATCH' }); load(); }
    catch (ex) { setErr(ex.message); }
  }

  return (
    <div className="grid two-col">
      <div className="panel">
        <h3>Users & role-based access</h3>
        <table className="data">
          <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {!users && <tr><td colSpan={6} className="muted">Loading…</td></tr>}
            {users?.map((u) => (
              <tr key={u.id}>
                <td><b>{u.username}</b></td>
                <td className="muted">{u.email || '—'}</td>
                <td><span className="role-chip">{u.role}</span></td>
                <td>{u.is_active ? <span className="badge ok">active</span> : <span className="badge critical">disabled</span>}</td>
                <td className="mono muted">{fmtTime(u.created_at).slice(0, 10)}</td>
                <td><button className="btn-sm" onClick={() => toggle(u)}>{u.is_active ? 'Disable' : 'Enable'}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {msg && <div className="badge ok" style={{ marginTop: 10 }}>{msg}</div>}
        {err && <div className="error-msg" style={{ marginTop: 10 }}>{err}</div>}
      </div>

      <div className="panel">
        <h3>Create user</h3>
        <form onSubmit={create}>
          <label style={{ display: 'block', fontSize: 12, color: 'var(--muted)', margin: '10px 0 4px' }}>Username</label>
          <input style={{ width: '100%' }} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required minLength={3} />
          <label style={{ display: 'block', fontSize: 12, color: 'var(--muted)', margin: '10px 0 4px' }}>Password</label>
          <input style={{ width: '100%' }} type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={6} />
          <label style={{ display: 'block', fontSize: 12, color: 'var(--muted)', margin: '10px 0 4px' }}>Email</label>
          <input style={{ width: '100%' }} value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <label style={{ display: 'block', fontSize: 12, color: 'var(--muted)', margin: '10px 0 4px' }}>Role</label>
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="viewer">viewer — read-only dashboards</option>
            <option value="analyst">analyst — ingest, resolve, export</option>
            <option value="admin">admin — full control incl. users</option>
          </select>
          <button className="primary" style={{ marginTop: 16, width: '100%' }}>Create user</button>
        </form>
      </div>
    </div>
  );
}
