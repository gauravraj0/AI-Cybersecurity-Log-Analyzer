import React, { useState } from 'react';
import { HashRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { getUser, clearSession } from './api.js';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import LiveLogs from './pages/LiveLogs.jsx';
import LogsExplorer from './pages/LogsExplorer.jsx';
import Incidents from './pages/Incidents.jsx';
import Alerts from './pages/Alerts.jsx';
import IpAnalysis from './pages/IpAnalysis.jsx';
import Reports from './pages/Reports.jsx';
import Users from './pages/Users.jsx';

const NAV = [
  { to: '/', label: 'Dashboard', icon: '📊', end: true },
  { to: '/live', label: 'Live Monitor', icon: '📡' },
  { to: '/logs', label: 'Log Explorer', icon: '🗂️' },
  { to: '/incidents', label: 'Incidents', icon: '🚨' },
  { to: '/alerts', label: 'Alerts', icon: '🔔' },
  { to: '/ips', label: 'IP Analysis', icon: '🌐' },
  { to: '/reports', label: 'Reports', icon: '📄' },
];

function Shell({ children }) {
  const user = getUser();
  const nav = [...NAV];
  if (user?.role === 'admin') nav.push({ to: '/users', label: 'Users', icon: '👤' });
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="logo">🛡️</span>
          <div>
            <div className="title">SentinelLens</div>
            <div className="sub">AI SOC Platform</div>
          </div>
        </div>
        <nav className="nav">
          {nav.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => (isActive ? 'active' : '')}>
              <span>{n.icon}</span> {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="foot">SentinelLens v1.0<br />FastAPI · React · ML · GenAI</div>
      </aside>
      <div className="main">
        <header className="topbar">
          <h1>AI Cybersecurity Log Analyzer</h1>
          <div className="who">
            <span className="role-chip">{user?.role}</span>
            <span>{user?.username}</span>
            <button className="btn-sm ghost" onClick={() => { clearSession(); window.location.hash = '#/login'; window.location.reload(); }}>
              Sign out
            </button>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}

function Protected({ children }) {
  return getTokenOrRedirect() ? <Shell>{children}</Shell> : <Navigate to="/login" replace />;
}

function getTokenOrRedirect() {
  const token = localStorage.getItem('sentinel_token');
  return token && getUser();
}

export default function App() {
  const logged = !!getTokenOrRedirect();
  return (
    <HashRouter>
      <Routes>
        <Route path="/login" element={logged ? <Navigate to="/" replace /> : <Login />} />
        <Route path="/" element={<Protected><Dashboard /></Protected>} />
        <Route path="/live" element={<Protected><LiveLogs /></Protected>} />
        <Route path="/logs" element={<Protected><LogsExplorer /></Protected>} />
        <Route path="/incidents" element={<Protected><Incidents /></Protected>} />
        <Route path="/alerts" element={<Protected><Alerts /></Protected>} />
        <Route path="/ips" element={<Protected><IpAnalysis /></Protected>} />
        <Route path="/reports" element={<Protected><Reports /></Protected>} />
        <Route path="/users" element={<Protected><Users /></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </HashRouter>
  );
}
