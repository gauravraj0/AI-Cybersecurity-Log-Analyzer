import React from 'react';

export function SevBadge({ severity }) {
  const s = (severity || 'info').toLowerCase();
  return <span className={`badge ${s}`}>{severity}</span>;
}

export function Kpi({ label, value, accent, sub }) {
  return (
    <div className={`kpi ${accent || ''}`}>
      <div className="num">{value}</div>
      <div className="lbl">{label}</div>
      {sub && <div className="lbl" style={{ color: 'var(--text)', opacity: .8 }}>{sub}</div>}
    </div>
  );
}

export function pct(n) { return `${(n * 100).toFixed(1)}%`; }
export function fmtBytes(b) {
  if (b == null) return '—';
  if (b > 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b > 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
}
export function fmtTime(ts) {
  if (!ts) return '—';
  return String(ts).replace('T', ' ').replace('Z', '').slice(0, 19);
}
export function fmtType(t) {
  return (t || '').replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
