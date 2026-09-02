const TOKEN_KEY = 'sentinel_token';
const USER_KEY = 'sentinel_user';

export function getToken() { return localStorage.getItem(TOKEN_KEY); }
export function getUser() {
  try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch { return null; }
}
export function setSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}
export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export async function api(path, { method = 'GET', body, raw = false } = {}) {
  const headers = { Authorization: `Bearer ${getToken() || ''}` };
  if (body && !(body instanceof Blob) && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, { method, headers, body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined });
  if (res.status === 401) {
    clearSession();
    window.location.hash = '#/login';
    window.location.reload();
    throw new ApiError(401, 'Session expired');
  }
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try { detail = (await res.json()).detail || detail; } catch { /* noop */ }
    throw new ApiError(res.status, typeof detail === 'string' ? detail : JSON.stringify(detail));
  }
  return raw ? await res.blob() : await res.json();
}

export function login(username, password) {
  const form = new URLSearchParams({ username, password });
  return fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  }).then(async (res) => {
    if (!res.ok) {
      const detail = await res.json().catch(() => ({}));
      throw new ApiError(res.status, detail.detail || 'Login failed');
    }
    return res.json();
  });
}

/** Open an authenticated export as a download. */
export async function downloadFile(path, filename) {
  const blob = await api(path, { raw: true });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

/** Open an authenticated HTML report in a new tab. */
export async function openReport(path) {
  const blob = await api(path, { raw: true });
  const url = URL.createObjectURL(new Blob([blob], { type: 'text/html' }));
  window.open(url, '_blank');
}

export function wsUrl() {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}/ws?token=${encodeURIComponent(getToken() || '')}`;
}
