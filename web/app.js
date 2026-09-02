var TOKEN = null;
var USER = null;

function $(id) { return document.getElementById(id); }

function showLanding() {
  $("landing").classList.remove("hidden");
  $("login").classList.add("hidden");
  $("shell").classList.remove("on");
}

function showLogin() {
  $("landing").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("shell").classList.remove("on");
}

function showApp() {
  $("landing").classList.add("hidden");
  $("login").classList.add("hidden");
  $("shell").classList.add("on");
  $("who").textContent = (USER.full_name || USER.username) + " · " + USER.role;
  loadDash();
}

function fill(u, p) {
  $("user").value = u;
  $("pass").value = p;
}

function api(path, opts) {
  opts = opts || {};
  var headers = opts.headers || {};
  if (!opts.raw) headers["Content-Type"] = "application/json";
  if (TOKEN) headers.Authorization = "Bearer " + TOKEN;
  return fetch(path, {
    method: opts.method || "GET",
    headers: headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  }).then(function (res) {
    if (opts.blob) return res.blob();
    return res.text().then(function (t) {
      var data = t ? JSON.parse(t) : null;
      if (!res.ok) throw new Error((data && data.detail) || res.statusText);
      return data;
    });
  });
}

function doLogin(e) {
  e.preventDefault();
  $("login-err").textContent = "";
  api("/api/auth/login", {
    method: "POST",
    body: { username: $("user").value, password: $("pass").value }
  }).then(function (data) {
    TOKEN = data.token;
    USER = data.user;
    try { localStorage.setItem("aegis_token", TOKEN); } catch (err) {}
    showApp();
  }).catch(function (err) {
    $("login-err").textContent = err.message || "Login failed";
  });
  return false;
}

function logout() {
  TOKEN = null;
  USER = null;
  try { localStorage.removeItem("aegis_token"); } catch (err) {}
  showLanding();
}

function tab(name, btn) {
  ["dash", "logs", "inc", "intel", "ingest", "reports"].forEach(function (n) {
    $("tab-" + n).classList.toggle("hidden", n !== name);
  });
  document.querySelectorAll(".nav-btn").forEach(function (b) { b.classList.remove("on"); });
  if (btn) btn.classList.add("on");
  if (name === "dash") loadDash();
  if (name === "logs") loadLogs();
  if (name === "inc") loadIncs();
  if (name === "intel") loadIps();
  if (name === "reports") loadReport();
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function loadDash() {
  api("/api/dashboard").then(function (d) {
    var k = d.kpis;
    $("kpis").innerHTML = [
      ["Events (24h)", k.logs_24h],
      ["Anomalies", k.anomalies],
      ["Open incidents", k.open_incidents],
      ["Threat level", k.threat_level]
    ].map(function (x) {
      return '<div class="card"><h3 style="color:var(--muted);font-size:12px;text-transform:uppercase">' + x[0] + '</h3><div class="stat">' + esc(x[1]) + "</div></div>";
    }).join("");
    $("alerts").innerHTML = "<h3>Latest alerts</h3>" + (d.alerts || []).map(function (a) {
      return '<div style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span class="badge ' + esc(a.severity) + '">' + esc(a.severity) + "</span> " + esc(a.title) + '<div class="mono" style="color:var(--muted);margin-top:4px">' + esc(a.message) + "</div></div>";
    }).join("");
  }).catch(function (err) {
    $("kpis").innerHTML = '<div class="err">' + esc(err.message) + "</div>";
  });
}

function loadLogs() {
  api("/api/logs?page_size=40").then(function (d) {
    var rows = (d.items || []).map(function (l) {
      return "<tr><td class='mono'>" + esc((l.timestamp || "").replace("T", " ").slice(0, 19)) + "</td><td>" + esc(l.source) + "</td><td class='badge " + esc(l.severity) + "'>" + esc(l.severity) + "</td><td class='mono'>" + esc(l.ip_address) + "</td><td class='mono'>" + esc(l.message) + "</td></tr>";
    }).join("");
    $("logs").innerHTML = "<table><thead><tr><th>Time</th><th>Src</th><th>Sev</th><th>IP</th><th>Event</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }).catch(function (err) {
    $("logs").textContent = err.message;
  });
}

function loadIncs() {
  api("/api/incidents").then(function (d) {
    $("incs").innerHTML = (d.items || []).map(function (i) {
      return '<article class="card"><span class="badge ' + esc(i.severity) + '">' + esc(i.severity) + '</span> <span class="badge">' + esc(i.status) + "</span><h2 style='font-size:18px;margin:10px 0'>" + esc(i.title) + "</h2><p style='color:var(--muted);font-size:13px;white-space:pre-wrap'>" + esc((i.ai_summary || "").slice(0, 420)) + "</p></article>";
    }).join("");
  }).catch(function (err) {
    $("incs").textContent = err.message;
  });
}

function loadIps() {
  api("/api/ips").then(function (d) {
    var rows = (d.items || []).slice(0, 30).map(function (p) {
      return "<tr><td class='mono'>" + esc(p.ip) + "</td><td>" + esc(p.city) + ", " + esc(p.country) + "</td><td class='badge " + esc(p.threat_level) + "'>" + esc(p.threat_level) + "</td><td>" + esc(p.reputation) + "</td><td>" + esc(p.anomaly_count) + "</td></tr>";
    }).join("");
    $("ips").innerHTML = "<table><thead><tr><th>IP</th><th>Geo</th><th>Level</th><th>Rep</th><th>Anomalies</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }).catch(function (err) {
    $("ips").textContent = err.message;
  });
}

function ingest() {
  $("ingest-out").textContent = "Analyzing…";
  api("/api/logs/ingest", { method: "POST", body: { text: $("ingest-text").value, source: "upload" } })
    .then(function (d) {
      $("ingest-out").textContent = "Ingested " + d.ingested + " events · " + d.anomalies + " anomalies · incidents " + (d.incidents || []).length;
    })
    .catch(function (err) { $("ingest-out").textContent = err.message; });
}

function simulate() {
  $("ingest-out").textContent = "Simulating…";
  api("/api/demo/simulate", { method: "POST" })
    .then(function (d) {
      $("ingest-out").textContent = "Simulated " + d.kind + " from " + d.ip + " · " + d.ingested + " events";
    })
    .catch(function (err) { $("ingest-out").textContent = err.message; });
}

function loadReport() {
  api("/api/reports/summary").then(function (d) {
    $("report").innerHTML = "<p>" + esc(d.narrative) + "</p><p style='margin-top:12px;color:var(--muted)'>Logs " + d.logs + " · incidents " + d.incidents + " · open " + d.open + "</p>";
  }).catch(function (err) {
    $("report").textContent = err.message;
  });
}

function exp(fmt) {
  fetch("/api/reports/export?fmt=" + fmt, { headers: { Authorization: "Bearer " + TOKEN } })
    .then(function (r) { return r.blob(); })
    .then(function (blob) {
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "aegis-incidents." + fmt;
      a.click();
    });
}

(function boot() {
  try { TOKEN = localStorage.getItem("aegis_token"); } catch (err) { TOKEN = null; }
  if (!TOKEN) return;
  api("/api/auth/me").then(function (u) {
    USER = u;
    showApp();
  }).catch(function () {
    TOKEN = null;
  });
})();
