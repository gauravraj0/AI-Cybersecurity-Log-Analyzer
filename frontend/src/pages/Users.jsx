import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../AuthContext.jsx";
import { api } from "../api.js";

export default function Users() {
  const { user, notify } = useAuth();
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({
    username: "",
    full_name: "",
    email: "",
    password: "",
    role: "analyst",
    department: "SOC",
  });

  async function load() {
    const d = await api("/api/users");
    setItems(d.items);
  }

  useEffect(() => {
    if (user.role === "admin") load().catch(() => {});
  }, [user.role]);

  if (user.role !== "admin") return <Navigate to="/console" replace />;

  async function create(e) {
    e.preventDefault();
    try {
      await api("/api/users", { method: "POST", body: form });
      notify("User created", "ok");
      setForm({ username: "", full_name: "", email: "", password: "", role: "analyst", department: "SOC" });
      load();
    } catch (err) {
      notify(err.message, "bad");
    }
  }

  async function toggle(u) {
    await api(`/api/users/${u.id}`, { method: "PATCH", body: { is_active: !u.is_active } });
    load();
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">Authentication & RBAC</div>
          <h1 style={{ fontSize: 32, marginTop: 6 }}>Access control</h1>
          <p>Admin, analyst, and viewer. Only admins can mint identities.</p>
        </div>
      </div>
      <div className="grid two">
        <div className="card" style={{ padding: 0 }}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {items.map((u) => (
                  <tr key={u.id}>
                    <td>
                      {u.full_name}
                      <div className="small muted">
                        {u.username} · {u.department}
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${u.role}`}>{u.role}</span>
                    </td>
                    <td>{u.is_active ? "active" : "disabled"}</td>
                    <td>
                      <button className="ghost" onClick={() => toggle(u)}>
                        {u.is_active ? "Disable" : "Enable"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <form className="card" onSubmit={create}>
          <h3>Create identity</h3>
          {["username", "full_name", "email", "password", "department"].map((k) => (
            <input
              key={k}
              className="field"
              style={{ width: "100%", marginTop: 10 }}
              placeholder={k.replace("_", " ")}
              type={k === "password" ? "password" : "text"}
              value={form[k]}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })}
              required
            />
          ))}
          <select className="field" style={{ width: "100%", marginTop: 10 }} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option>admin</option>
            <option>analyst</option>
            <option>viewer</option>
          </select>
          <button className="btn" style={{ marginTop: 14 }}>
            Create user
          </button>
        </form>
      </div>
    </>
  );
}
