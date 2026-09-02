import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./AuthContext.jsx";
import Layout from "./components/Layout.jsx";
import Landing from "./pages/Landing.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import LiveMonitor from "./pages/LiveMonitor.jsx";
import Incidents from "./pages/Incidents.jsx";
import IncidentDetail from "./pages/IncidentDetail.jsx";
import ThreatIntel from "./pages/ThreatIntel.jsx";
import Anomalies from "./pages/Anomalies.jsx";
import Ingest from "./pages/Ingest.jsx";
import Reports from "./pages/Reports.jsx";
import Users from "./pages/Users.jsx";

function Guard({ children }) {
  const { user, ready } = useAuth();
  if (!ready) return <div className="empty">Initializing secure session…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <Guard>
            <Layout />
          </Guard>
        }
      >
        <Route path="/console" element={<Dashboard />} />
        <Route path="/monitor" element={<LiveMonitor />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/intel" element={<ThreatIntel />} />
        <Route path="/anomalies" element={<Anomalies />} />
        <Route path="/ingest" element={<Ingest />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/users" element={<Users />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
