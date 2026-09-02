import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { api, getToken, setToken } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setReady(true);
      return;
    }
    api("/api/auth/me")
      .then(setUser)
      .catch(() => setToken(null))
      .finally(() => setReady(true));
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3800);
    return () => clearTimeout(t);
  }, [toast]);

  const value = useMemo(
    () => ({
      user,
      ready,
      toast,
      notify: (message, tone = "info") => setToast({ message, tone }),
      login: async (username, password) => {
        const data = await api("/api/auth/login", { method: "POST", body: { username, password } });
        setToken(data.token);
        setUser(data.user);
        return data.user;
      },
      logout: () => {
        setToken(null);
        setUser(null);
      },
    }),
    [user, ready, toast]
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
      {toast && <div className={`toast ${toast.tone}`}>{toast.message}</div>}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
