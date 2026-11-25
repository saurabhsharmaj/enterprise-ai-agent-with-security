import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { initAuth, keycloak, login, logout } from "./keycloak";
import { api } from "../services/api";

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ ready: false, authenticated: false, me: null, error: null });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const authenticated = await initAuth();
        if (!alive) return;
        if (!authenticated) return setState({ ready: true, authenticated: false, me: null, error: null });
        const me = await api.me(); // identity as the BACKEND sees it (validated token + database)
        if (alive) setState({ ready: true, authenticated: true, me, error: null });
      } catch (e) {
        if (alive) setState({ ready: true, authenticated: !!keycloak.authenticated, me: null, error: e });
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const value = useMemo(
    () => ({
      ...state,
      login,
      logout,
      // UI hint ONLY: hides links the user could not use anyway. The backend re-authorizes every request.
      can: (permission) => !!state.me?.permissions?.includes(permission),
    }),
    [state]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
