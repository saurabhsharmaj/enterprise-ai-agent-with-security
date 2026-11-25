// Keycloak (OIDC) client: Authorization Code Flow with PKCE (S256). Public client, so there is NO secret here.
// Tokens live only in memory (keycloak-js); nothing is written to localStorage.
import Keycloak from "keycloak-js";

export const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL || "http://localhost:8080",
  realm: import.meta.env.VITE_KEYCLOAK_REALM || "enterprise-ai",
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || "enterprise-ai-frontend",
});

let initPromise = null;

export function initAuth() {
  // Guard against React StrictMode calling init twice (keycloak-js allows a single init).
  if (!initPromise) {
    initPromise = keycloak.init({
      onLoad: "check-sso",
      pkceMethod: "S256",
      checkLoginIframe: false,
      silentCheckSsoRedirectUri: undefined,
    });
  }
  return initPromise;
}

export function login() {
  return keycloak.login({ redirectUri: window.location.origin + "/" });
}

export function logout() {
  // Ends the Keycloak SSO session too (RP-initiated logout), then returns to the login page.
  return keycloak.logout({ redirectUri: window.location.origin + "/" });
}

// Returns a fresh access token, refreshing it when it expires within `minValidity` seconds.
// If the session can no longer be refreshed, the user is sent back to Keycloak to sign in again.
export async function getToken(forceRefresh = false) {
  if (!keycloak.authenticated) throw new Error("not_authenticated");
  try {
    await keycloak.updateToken(forceRefresh ? -1 : 30);
  } catch {
    await login();
    throw new Error("session_expired");
  }
  return keycloak.token;
}
