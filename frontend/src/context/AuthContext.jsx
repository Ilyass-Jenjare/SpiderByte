import { createContext, useContext, useEffect, useMemo, useState } from "react";

const AuthContext = createContext(null);

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const TOKEN_KEY = "spiderbyte_token";
const USER_KEY = "spiderbyte_user";

function readStorage(key) {
  if (typeof window === "undefined") {
    return "";
  }

  const sessionValue = sessionStorage.getItem(key) || "";
  if (sessionValue) {
    return sessionValue;
  }

  // Migrate old persistent values to session storage.
  const localValue = localStorage.getItem(key) || "";
  if (localValue) {
    sessionStorage.setItem(key, localValue);
    localStorage.removeItem(key);
  }
  return localValue;
}

function writeStorage(key, value) {
  if (typeof window === "undefined") {
    return;
  }

  sessionStorage.setItem(key, value);
  localStorage.removeItem(key);
}

function removeStorage(key) {
  if (typeof window === "undefined") {
    return;
  }
  sessionStorage.removeItem(key);
  localStorage.removeItem(key);
}

function safeParseJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function decodeBase64Url(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  return atob(padded);
}

function decodeUserFromToken(token) {
  const payload = decodeTokenPayload(token);
  if (!payload) {
    return null;
  }

  const email = payload.sub || payload.email || "";
  const username = String(email).split("@")[0] || "user";
  return { email, username };
}

function decodeTokenPayload(token) {
  if (!token) {
    return null;
  }

  try {
    const payloadPart = token.split(".")[1];
    if (!payloadPart) {
      return null;
    }
    const payload = safeParseJson(decodeBase64Url(payloadPart), null);
    if (!payload || typeof payload !== "object") {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function tokenExpirationMs(token) {
  const payload = decodeTokenPayload(token);
  const exp = Number(payload?.exp);
  if (!Number.isFinite(exp) || exp <= 0) {
    return 0;
  }
  return exp * 1000;
}

function isTokenExpired(token) {
  const expiration = tokenExpirationMs(token);
  if (!expiration) {
    return false;
  }
  return Date.now() >= expiration;
}

function readValidToken() {
  const storedToken = readStorage(TOKEN_KEY);
  if (!storedToken) {
    return "";
  }

  if (isTokenExpired(storedToken)) {
    removeStorage(TOKEN_KEY);
    removeStorage(USER_KEY);
    return "";
  }

  return storedToken;
}

function normalizeUser(user, fallbackEmail = "") {
  const email = user?.email || fallbackEmail || "";
  const username = user?.username || String(email).split("@")[0] || "user";
  return { email, username };
}

function parseApiError(payload, fallback) {
  if (!payload) {
    return fallback;
  }
  if (typeof payload === "string") {
    return payload;
  }
  if (typeof payload === "object" && payload.detail) {
    return String(payload.detail);
  }
  return fallback;
}

function readResponsePayload(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => readValidToken());
  const [user, setUser] = useState(() => {
    const raw = readStorage(USER_KEY);
    if (raw) {
      return normalizeUser(safeParseJson(raw, {}));
    }
    return normalizeUser(decodeUserFromToken(readValidToken()));
  });
  const [isLoadingAuth, setIsLoadingAuth] = useState(false);

  function setSession(nextToken, nextUser) {
    if (!nextToken || isTokenExpired(nextToken)) {
      logout();
      return;
    }

    const normalizedUser = normalizeUser(nextUser);

    setToken(nextToken);
    setUser(normalizedUser);
    writeStorage(TOKEN_KEY, nextToken);
    writeStorage(USER_KEY, JSON.stringify(normalizedUser));
  }

  async function login({ email, password }) {
    setIsLoadingAuth(true);
    try {
      const body = new URLSearchParams();
      body.set("username", email.trim());
      body.set("password", password);

      const response = await fetch(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        credentials: "include",
        body,
      });

      const payload = await readResponsePayload(response);
      if (!response.ok || typeof payload !== "object" || !payload.access_token) {
        throw new Error(parseApiError(payload, "Login failed"));
      }

      const derivedUser = normalizeUser(decodeUserFromToken(payload.access_token), email);
      setSession(payload.access_token, derivedUser);
      return derivedUser;
    } finally {
      setIsLoadingAuth(false);
    }
  }

  async function signup({ email, password }) {
    setIsLoadingAuth(true);
    try {
      const rawName = email.split("@")[0] || "user";
      const username = rawName.replace(/[^a-zA-Z0-9_-]/g, "") || "user";

      const response = await fetch(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: email.trim(),
          password,
          username,
          fullname: username,
        }),
      });

      const payload = await readResponsePayload(response);
      if (!response.ok) {
        throw new Error(parseApiError(payload, "Registration failed"));
      }
    } finally {
      setIsLoadingAuth(false);
    }

    return login({ email, password });
  }

  function logout() {
    setToken("");
    setUser(null);
    removeStorage(TOKEN_KEY);
    removeStorage(USER_KEY);
  }

  useEffect(() => {
    if (!token) {
      return undefined;
    }

    const expiration = tokenExpirationMs(token);
    if (!expiration) {
      return undefined;
    }

    const remainingMs = expiration - Date.now();
    if (remainingMs <= 0) {
      logout();
      return undefined;
    }

    const timeoutId = setTimeout(() => {
      logout();
    }, remainingMs);

    return () => {
      clearTimeout(timeoutId);
    };
  }, [token]);

  const value = useMemo(
    () => ({
      token,
      user,
      isAuthenticated: Boolean(token),
      isLoadingAuth,
      login,
      signup,
      logout,
    }),
    [token, user, isLoadingAuth],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return context;
}
