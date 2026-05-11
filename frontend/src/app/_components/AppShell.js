"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import axios from "axios";
import AuthPanel from "./AuthPanel";
import { API_BASE, SESSION_KEY } from "../_lib/constants";

const SentinelAppContext = createContext(null);

const navItems = [
  { href: "/dashboard", label: "Command Center", marker: "D" },
  { href: "/analyze", label: "Analyze File", marker: "A" },
  { href: "/reports", label: "Reports", marker: "R" },
  { href: "/settings", label: "Settings", marker: "S" },
];

function normalizeStoredSession(value) {
  const token = value?.token || value?.access_token;
  if (!token) {
    return null;
  }

  return {
    token,
    user: value.user || {
      id: value.user_id,
      email: value.email || "Analyst",
      name: value.email || "Analyst",
    },
    tenant: value.tenant || {
      id: value.tenant_id,
      name: value.tenant_name,
      tier: value.tenant_tier,
    },
  };
}

function statusValue(status) {
  return String(status || "").toLowerCase();
}

export function useSentinelApp() {
  const context = useContext(SentinelAppContext);

  if (!context) {
    throw new Error("useSentinelApp must be used inside AppShell");
  }

  return context;
}

export default function AppShell({ children }) {
  const router = useRouter();
  const pathname = usePathname();
  const [session, setSession] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [jobs, setJobs] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    completed: 0,
    running: 0,
    malicious: 0,
  });

  useEffect(() => {
    const stored = localStorage.getItem(SESSION_KEY);

    if (stored) {
      try {
        const normalized = normalizeStoredSession(JSON.parse(stored));
        if (normalized) {
          setSession(normalized);
        } else {
          localStorage.removeItem(SESSION_KEY);
        }
      } catch {
        localStorage.removeItem(SESSION_KEY);
      }
    }

    setAuthReady(true);
  }, []);

  const apiClient = useMemo(() => {
    const client = axios.create({
      baseURL: API_BASE,
      headers: session?.token
        ? { Authorization: `Bearer ${session.token}` }
        : undefined,
    });

    return client;
  }, [session]);

  const handleAuthExpired = useCallback(() => {
    localStorage.removeItem(SESSION_KEY);
    setSession(null);
    setJobs([]);
    setStats({ total: 0, completed: 0, running: 0, malicious: 0 });
  }, []);

  const loadJobs = useCallback(async () => {
    if (!session?.token) {
      return;
    }

    try {
      const response = await apiClient.get("/jobs");
      const nextJobs = Array.isArray(response.data)
        ? response.data
        : response.data?.jobs || [];
      setJobs(nextJobs);
      setStats({
        total: nextJobs.length,
        completed: nextJobs.filter((job) => statusValue(job.status) === "completed").length,
        running: nextJobs.filter((job) =>
          ["ingesting", "queued", "analyzing", "cortex_reasoning"].includes(statusValue(job.status)),
        ).length,
        malicious: nextJobs.filter((job) => statusValue(job.verdict) === "malicious").length,
      });
    } catch (error) {
      if (error.response?.status === 401) {
        handleAuthExpired();
      }
    }
  }, [apiClient, handleAuthExpired, session]);

  useEffect(() => {
    if (session?.token) {
      loadJobs();
    }
  }, [loadJobs, session]);

  const handleAuthenticated = useCallback(
    (profile) => {
      const normalized = normalizeStoredSession(profile);
      localStorage.setItem(SESSION_KEY, JSON.stringify(normalized));
      setSession(normalized);
      router.replace("/dashboard");
    },
    [router],
  );

  const handleLogout = useCallback(() => {
    handleAuthExpired();
    router.replace("/dashboard");
  }, [handleAuthExpired, router]);

  const contextValue = useMemo(
    () => ({
      apiClient,
      jobs,
      loadJobs,
      onAuthExpired: handleAuthExpired,
      session,
      stats,
    }),
    [apiClient, handleAuthExpired, jobs, loadJobs, session, stats],
  );

  if (!authReady) {
    return (
      <main className="loading-page">
        <div className="pulse-ring" />
        <p>Starting workspace...</p>
      </main>
    );
  }

  if (!session) {
    return <AuthPanel onAuthenticated={handleAuthenticated} />;
  }

  return (
    <SentinelAppContext.Provider value={contextValue}>
      <main className="app-shell">
        <aside className="sidebar">
          <div className="brand-lockup">
            <div className="brand-mark">S</div>
            <div>
              <strong>Sentinel</strong>
              <span>Malware Intelligence</span>
            </div>
          </div>

          <nav>
            {navItems.map((item) => {
              const active =
                pathname === item.href || pathname.startsWith(`${item.href}/`);

              return (
                <Link
                  className={`nav-item ${active ? "active" : ""}`}
                  href={item.href}
                  key={item.href}
                >
                  <span>{item.marker}</span>
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="sidebar-footer">
            <span>{session.user?.email || "Analyst"}</span>
            <button className="ghost-button" onClick={handleLogout} type="button">
              Sign out
            </button>
          </div>
        </aside>

        <section className="workspace">{children}</section>
      </main>
    </SentinelAppContext.Provider>
  );
}
