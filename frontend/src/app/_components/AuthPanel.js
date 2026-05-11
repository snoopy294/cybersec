"use client";

import { useState } from "react";
import axios from "axios";
import { API_BASE } from "../_lib/constants";

export default function AuthPanel({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ email: "", name: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const endpoint = mode === "register" ? "/auth/register" : "/auth/login";
      const payload =
        mode === "register"
          ? { email: form.email, password: form.password, tenant_name: form.name }
          : { email: form.email, password: form.password };
      const response = await axios.post(`${API_BASE}${endpoint}`, payload);
      const token = response.data.access_token;
      const profile = await axios.get(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      onAuthenticated({
        token,
        user: {
          id: profile.data.user_id,
          email: profile.data.email,
          name: profile.data.email,
          role: profile.data.role,
        },
        tenant: {
          id: profile.data.tenant_id,
          name: profile.data.tenant_name,
          tier: profile.data.tenant_tier,
        },
      });
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-copy">
        <span className="eyebrow">Sentinel Alpha</span>
        <h1>Analyze suspicious files without losing the investigation thread.</h1>
        <p>
          Upload a sample, track the analysis job, review extracted indicators,
          compare similar submissions, and promote useful findings into local
          detection rules.
        </p>
        <div className="auth-metrics">
          <div>
            <strong>Static + dynamic</strong>
            <span>Layered file assessment</span>
          </div>
          <div>
            <strong>IOC focused</strong>
            <span>Domains, URLs, IPs, hashes</span>
          </div>
          <div>
            <strong>Analyst feedback</strong>
            <span>Rule tuning loop</span>
          </div>
        </div>
      </section>

      <section className="auth-card">
        <div className="auth-tabs">
          <button
            className={mode === "login" ? "active" : ""}
            onClick={() => setMode("login")}
            type="button"
          >
            Sign in
          </button>
          <button
            className={mode === "register" ? "active" : ""}
            onClick={() => setMode("register")}
            type="button"
          >
            Create account
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {mode === "register" ? (
            <label>
              Name
              <input
                value={form.name}
                onChange={(event) =>
                  setForm((current) => ({ ...current, name: event.target.value }))
                }
                placeholder="Analyst name"
                required
              />
            </label>
          ) : null}

          <label>
            Email
            <input
              type="email"
              value={form.email}
              onChange={(event) =>
                setForm((current) => ({ ...current, email: event.target.value }))
              }
              placeholder="analyst@example.com"
              required
            />
          </label>

          <label>
            Password
            <input
              type="password"
              value={form.password}
              onChange={(event) =>
                setForm((current) => ({ ...current, password: event.target.value }))
              }
              placeholder="Minimum 12 characters"
              required
            />
          </label>

          {error ? <p className="form-error">{error}</p> : null}

          <button className="primary-button full" disabled={loading} type="submit">
            {loading
              ? "Working..."
              : mode === "register"
                ? "Create workspace"
                : "Enter workspace"}
          </button>
        </form>
      </section>
    </main>
  );
}
