"use client";

import { useState } from "react";
import axios from "axios";
import { API_BASE, API_TIMEOUT_MS, apiErrorMessage, passwordProblems } from "../_lib/constants";

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export default function AuthPanel({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ email: "", name: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const validate = () => {
    const email = form.email.trim();
    if (!EMAIL_RE.test(email)) {
      return "Enter a valid email address.";
    }
    if (mode === "register") {
      if (!form.name.trim()) {
        return "Enter your name.";
      }
      const problems = passwordProblems(form.password);
      if (problems.length) {
        return `Password needs ${problems.join(", ")}.`;
      }
    } else if (!form.password) {
      return "Enter your password.";
    }
    return "";
  };

  const switchMode = (nextMode) => {
    setMode(nextMode);
    setError("");
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (loading) {
      return;
    }

    const problem = validate();
    setError(problem);
    if (problem) {
      return;
    }
    setLoading(true);

    try {
      const endpoint = mode === "register" ? "/auth/register" : "/auth/login";
      const payload =
        mode === "register"
          ? { email: form.email.trim(), password: form.password, tenant_name: form.name.trim() }
          : { email: form.email.trim(), password: form.password };
      const response = await axios.post(`${API_BASE}${endpoint}`, payload, {
        timeout: API_TIMEOUT_MS,
      });
      const token = response.data.access_token;
      const profile = await axios.get(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: API_TIMEOUT_MS,
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
      setError(
        apiErrorMessage(err, mode === "register" ? "Could not create the account." : "Could not sign in."),
      );
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
            onClick={() => switchMode("login")}
            type="button"
          >
            Sign in
          </button>
          <button
            className={mode === "register" ? "active" : ""}
            onClick={() => switchMode("register")}
            type="button"
          >
            Create account
          </button>
        </div>

        <form noValidate onSubmit={handleSubmit}>
          {mode === "register" ? (
            <label>
              Name
              <input
                autoComplete="name"
                maxLength={100}
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
              autoComplete="email"
              maxLength={320}
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
              autoComplete={mode === "register" ? "new-password" : "current-password"}
              maxLength={128}
              type="password"
              value={form.password}
              onChange={(event) =>
                setForm((current) => ({ ...current, password: event.target.value }))
              }
              placeholder="Minimum 12 characters"
              required
            />
          </label>

          {mode === "register" ? (
            <p className="muted">
              12+ characters, using at least three of: lowercase, uppercase, number, symbol.
            </p>
          ) : null}

          {error ? <p className="form-error" role="alert">{error}</p> : null}

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
