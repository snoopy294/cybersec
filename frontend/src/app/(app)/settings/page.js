"use client";

import { useSentinelApp } from "../../_components/AppShell";

export default function SettingsPage() {
  const { session } = useSentinelApp();

  return (
    <>
      <div className="workspace-header">
        <div>
          <span className="eyebrow">Workspace</span>
          <h1>Settings</h1>
          <p>Review the active analyst session and MVP service assumptions.</p>
        </div>
      </div>

      <section className="content-grid two">
        <article className="card">
          <h2>Account</h2>
          <div className="key-value-list">
            <div>
              <span>Name</span>
              <strong>{session.user?.name || "Unknown"}</strong>
            </div>
            <div>
              <span>Email</span>
              <strong>{session.user?.email}</strong>
            </div>
            <div>
              <span>Role</span>
              <strong>MVP analyst</strong>
            </div>
          </div>
        </article>

        <article className="card">
          <h2>Operational notes</h2>
          <p>
            This build now enforces stronger signup passwords, authenticated
            uploads, rate limits, active-job limits, daily upload quotas, and
            retention cleanup for old terminal jobs. Keep uploaded samples in
            private object storage and use isolated malware execution
            infrastructure before opening the service to untrusted users.
          </p>
        </article>
      </section>
    </>
  );
}
