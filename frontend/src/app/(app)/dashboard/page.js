"use client";

import Link from "next/link";
import { useSentinelApp } from "../../_components/AppShell";
import ReportsTable from "../../_components/ReportsTable";
import StatCard from "../../_components/StatCard";

export default function DashboardPage() {
  const { jobs, stats } = useSentinelApp();

  return (
    <>
      <div className="workspace-header">
        <div>
          <span className="eyebrow">Command Center</span>
          <h1>Analyst Dashboard</h1>
          <p>
            Watch analysis throughput, resume recent investigations, and send
            new suspicious files into the pipeline.
          </p>
        </div>
        <Link className="primary-button" href="/analyze">
          Analyze file
        </Link>
      </div>

      <section className="stats-grid">
        <StatCard label="Total analyses" value={stats.total} />
        <StatCard label="Completed" value={stats.completed} />
        <StatCard label="Running" value={stats.running} />
        <StatCard label="Malicious" value={stats.malicious} />
      </section>

      <section className="content-grid two">
        <article className="card">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Recent</span>
              <h2>Latest reports</h2>
            </div>
            <Link className="ghost-button" href="/reports">
              View all
            </Link>
          </div>
          <ReportsTable jobs={jobs} limit={5} />
        </article>

        <article className="card">
          <span className="eyebrow">Workflow</span>
          <h2>Next best action</h2>
          <p>
            Use this workspace as a triage bench: submit unknown files, review
            extracted indicators, compare related samples, then save analyst
            feedback so future scoring can improve.
          </p>
          <div className="action-stack">
            <Link className="secondary-button" href="/analyze">
              Submit a sample
            </Link>
            <Link className="ghost-button" href="/reports">
              Review report history
            </Link>
          </div>
        </article>
      </section>
    </>
  );
}
