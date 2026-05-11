"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useSentinelApp } from "../../_components/AppShell";
import ReportsTable from "../../_components/ReportsTable";

const filters = ["all", "queued", "running", "completed", "failed"];

export default function ReportsPage() {
  const { jobs } = useSentinelApp();
  const [filter, setFilter] = useState("all");

  const filteredJobs = useMemo(() => {
    if (filter === "all") {
      return jobs;
    }

    return jobs.filter((job) => job.status === filter);
  }, [filter, jobs]);

  return (
    <>
      <div className="workspace-header">
        <div>
          <span className="eyebrow">History</span>
          <h1>Reports</h1>
          <p>Open completed analyses or check the state of queued jobs.</p>
        </div>
        <Link className="primary-button" href="/analyze">
          Analyze file
        </Link>
      </div>

      <section className="card wide">
        <div className="report-list-header">
          <div className="report-tabs compact">
            {filters.map((item) => (
              <button
                className={filter === item ? "active" : ""}
                key={item}
                onClick={() => setFilter(item)}
                type="button"
              >
                {item}
              </button>
            ))}
          </div>
          <span className="muted">{filteredJobs.length} shown</span>
        </div>

        <ReportsTable jobs={filteredJobs} showHash />
      </section>
    </>
  );
}
