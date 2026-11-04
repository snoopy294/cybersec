"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useSentinelApp } from "../../_components/AppShell";
import ReportsTable from "../../_components/ReportsTable";
import { ACTIVE_STATUSES } from "../../_lib/constants";

const filters = ["all", "queued", "running", "completed", "failed"];

// The API returns uppercase statuses; "running" covers every in-progress stage.
function matchesFilter(job, filter) {
  const status = String(job.status || "").toLowerCase();
  if (filter === "running") {
    return ACTIVE_STATUSES.includes(status) && status !== "queued";
  }
  return status === filter;
}

export default function ReportsPage() {
  const { jobs } = useSentinelApp();
  const [filter, setFilter] = useState("all");

  const filteredJobs = useMemo(() => {
    if (filter === "all") {
      return jobs;
    }

    return jobs.filter((job) => matchesFilter(job, filter));
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
