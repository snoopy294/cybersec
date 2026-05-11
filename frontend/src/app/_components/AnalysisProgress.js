"use client";

import { useEffect, useState } from "react";
import { StatusBadge } from "./Badges";

const progressByStatus = {
  ingesting: 10,
  queued: 20,
  analyzing: 60,
  cortex_reasoning: 80,
  completed: 100,
  failed: 100,
};

export default function AnalysisProgress({
  apiClient,
  jobId,
  onAuthExpired,
  onComplete,
}) {
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!jobId) {
      return undefined;
    }

    let active = true;

    const poll = async () => {
      try {
        const response = await apiClient.get("/jobs");
        const jobs = Array.isArray(response.data) ? response.data : response.data?.jobs || [];
        const current = jobs.find((item) => item.job_id === jobId);

        if (!active) {
          return;
        }

        if (!current) {
          setError("Job not found");
          return;
        }

        setJob(current);

        const status = String(current.status || "").toLowerCase();
        if (status === "completed" && current.report_url) {
          onComplete(current);
        } else if (status === "failed") {
          setError(current.error || current.error_message || "Analysis failed");
        }
      } catch (err) {
        if (err.response?.status === 401) {
          onAuthExpired();
        } else {
          setError("Unable to load job status");
        }
      }
    };

    poll();
    const interval = window.setInterval(poll, 2500);

    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [apiClient, jobId, onAuthExpired, onComplete]);

  const status = String(job?.status || "queued").toLowerCase();
  const progress = progressByStatus[status] || 10;

  return (
    <div className="progress-card">
      <div className="progress-header">
        <div>
          <span className="eyebrow">Analysis job</span>
          <h3>{job?.filename || "Preparing sample"}</h3>
        </div>
        <StatusBadge status={status} />
      </div>
      <div className="progress-bar">
        <span style={{ width: `${progress}%` }} />
      </div>
      <p>
        {status === "completed"
          ? "Report ready. Redirecting..."
          : status === "failed"
            ? "Review the error and submit a new sample if needed."
            : "Static triage and behavioral enrichment are in progress."}
      </p>
      {error ? <p className="form-error">{error}</p> : null}
    </div>
  );
}
