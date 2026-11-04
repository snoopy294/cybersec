"use client";

import { useEffect, useRef, useState } from "react";
import { StatusBadge } from "./Badges";
import { apiErrorMessage } from "../_lib/constants";

const progressByStatus = {
  ingesting: 10,
  queued: 20,
  analyzing: 60,
  cortex_reasoning: 80,
  completed: 100,
  failed: 100,
};

const POLL_MS = 2500;
const MAX_POLL_MS = 30_000;
const GIVE_UP_AFTER_MS = 10 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default function AnalysisProgress({
  apiClient,
  jobId,
  onComplete,
}) {
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");
  // Keep the latest callback without restarting the poll loop when it changes.
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  useEffect(() => {
    if (!jobId) {
      return undefined;
    }

    if (!UUID_RE.test(jobId)) {
      setError("That job link is invalid. Submit the file again.");
      return undefined;
    }

    let active = true;
    let timer = null;
    let delay = POLL_MS;
    const startedAt = Date.now();
    setJob(null);
    setError("");

    const schedule = () => {
      if (!active) {
        return;
      }
      if (Date.now() - startedAt > GIVE_UP_AFTER_MS) {
        setError("This analysis is taking longer than expected. Check Reports later for the result.");
        return;
      }
      timer = window.setTimeout(poll, delay);
    };

    const poll = async () => {
      try {
        const response = await apiClient.get(`/analyze/${jobId}`);
        if (!active) {
          return;
        }

        const current = response.data;
        setJob(current);
        setError("");
        delay = POLL_MS;

        const status = String(current.status || "").toLowerCase();
        if (status === "completed" && current.report_url) {
          onCompleteRef.current?.(current);
          return;
        }
        if (status === "failed") {
          setError(current.error_message || "Analysis failed.");
          return;
        }
        schedule();
      } catch (err) {
        if (!active) {
          return;
        }
        const httpStatus = err.response?.status;
        if (httpStatus === 401) {
          return; // AppShell signs the person out.
        }
        if (httpStatus === 404 || httpStatus === 422) {
          setError("This analysis job no longer exists. Submit the file again.");
          return;
        }
        setError(`${apiErrorMessage(err, "Unable to load job status.")} Retrying...`);
        delay = Math.min(delay * 2, MAX_POLL_MS);
        schedule();
      }
    };

    poll();

    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [apiClient, jobId]);

  const status = String(job?.status || "queued").toLowerCase();
  const progress = progressByStatus[status] || 10;

  return (
    <div className="progress-card">
      <div className="progress-header">
        <div>
          <span className="eyebrow">Analysis job</span>
          <h3>{job?.file_name || "Preparing sample"}</h3>
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
      {error ? <p className="form-error" role="alert">{error}</p> : null}
    </div>
  );
}
