"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AnalysisProgress from "./AnalysisProgress";
import UploadZone from "./UploadZone";
import { useSentinelApp } from "./AppShell";
import { reportHashFromUrl } from "../_lib/constants";

export default function AnalyzeClient({ initialJobId }) {
  const router = useRouter();
  const { apiClient, loadJobs, onAuthExpired } = useSentinelApp();
  const [uploading, setUploading] = useState(false);
  const [activeJobId, setActiveJobId] = useState(initialJobId || null);
  const [error, setError] = useState("");

  useEffect(() => {
    setActiveJobId(initialJobId || null);
  }, [initialJobId]);

  const handleFileUpload = async (file) => {
    setUploading(true);
    setError("");

    try {
      const data = new FormData();
      data.append("file", file);

      const response = await apiClient.post("/analyze", data, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      const jobId = response.data.job_id;
      setActiveJobId(jobId);
      router.replace(`/analyze?job=${jobId}`);
      loadJobs();
    } catch (err) {
      if (err.response?.status === 401) {
        onAuthExpired();
      } else {
        const detail = err.response?.data?.detail;
        setError(typeof detail === "string" ? detail : "Upload failed");
      }
    } finally {
      setUploading(false);
    }
  };

  const handleComplete = useCallback(
    (job) => {
      loadJobs();
      const hash = reportHashFromUrl(job.report_url);
      if (hash) {
        router.push(`/reports/${hash}`);
      }
    },
    [loadJobs, router],
  );

  return (
    <>
      <div className="workspace-header">
        <div>
          <span className="eyebrow">Submission</span>
          <h1>Analyze File</h1>
          <p>
            Queue one suspicious file, then follow the job until the report is
            ready.
          </p>
        </div>
      </div>

      <section className="content-grid">
        <div className="card wide">
          {activeJobId ? (
            <AnalysisProgress
              apiClient={apiClient}
              jobId={activeJobId}
              onAuthExpired={onAuthExpired}
              onComplete={handleComplete}
            />
          ) : (
            <UploadZone disabled={uploading} onFileSelect={handleFileUpload} />
          )}

          {uploading ? <p className="muted">Uploading sample...</p> : null}
          {error ? <p className="form-error">{error}</p> : null}

          {activeJobId ? (
            <button
              className="ghost-button"
              onClick={() => {
                setActiveJobId(null);
                router.replace("/analyze");
              }}
              type="button"
            >
              Submit another file
            </button>
          ) : null}
        </div>
      </section>
    </>
  );
}
