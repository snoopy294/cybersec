"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { reportHashFromUrl, formatDate, formatSize } from "../_lib/constants";
import { StatusBadge } from "./Badges";

export default function ReportsTable({ jobs, limit, showHash = false }) {
  const router = useRouter();
  const visibleJobs = typeof limit === "number" ? jobs.slice(0, limit) : jobs;

  if (!visibleJobs.length) {
    return (
      <div className="empty-state">
        <h3>No analysis jobs yet</h3>
        <p>Submit a sample to start building report history.</p>
        <Link className="primary-button" href="/analyze">
          Analyze a file
        </Link>
      </div>
    );
  }

  return (
    <table>
      <thead>
        <tr>
          <th>File</th>
          <th>Status</th>
          <th>Size</th>
          <th>Submitted</th>
          {showHash ? <th>Hash</th> : null}
        </tr>
      </thead>
      <tbody>
        {visibleJobs.map((job) => {
          const hash = reportHashFromUrl(job.report_url);
          const status = String(job.status || "").toLowerCase();
          const canOpen = status === "completed" && hash;
          const filename = job.filename || job.file_name || "Unknown file";
          const jobId = job.job_id || job.id;
          const fileSize = job.file_size ?? job.file_size_bytes;
          const submittedAt = job.submitted_at || job.created_at;

          return (
            <tr
              className={canOpen ? "clickable-row" : ""}
              key={jobId}
              onClick={() => {
                if (canOpen) {
                  router.push(`/reports/${hash}`);
                }
              }}
            >
              <td>
                <strong>{filename}</strong>
                <span>{jobId}</span>
              </td>
              <td>
                <StatusBadge status={status} />
              </td>
              <td>{formatSize(fileSize)}</td>
              <td>{formatDate(submittedAt)}</td>
              {showHash ? <td>{hash || "Pending"}</td> : null}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
