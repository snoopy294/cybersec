"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSentinelApp } from "./AppShell";
import { VerdictBadge } from "./Badges";

function MarkdownLine({ text }) {
  const html = text
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");

  return <p dangerouslySetInnerHTML={{ __html: html }} />;
}

export default function ReportView({ reportHash }) {
  const router = useRouter();
  const { apiClient, loadJobs, onAuthExpired } = useSentinelApp();
  const [report, setReport] = useState(null);
  const [similar, setSimilar] = useState([]);
  const [detections, setDetections] = useState(null);
  const [activeTab, setActiveTab] = useState("summary");
  const [feedback, setFeedback] = useState({ verdict: "", notes: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [feedbackStatus, setFeedbackStatus] = useState("");

  const loadReport = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const [reportResponse, similarResponse, detectionResponse] =
        await Promise.all([
          apiClient.get(`/report/${reportHash}`),
          apiClient.get(`/report/${reportHash}/similar`),
          apiClient.post(`/report/${reportHash}/detections`),
        ]);

      setReport(reportResponse.data);
      setSimilar(similarResponse.data.similar_reports || similarResponse.data.matches || []);
      setDetections(detectionResponse.data);
      setFeedback({
        verdict: "",
        notes: "",
      });
    } catch (err) {
      if (err.response?.status === 401) {
        onAuthExpired();
      } else {
        const detail = err.response?.data?.detail;
        setError(typeof detail === "string" ? detail : "Unable to load report");
      }
    } finally {
      setLoading(false);
    }
  }, [apiClient, onAuthExpired, reportHash]);

  useEffect(() => {
    loadReport();
  }, [loadReport]);

  const submitFeedback = async () => {
    setFeedbackStatus("");

    try {
      await apiClient.post(`/report/${reportHash}/feedback`, {
        type: "verdict",
        value: feedback.verdict || "reviewed",
        comment: feedback.notes || null,
      });
      setFeedbackStatus("Feedback saved");
      loadReport();
    } catch (err) {
      if (err.response?.status === 401) {
        onAuthExpired();
      } else {
        setFeedbackStatus("Unable to save feedback");
      }
    }
  };

  const refreshReport = async () => {
    setRefreshing(true);
    setError("");

    try {
      const response = await apiClient.post(`/report/${reportHash}/refresh`);
      loadJobs();
      router.push(`/analyze?job=${response.data.job_id}`);
    } catch (err) {
      if (err.response?.status === 401) {
        onAuthExpired();
      } else {
        const detail = err.response?.data?.detail;
        setError(typeof detail === "string" ? detail : "Unable to refresh report");
      }
    } finally {
      setRefreshing(false);
    }
  };

  const indicatorCount = useMemo(() => {
    if (!report?.iocs) {
      return 0;
    }

    return Object.values(report.iocs).reduce(
      (total, values) => total + (Array.isArray(values) ? values.length : 0),
      0,
    );
  }, [report]);

  if (loading) {
    return (
      <div className="report-loader">
        <div className="pulse-ring" />
        <p>Loading report...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="empty-state">
        <h3>Report unavailable</h3>
        <p>{error}</p>
        <Link className="ghost-button" href="/reports">
          Back to reports
        </Link>
      </div>
    );
  }

  if (!report) {
    return null;
  }

  const tabs = ["summary", "indicators", "detections", "feedback"];
  const reportTitle = report.filename || report.file_name || "Threat report";
  const reportHashValue = report.file_hash || report.file_hash_sha256 || reportHash;
  const reportScore = report.score ?? report.severity_score ?? 0;
  const reportSummary =
    report.summary ||
    (report.ai_narrative || "")
      .split("\n")
      .find((line) => line.trim() && !line.trim().startsWith("#")) ||
    "Automated static analysis report is available.";

  return (
    <>
      <div className="workspace-header">
        <div>
          <span className="eyebrow">Report</span>
          <h1>{reportTitle}</h1>
          <p>{reportHashValue}</p>
        </div>
        <div className="header-actions">
          <Link className="ghost-button" href="/reports">
            Back
          </Link>
          <button
            className="secondary-button"
            disabled={refreshing}
            onClick={refreshReport}
            type="button"
          >
            {refreshing ? "Queueing..." : "Refresh analysis"}
          </button>
        </div>
      </div>

      <section className="report-hero">
        <div>
          <VerdictBadge verdict={report.verdict} />
          <h2>Risk score {reportScore}/100</h2>
          <p>{reportSummary}</p>
        </div>
        <div className="report-stats">
          <div>
            <strong>{indicatorCount}</strong>
            <span>Indicators</span>
          </div>
          <div>
            <strong>{similar.length}</strong>
            <span>Similar samples</span>
          </div>
          <div>
            <strong>{detections?.rules?.length || 0}</strong>
            <span>Detection rules</span>
          </div>
        </div>
      </section>

      <div className="report-tabs">
        {tabs.map((tab) => (
          <button
            className={activeTab === tab ? "active" : ""}
            key={tab}
            onClick={() => setActiveTab(tab)}
            type="button"
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === "summary" ? (
        <section className="content-grid two">
          <article className="card">
            <h3>Behavior profile</h3>
            <div className="key-value-list">
              {Object.entries(report.static_data?.behavior_profile || {}).map(
                ([key, value]) => (
                  <div key={key}>
                    <span>{key.replaceAll("_", " ")}</span>
                    <strong>{String(value)}</strong>
                  </div>
                ),
              )}
            </div>
          </article>

          <article className="card">
            <h3>Similar reports</h3>
            {similar.length ? (
              <ul className="similar-list">
                {similar.map((item) => (
                  <li key={item.file_hash || item.file_hash_sha256}>
                    <Link href={`/reports/${item.file_hash || item.file_hash_sha256}`}>
                      <strong>{item.filename || item.file_name || item.file_hash_sha256}</strong>
                      <span>
                        {item.similarity_score}% match - {item.verdict}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No related samples yet.</p>
            )}
          </article>
        </section>
      ) : null}

      {activeTab === "indicators" ? (
        <section className="content-grid">
          <article className="card wide">
            <h3>Extracted indicators</h3>
            <div className="ioc-grid">
              {Object.entries(report.iocs || {}).map(([type, values]) => (
                <div className="ioc-group" key={type}>
                  <h4>{type}</h4>
                  {Array.isArray(values) && values.length ? (
                    values.map((value) => <code key={value}>{value}</code>)
                  ) : (
                    <span className="muted">None found</span>
                  )}
                </div>
              ))}
            </div>
          </article>
        </section>
      ) : null}

      {activeTab === "detections" ? (
        <section className="content-grid two">
          <article className="card">
            <h3>Sigma draft</h3>
            {detections?.rules?.length ? (
              <pre>{detections.rules[0].content}</pre>
            ) : (
              <p className="muted">No detection rule generated.</p>
            )}
          </article>
          <article className="card">
            <h3>YARA draft</h3>
            {detections?.rules?.[1] ? (
              <pre>{detections.rules[1].content}</pre>
            ) : (
              <p className="muted">No YARA draft generated.</p>
            )}
          </article>
        </section>
      ) : null}

      {activeTab === "feedback" ? (
        <section className="content-grid two">
          <article className="card">
            <h3>Analyst feedback</h3>
            <label>
              Verdict
              <select
                value={feedback.verdict}
                onChange={(event) =>
                  setFeedback((current) => ({
                    ...current,
                    verdict: event.target.value,
                  }))
                }
              >
                <option value="">No override</option>
                <option value="benign">Benign</option>
                <option value="suspicious">Suspicious</option>
                <option value="malicious">Malicious</option>
              </select>
            </label>
            <label>
              Notes
              <textarea
                onChange={(event) =>
                  setFeedback((current) => ({
                    ...current,
                    notes: event.target.value,
                  }))
                }
                placeholder="What did the analyst confirm or reject?"
                value={feedback.notes}
              />
            </label>
            <button className="primary-button" onClick={submitFeedback} type="button">
              Save feedback
            </button>
            {feedbackStatus ? <p className="muted">{feedbackStatus}</p> : null}
          </article>

          <article className="card markdown-card">
            <h3>Markdown report</h3>
            {(report.markdown_report || "")
              .split("\n")
              .filter(Boolean)
              .slice(0, 12)
              .map((line, index) => (
                <MarkdownLine key={`${line}-${index}`} text={line} />
              ))}
          </article>
        </section>
      ) : null}
    </>
  );
}
