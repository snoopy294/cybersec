"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSentinelApp } from "./AppShell";
import { VerdictBadge } from "./Badges";
import { apiErrorMessage, isSha256 } from "../_lib/constants";

// Report text includes strings pulled out of uploaded samples, so it is
// attacker-controlled. Build React elements instead of injecting HTML.
function MarkdownLine({ text }) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);

  return (
    <p>
      {parts.map((part, index) => {
        if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
          return <strong key={index}>{part.slice(2, -2)}</strong>;
        }
        if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
          return <code key={index}>{part.slice(1, -1)}</code>;
        }
        return part;
      })}
    </p>
  );
}

function ruleText(content) {
  if (typeof content === "string") {
    return content;
  }
  try {
    return JSON.stringify(content, null, 2);
  } catch {
    return "Rule content could not be displayed.";
  }
}

export default function ReportView({ reportHash }) {
  const router = useRouter();
  const { apiClient, loadJobs } = useSentinelApp();
  const validHash = isSha256(reportHash);
  const [report, setReport] = useState(null);
  const [similar, setSimilar] = useState([]);
  const [detections, setDetections] = useState(null);
  const [activeTab, setActiveTab] = useState("summary");
  const [feedback, setFeedback] = useState({ verdict: "", notes: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [feedbackStatus, setFeedbackStatus] = useState("");
  const [savingFeedback, setSavingFeedback] = useState(false);
  const [sectionErrors, setSectionErrors] = useState([]);
  const [refreshError, setRefreshError] = useState("");

  const loadReport = useCallback(async () => {
    if (!validHash) {
      setError("That report link is invalid.");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError("");
    setSectionErrors([]);

    try {
      const reportResponse = await apiClient.get(`/report/${reportHash}`);
      setReport(reportResponse.data);
      setFeedback({
        verdict: "",
        notes: "",
      });
    } catch (err) {
      if (err.response?.status !== 401) {
        setError(apiErrorMessage(err, "Unable to load report."));
      }
      setLoading(false);
      return;
    }

    // Secondary panels should not take the whole report down if one fails.
    const [similarResult, detectionResult] = await Promise.allSettled([
      apiClient.get(`/report/${reportHash}/similar`),
      apiClient.post(`/report/${reportHash}/detections`),
    ]);
    const problems = [];
    if (similarResult.status === "fulfilled") {
      const data = similarResult.value.data;
      setSimilar(data.similar_reports || data.matches || []);
    } else {
      setSimilar([]);
      problems.push(`Similar reports: ${apiErrorMessage(similarResult.reason)}`);
    }
    if (detectionResult.status === "fulfilled") {
      setDetections(detectionResult.value.data);
    } else {
      setDetections(null);
      problems.push(`Detection rules: ${apiErrorMessage(detectionResult.reason)}`);
    }
    setSectionErrors(problems);
    setLoading(false);
  }, [apiClient, reportHash, validHash]);

  useEffect(() => {
    loadReport();
  }, [loadReport]);

  const submitFeedback = async () => {
    if (savingFeedback) {
      return;
    }
    if (feedback.notes.length > 2000) {
      setFeedbackStatus("Notes must be 2000 characters or fewer.");
      return;
    }

    setFeedbackStatus("");
    setSavingFeedback(true);

    try {
      await apiClient.post(`/report/${reportHash}/feedback`, {
        type: "verdict",
        value: feedback.verdict || "reviewed",
        comment: feedback.notes.trim() || null,
      });
      setFeedbackStatus("Feedback saved");
      loadReport();
    } catch (err) {
      if (err.response?.status !== 401) {
        setFeedbackStatus(apiErrorMessage(err, "Unable to save feedback."));
      }
    } finally {
      setSavingFeedback(false);
    }
  };

  const refreshReport = async () => {
    setRefreshing(true);
    setRefreshError("");

    try {
      const response = await apiClient.post(`/report/${reportHash}/refresh`);
      loadJobs();
      router.push(`/analyze?job=${response.data.job_id}`);
    } catch (err) {
      if (err.response?.status !== 401) {
        setRefreshError(apiErrorMessage(err, "Unable to refresh report."));
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
        {validHash ? (
          <button className="secondary-button" onClick={loadReport} type="button">
            Try again
          </button>
        ) : null}
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

      {refreshError ? <p className="form-error" role="alert">{refreshError}</p> : null}
      {sectionErrors.map((message) => (
        <p className="form-error" key={message} role="alert">{message}</p>
      ))}

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
              <pre>{ruleText(detections.rules[0].content)}</pre>
            ) : (
              <p className="muted">No detection rule generated.</p>
            )}
          </article>
          <article className="card">
            <h3>YARA draft</h3>
            {detections?.rules?.[1] ? (
              <pre>{ruleText(detections.rules[1].content)}</pre>
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
                maxLength={2000}
                placeholder="What did the analyst confirm or reject?"
                value={feedback.notes}
              />
            </label>
            <button
              className="primary-button"
              disabled={savingFeedback}
              onClick={submitFeedback}
              type="button"
            >
              {savingFeedback ? "Saving..." : "Save feedback"}
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
