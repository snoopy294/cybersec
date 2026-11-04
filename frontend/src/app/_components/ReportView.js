"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSentinelApp } from "./AppShell";
import { VerdictBadge } from "./Badges";
import { apiErrorMessage, isSha256 } from "../_lib/constants";

// Report text includes strings pulled out of uploaded samples, so it is
// attacker-controlled. Build React elements instead of injecting HTML.
function inlineMarkdown(text) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);

  return parts.map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
      return <strong key={index}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
      return <code key={index}>{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

function ReportMarkdown({ text }) {
  const blocks = [];
  let bullets = null;

  text.split("\n").forEach((rawLine) => {
    const line = rawLine.trim();
    if (!line) {
      bullets = null;
    } else if (line.startsWith("- ")) {
      if (!bullets) {
        bullets = [];
        blocks.push({ type: "list", items: bullets });
      }
      bullets.push(line.slice(2));
    } else {
      bullets = null;
      const heading = line.match(/^#{1,6}\s+(.*)$/);
      blocks.push(
        heading
          ? { type: "heading", text: heading[1] }
          : { type: "paragraph", text: line },
      );
    }
  });

  // The title repeats the page header, so the report starts at its first section.
  const body = blocks[0]?.type === "heading" ? blocks.slice(1) : blocks;

  return body.map((block, index) => {
    if (block.type === "heading") {
      return <h4 key={index}>{block.text}</h4>;
    }
    if (block.type === "list") {
      return (
        <ul key={index}>
          {block.items.map((item, itemIndex) => (
            <li key={itemIndex}>{inlineMarkdown(item)}</li>
          ))}
        </ul>
      );
    }
    return <p key={index}>{inlineMarkdown(block.text)}</p>;
  });
}

function DocumentCard({ document }) {
  const facts = [
    ["Pages", document.page_count],
    ["Title", document.title],
    ["Author", document.author],
    ["Created with", document.producer],
    ["Active content", document.active_content?.join(", ") || "None"],
    ["Attachments", document.attachments?.length || 0],
  ].filter(([, value]) => value !== null && value !== undefined && value !== "");

  return (
    <article className="card wide">
      <h3>PDF document</h3>
      {document.parse_warning ? <p className="form-error">{document.parse_warning}</p> : null}
      {document.encrypted ? (
        <p className="muted">This PDF requires a password, so its contents could not be inspected.</p>
      ) : (
        <div className="content-grid two">
          <div className="key-value-list">
            {facts.map(([label, value]) => (
              <div key={label}>
                <span>{label}</span>
                <strong>{String(value)}</strong>
              </div>
            ))}
            {document.attachments?.map((attachment) => (
              <div key={attachment.name}>
                <span>{attachment.executable ? "Executable attachment" : "Attachment"}</span>
                <strong>{attachment.name}</strong>
              </div>
            ))}
          </div>
          <div>
            <h4 className="document-text-heading">Extracted text</h4>
            {document.text_preview ? (
              <>
                <pre className="document-text">{document.text_preview}</pre>
                {document.text_truncated ? (
                  <p className="muted">
                    Showing the start of {document.text_characters.toLocaleString()} extracted characters.
                  </p>
                ) : null}
              </>
            ) : (
              <p className="muted">
                {document.parsed
                  ? "No extractable text. This PDF may contain only scanned images."
                  : "Text could not be extracted."}
              </p>
            )}
          </div>
        </div>
      )}
    </article>
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
  const reportTitle = report.file_name || "Threat report";
  const reportHashValue = report.file_hash_sha256 || reportHash;
  const reportScore = report.severity_score ?? 0;
  const reportSummary =
    report.static_data?.summary ||
    "This report predates the latest analyzer. Use Refresh analysis to update it.";
  const riskReasons = report.static_data?.risk_reasons || [];
  const capabilities = report.static_data?.behavior_profile?.capabilities || [];
  const reportDocument = report.static_data?.document;

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
          {riskReasons.length ? (
            <article className="card wide">
              <h3>Why this verdict</h3>
              <ul className="reason-list">
                {riskReasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            </article>
          ) : null}

          {reportDocument ? <DocumentCard document={reportDocument} /> : null}

          <article className="card">
            <h3>Behavior profile</h3>
            {capabilities.length ? (
              <div className="capability-list">
                {capabilities.map((capability) => (
                  <div className="behavior-row" key={capability.name}>
                    <div>
                      <div className="behavior-title">{capability.label}</div>
                      <div className="behavior-meta">
                        {Math.round(capability.confidence * 100)}% confidence
                        {capability.mitre?.length ? ` - ${capability.mitre.join(", ")}` : ""}
                      </div>
                    </div>
                    <div className="behavior-evidence">
                      {capability.evidence?.slice(0, 5).map((item) => (
                        <code key={item} title={item}>{item}</code>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="muted">No risky behavior detected.</p>
            )}
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

          {report.ai_narrative ? (
            <article className="card wide report-markdown">
              <h3>Full report</h3>
              <ReportMarkdown text={report.ai_narrative} />
            </article>
          ) : null}
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
        </section>
      ) : null}
    </>
  );
}
