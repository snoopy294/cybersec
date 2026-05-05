'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import axios from 'axios';

const API_BASE = '/api/v1';

// ── Sidebar ─────────────────────────────────────────────────────

function Sidebar({ currentPage, onNavigate }) {
  const navItems = [
    { id: 'dashboard', label: 'Command Center', icon: '◉' },
    { id: 'upload', label: 'Analyze File', icon: '⬆' },
    { id: 'jobs', label: 'Analysis History', icon: '☰' },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">S</div>
        <span className="sidebar-brand">SENTINEL</span>
      </div>
      <nav className="sidebar-nav">
        {navItems.map(item => (
          <div
            key={item.id}
            className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
            onClick={() => onNavigate(item.id)}
          >
            <span style={{ fontSize: 18, width: 24, textAlign: 'center' }}>{item.icon}</span>
            {item.label}
          </div>
        ))}
      </nav>
      <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border-color)', fontSize: 11, color: 'var(--text-muted)' }}>
        SENTINEL v0.1.0 — Pre-Seed
      </div>
    </aside>
  );
}

// ── Stat Card ───────────────────────────────────────────────────

function StatCard({ label, value, change, positive }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {change && (
        <div className={`stat-change ${positive ? 'positive' : 'negative'}`}>
          {positive ? '↑' : '↓'} {change}
        </div>
      )}
    </div>
  );
}

// ── Upload Zone ─────────────────────────────────────────────────

function UploadZone({ onFileSelected }) {
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) onFileSelected(files[0]);
  }, [onFileSelected]);

  return (
    <div
      className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onClick={() => fileInputRef.current?.click()}
    >
      <div className="upload-icon" style={{ fontSize: 48, marginBottom: 16 }}>🔬</div>
      <div className="upload-title">Drop a suspicious file here</div>
      <div className="upload-subtitle">
        or click to browse — PE, ELF, scripts, docs, archives up to 500MB
      </div>
      <input
        ref={fileInputRef}
        type="file"
        style={{ display: 'none' }}
        onChange={(e) => e.target.files?.[0] && onFileSelected(e.target.files[0])}
      />
    </div>
  );
}

// ── Analysis Progress ───────────────────────────────────────────

function AnalysisProgress({ jobId, onComplete }) {
  const [job, setJob] = useState(null);

  useEffect(() => {
    if (!jobId) return;
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${API_BASE}/analyze/${jobId}`);
        setJob(res.data);
        if (res.data.status === 'COMPLETED' || res.data.status === 'FAILED') {
          clearInterval(interval);
          if (res.data.status === 'COMPLETED') onComplete(res.data);
        }
      } catch (err) {
        console.error('Poll error:', err);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [jobId, onComplete]);

  const statusLabel = {
    QUEUED: 'Queued for analysis...',
    INGESTING: 'Ingesting file...',
    ANALYZING: 'Running static analysis...',
    CORTEX_REASONING: 'AI reasoning engine processing...',
    COMPLETED: 'Analysis complete!',
    FAILED: 'Analysis failed.',
  };

  return (
    <div className="card animate-in" style={{ textAlign: 'center', padding: 48 }}>
      <div style={{ marginBottom: 24 }}>
        {job?.status === 'COMPLETED' ? (
          <span style={{ fontSize: 48 }}>✅</span>
        ) : job?.status === 'FAILED' ? (
          <span style={{ fontSize: 48 }}>❌</span>
        ) : (
          <div className="spinner" style={{ width: 48, height: 48, margin: '0 auto', borderWidth: 3 }} />
        )}
      </div>
      <h3 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>
        {statusLabel[job?.status] || 'Initializing...'}
      </h3>
      <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginBottom: 20 }}>
        {job?.file_name || 'Processing your file'}
      </p>
      <div className="progress-bar" style={{ maxWidth: 400, margin: '0 auto' }}>
        <div className="progress-fill" style={{ width: `${job?.progress_percent || 0}%` }} />
      </div>
      <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 8 }}>
        {job?.progress_percent || 0}% complete
      </p>
      {job?.status === 'COMPLETED' && job?.report_url && (
        <button
          className="btn btn-primary"
          style={{ marginTop: 24 }}
          onClick={() => onComplete(job)}
        >
          View Threat Report →
        </button>
      )}
    </div>
  );
}

// ── Status Badge ────────────────────────────────────────────────

function StatusBadge({ status }) {
  const cls = {
    QUEUED: 'badge-queued', INGESTING: 'badge-queued',
    ANALYZING: 'badge-analyzing', CORTEX_REASONING: 'badge-analyzing',
    COMPLETED: 'badge-completed', FAILED: 'badge-failed',
  };
  return <span className={`badge ${cls[status] || 'badge-queued'}`}>{status}</span>;
}

function VerdictBadge({ verdict }) {
  const cls = {
    BENIGN: 'badge-benign', SUSPICIOUS: 'badge-suspicious',
    MALICIOUS: 'badge-malicious', UNKNOWN: 'badge-queued',
  };
  return <span className={`badge ${cls[verdict] || 'badge-queued'}`}>{verdict}</span>;
}

// ── Report View ─────────────────────────────────────────────────

function ReportView({ reportHash, onBack }) {
  const [report, setReport] = useState(null);
  const [activeTab, setActiveTab] = useState('summary');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!reportHash) return;
    axios.get(`${API_BASE}/report/${reportHash}`)
      .then(res => { setReport(res.data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [reportHash]);

  if (loading) return <div style={{ textAlign: 'center', padding: 60 }}><div className="spinner" style={{ margin: '0 auto' }} /></div>;
  if (!report) return <div className="empty-state"><div className="empty-state-title">Report not found</div></div>;

  const severityClass = report.severity_score >= 70 ? 'high' : report.severity_score >= 30 ? 'medium' : 'low';

  return (
    <div className="animate-in">
      <button className="btn btn-ghost" onClick={onBack} style={{ marginBottom: 20 }}>← Back</button>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 20, marginBottom: 24 }}>
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="stat-label">Severity Score</div>
          <div className={`severity-score ${severityClass}`}>{report.severity_score}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>/ 100</div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="stat-label">Verdict</div>
          <div style={{ marginTop: 12 }}><VerdictBadge verdict={report.verdict} /></div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="stat-label">File Hash</div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-secondary)', marginTop: 12, wordBreak: 'break-all' }}>
            {report.file_hash_sha256}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="tabs">
          {['summary', 'behavior', 'static', 'iocs'].map(tab => (
            <button key={tab} className={`tab ${activeTab === tab ? 'active' : ''}`} onClick={() => setActiveTab(tab)}>
              {tab === 'summary' ? 'AI Summary' : tab === 'behavior' ? 'Behavior Graph' : tab === 'static' ? 'Static Analysis' : 'IOCs'}
            </button>
          ))}
        </div>

        {activeTab === 'summary' && report.ai_narrative && (
          <div className="markdown-content">
            {report.ai_narrative.split('\n').map((line, i) => {
              if (line.startsWith('## ')) return <h2 key={i}>{line.replace('## ', '')}</h2>;
              if (line.startsWith('### ')) return <h3 key={i}>{line.replace('### ', '')}</h3>;
              if (line.startsWith('- ')) return <li key={i} dangerouslySetInnerHTML={{ __html: line.replace('- ', '').replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>') }} />;
              if (line.startsWith('**')) return <p key={i} dangerouslySetInnerHTML={{ __html: line.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>') }} />;
              if (line.trim()) return <p key={i}>{line}</p>;
              return null;
            })}
          </div>
        )}

        {activeTab === 'behavior' && report.static_data && (
          <div>
            {report.static_data.behavior_profile?.capabilities?.length > 0 ? (
              <div style={{ display: 'grid', gap: 12, marginBottom: 24 }}>
                {report.static_data.behavior_profile.capabilities.map(capability => (
                  <div key={capability.name} className="behavior-row">
                    <div>
                      <div className="behavior-title">{capability.label}</div>
                      <div className="behavior-meta">
                        {capability.mitre?.join(', ') || 'No MITRE mapping'} · {Math.round(capability.confidence * 100)}% confidence
                      </div>
                    </div>
                    <div className="behavior-evidence">
                      {capability.evidence?.slice(0, 4).map(item => <code key={item}>{item}</code>)}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state"><div className="empty-state-title">No behavior profile detected</div></div>
            )}

            <div className="behavior-section">
              <div className="card-title" style={{ marginBottom: 12 }}>Historical Behavior Matches</div>
              {report.static_data.cross_reference?.top_matches?.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Similarity</th>
                      <th>File</th>
                      <th>Verdict</th>
                      <th>Matched Behaviors</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.static_data.cross_reference.top_matches.map(match => (
                      <tr key={match.file_hash_sha256}>
                        <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{match.similarity_score}%</td>
                        <td style={{ color: 'var(--text-primary)' }}>{match.file_name}</td>
                        <td><VerdictBadge verdict={match.verdict} /></td>
                        <td>{match.matched_behaviors?.join(', ') || 'Shared static traits'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-state"><div className="empty-state-title">No similar prior samples yet</div></div>
              )}
            </div>

            {report.static_data.behavior_profile?.semantic_fingerprint && (
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                Semantic fingerprint: {report.static_data.behavior_profile.semantic_fingerprint}
              </div>
            )}
          </div>
        )}

        {activeTab === 'static' && report.static_data && (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
              <div className="card">
                <div className="stat-label">Entropy</div>
                <div className="stat-value" style={{ fontSize: 24 }}>{report.static_data.entropy}</div>
                <div className="progress-bar" style={{ marginTop: 8 }}>
                  <div className="progress-fill" style={{ width: `${(report.static_data.entropy / 8) * 100}%` }} />
                </div>
                {report.static_data.high_entropy && <div style={{ color: 'var(--color-warning)', fontSize: 12, marginTop: 4 }}>⚠ High entropy — possibly packed</div>}
              </div>
              <div className="card">
                <div className="stat-label">Strings Found</div>
                <div className="stat-value" style={{ fontSize: 24 }}>{report.static_data.strings_count}</div>
              </div>
            </div>
            {report.static_data.pe_headers && (
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-title" style={{ marginBottom: 12 }}>PE Header Information</div>
                <table className="data-table">
                  <tbody>
                    {Object.entries(report.static_data.pe_headers).map(([key, val]) => (
                      <tr key={key}>
                        <td style={{ fontWeight: 600, color: 'var(--text-accent)', width: '40%' }}>{key}</td>
                        <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>{String(val)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'iocs' && report.iocs && (
          <div>
            {Object.entries(report.iocs).filter(([, v]) => v.length > 0).map(([category, values]) => (
              <div key={category} style={{ marginBottom: 20 }}>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-accent)', marginBottom: 8, textTransform: 'uppercase' }}>
                  {category.replace('_', ' ')} ({values.length})
                </h3>
                {values.map((val, i) => (
                  <div key={i} style={{
                    padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)',
                    marginBottom: 4, fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: 'var(--color-danger)'
                  }}>
                    {val}
                  </div>
                ))}
              </div>
            ))}
            {Object.values(report.iocs).every(v => v.length === 0) && (
              <div className="empty-state"><div className="empty-state-title">No IOCs detected</div></div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main Page ───────────────────────────────────────────────────

export default function Home() {
  const [page, setPage] = useState('dashboard');
  const [uploading, setUploading] = useState(false);
  const [activeJobId, setActiveJobId] = useState(null);
  const [reportHash, setReportHash] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [stats, setStats] = useState({ total: 0, completed: 0, malicious: 0, queued: 0 });

  // Load jobs
  const loadJobs = useCallback(async () => {
    try {
      const res = await axios.get(`${API_BASE}/jobs?per_page=50`);
      setJobs(res.data.jobs || []);
      const all = res.data.jobs || [];
      setStats({
        total: res.data.total,
        completed: all.filter(j => j.status === 'COMPLETED').length,
        malicious: 0,
        queued: all.filter(j => j.status === 'QUEUED' || j.status === 'ANALYZING').length,
      });
    } catch (err) {
      // API might not be up yet
    }
  }, []);

  useEffect(() => {
    loadJobs();
    const interval = setInterval(loadJobs, 10000);
    return () => clearInterval(interval);
  }, [loadJobs]);

  // Handle file upload
  const handleFileUpload = async (file) => {
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await axios.post(`${API_BASE}/analyze`, formData);
      setActiveJobId(res.data.job_id);
      setPage('progress');
    } catch (err) {
      alert(err.response?.data?.detail || 'Upload failed');
    }
    setUploading(false);
  };

  // Handle job completion
  const handleComplete = (job) => {
    if (job.report_url) {
      const hash = job.report_url.split('/').pop();
      setReportHash(hash);
      setPage('report');
    }
    loadJobs();
  };

  // Format file size
  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  };

  // Format date
  const formatDate = (d) => new Date(d).toLocaleString();

  return (
    <div className="app-layout">
      <Sidebar currentPage={page} onNavigate={(p) => { setPage(p); setReportHash(null); setActiveJobId(null); }} />

      <main className="main-content">
        {/* ── Dashboard ──────────────────────────────────── */}
        {page === 'dashboard' && (
          <div className="animate-in">
            <div className="page-header">
              <h1 className="page-title">Command Center</h1>
              <p className="page-subtitle">Real-time threat intelligence overview</p>
            </div>
            <div className="stats-grid">
              <StatCard label="Total Analyses" value={stats.total} />
              <StatCard label="Completed" value={stats.completed} change="Ready" positive />
              <StatCard label="In Queue" value={stats.queued} />
            </div>
            <div className="card">
              <div className="card-header">
                <span className="card-title">Recent Analyses</span>
                <button className="btn btn-primary" onClick={() => setPage('upload')}>+ New Analysis</button>
              </div>
              {jobs.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>File Name</th>
                      <th>Size</th>
                      <th>Status</th>
                      <th>Submitted</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.slice(0, 10).map(job => (
                      <tr key={job.job_id} onClick={() => {
                        if (job.status === 'COMPLETED' && job.report_url) {
                          setReportHash(job.report_url.split('/').pop());
                          setPage('report');
                        }
                      }}>
                        <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{job.file_name}</td>
                        <td>{formatSize(job.file_size_bytes)}</td>
                        <td><StatusBadge status={job.status} /></td>
                        <td>{formatDate(job.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-title">No analyses yet</div>
                  <p style={{ color: 'var(--text-muted)', marginBottom: 20 }}>Upload your first suspicious file to get started</p>
                  <button className="btn btn-primary" onClick={() => setPage('upload')}>Analyze a File</button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Upload ─────────────────────────────────────── */}
        {page === 'upload' && (
          <div className="animate-in">
            <div className="page-header">
              <h1 className="page-title">Analyze File</h1>
              <p className="page-subtitle">Upload a suspicious file for autonomous threat analysis</p>
            </div>
            {uploading ? (
              <div className="card" style={{ textAlign: 'center', padding: 48 }}>
                <div className="spinner" style={{ width: 40, height: 40, margin: '0 auto 16px' }} />
                <p style={{ color: 'var(--text-secondary)' }}>Uploading and hashing...</p>
              </div>
            ) : (
              <UploadZone onFileSelected={handleFileUpload} />
            )}
          </div>
        )}

        {/* ── Progress ───────────────────────────────────── */}
        {page === 'progress' && activeJobId && (
          <div className="animate-in">
            <div className="page-header">
              <h1 className="page-title">Analysis in Progress</h1>
              <p className="page-subtitle">SENTINEL is examining your file</p>
            </div>
            <AnalysisProgress jobId={activeJobId} onComplete={handleComplete} />
          </div>
        )}

        {/* ── Report ─────────────────────────────────────── */}
        {page === 'report' && reportHash && (
          <div>
            <div className="page-header">
              <h1 className="page-title">Threat Report</h1>
              <p className="page-subtitle">Detailed analysis findings</p>
            </div>
            <ReportView reportHash={reportHash} onBack={() => setPage('dashboard')} />
          </div>
        )}

        {/* ── Job History ────────────────────────────────── */}
        {page === 'jobs' && (
          <div className="animate-in">
            <div className="page-header">
              <h1 className="page-title">Analysis History</h1>
              <p className="page-subtitle">All submitted files and their results</p>
            </div>
            <div className="card">
              {jobs.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>File Name</th>
                      <th>SHA-256</th>
                      <th>Size</th>
                      <th>Status</th>
                      <th>Submitted</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map(job => (
                      <tr key={job.job_id} onClick={() => {
                        if (job.status === 'COMPLETED' && job.report_url) {
                          setReportHash(job.report_url.split('/').pop());
                          setPage('report');
                        }
                      }}>
                        <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{job.file_name}</td>
                        <td style={{ fontFamily: "'JetBrains Mono'", fontSize: 11 }}>{job.file_hash_sha256?.slice(0, 16)}...</td>
                        <td>{formatSize(job.file_size_bytes)}</td>
                        <td><StatusBadge status={job.status} /></td>
                        <td>{formatDate(job.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-title">No analyses yet</div>
                  <button className="btn btn-primary" onClick={() => setPage('upload')} style={{ marginTop: 16 }}>Analyze a File</button>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
