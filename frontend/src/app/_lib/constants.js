export const API_BASE = "/api/v1";
export const SESSION_KEY = "sentinel_session";
export const MAX_UPLOAD_SIZE_MB = 10;
export const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;
// Render's free tier can take up to a minute to wake, so allow for a cold start.
export const API_TIMEOUT_MS = 90_000;

export const ACTIVE_STATUSES = ["ingesting", "queued", "analyzing", "cortex_reasoning"];
const SHA256_RE = /^[a-f0-9]{64}$/i;

export function isSha256(value) {
  return typeof value === "string" && SHA256_RE.test(value);
}

export function reportHashFromUrl(reportUrl) {
  const hash = reportUrl?.split("/").pop();
  return isSha256(hash) ? hash : null;
}

export function formatSize(bytes) {
  if (!bytes) {
    return "Unknown";
  }

  const mb = bytes / (1024 * 1024);
  return mb >= 1 ? `${mb.toFixed(2)} MB` : `${(bytes / 1024).toFixed(2)} KB`;
}

export function formatDate(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

/**
 * Turn an axios error into a message a person can act on.
 * The API returns { detail: string } for every error it raises on purpose.
 */
export function apiErrorMessage(err, fallback = "Something went wrong. Try again.") {
  if (err?.code === "ECONNABORTED") {
    return "The server took too long to respond. It may be waking up; try again in a moment.";
  }

  const response = err?.response;
  if (!response) {
    return "Can't reach the server. Check your connection, or wait a minute while it wakes up.";
  }

  const detail = response.data?.detail;
  if (typeof detail === "string" && detail) {
    return detail;
  }
  if (Array.isArray(detail) && detail.length) {
    return detail.map((item) => item?.msg).filter(Boolean).join("; ") || fallback;
  }

  switch (response.status) {
    case 413:
      return `File is too large. The limit is ${MAX_UPLOAD_SIZE_MB} MB.`;
    case 429: {
      const retry = Number(response.headers?.["retry-after"]);
      return retry > 0
        ? `Too many requests. Try again in ${retry} seconds.`
        : "Too many requests. Wait a moment and try again.";
    }
    case 502:
    case 503:
    case 504:
      return "The server is starting up or temporarily unavailable. Try again in a minute.";
    default:
      return response.status >= 500 ? "Server error. Try again in a moment." : fallback;
  }
}

/** Mirrors the backend password policy so people see problems before submitting. */
export function passwordProblems(password) {
  const problems = [];
  if (password.length < 12) {
    problems.push("at least 12 characters");
  }
  if (new TextEncoder().encode(password).length > 72) {
    problems.push("at most 72 bytes");
  }
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes < 3) {
    problems.push("three of: lowercase, uppercase, number, symbol");
  }
  return problems;
}

/** Read a JWT's expiry without verifying it; the server still checks the signature. */
export function tokenExpiresAt(token) {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return typeof payload.exp === "number" ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
}
