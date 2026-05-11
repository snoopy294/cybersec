export const API_BASE = "/api/v1";
export const SESSION_KEY = "sentinel_session";
export const MAX_UPLOAD_SIZE_MB = 100;
export const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;

export function reportHashFromUrl(reportUrl) {
  return reportUrl?.split("/").pop() || null;
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

  return new Date(value).toLocaleString();
}
