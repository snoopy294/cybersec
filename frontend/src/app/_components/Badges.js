export function StatusBadge({ status }) {
  const value = String(status || "unknown").toLowerCase();

  return (
    <span className={`status-badge status-${value}`}>
      {value}
    </span>
  );
}

export function VerdictBadge({ verdict }) {
  const value = String(verdict || "unknown").toLowerCase();

  return (
    <span className={`verdict-badge verdict-${value}`}>
      {value}
    </span>
  );
}
