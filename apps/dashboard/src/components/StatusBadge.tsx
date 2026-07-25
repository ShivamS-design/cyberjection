interface StatusBadgeProps {
  status: string;
}

// Maps a campaign/test status or verdict string to a color class. Shared
// by every page that renders one of these (campaign status: QUEUED,
// RUNNING, COMPLETED, FAILED, INTERRUPTED; test verdict: PASS, FAIL,
// UNCERTAIN -- see cyberjection.persistence.models' own column comments
// for the full enumerations), so the color mapping only lives in one
// place instead of being re-derived per page.
const STATUS_CLASSES: Record<string, string> = {
  COMPLETED: "badge badge-ok",
  PASS: "badge badge-ok",
  RUNNING: "badge badge-pending",
  QUEUED: "badge badge-pending",
  UNCERTAIN: "badge badge-pending",
  FAILED: "badge badge-bad",
  FAIL: "badge badge-bad",
  INTERRUPTED: "badge badge-bad",
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const className = STATUS_CLASSES[status] ?? "badge";
  return <span className={className}>{status}</span>;
}
