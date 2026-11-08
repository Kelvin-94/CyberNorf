const BADGE_CLASS: Record<string, string> = {
  PENDING_APPROVAL: 'medium',
  ACTIVE: 'success',
  SUSPENDED: 'info',
  REVOKED: 'denied',
};

/** Renders the lifecycle state with the same severity vocabulary as findings. */
export function AgentStatusBadge({ status }: { status: string }) {
  return (
    <span className={`badge ${BADGE_CLASS[status] ?? 'info'}`}>
      {status.replaceAll('_', ' ').toLowerCase()}
    </span>
  );
}
