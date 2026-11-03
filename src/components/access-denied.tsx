export function AccessDenied({ detail }: { detail?: string }) {
  return (
    <section className="card stack" role="alert">
      <h2>Access denied</h2>
      <p className="muted">
        {detail ?? 'Your role in this organization does not include permission for this page.'}
      </p>
      <p className="small muted">
        Ask an organization owner to adjust your role, or return to the dashboard.
      </p>
    </section>
  );
}

export function MfaRequiredBanner() {
  return (
    <p className="banner warning" role="alert">
      Two-factor authentication is required before privileged roles can change data. Enable it under{' '}
      <a href="/account/security">account security</a>.
    </p>
  );
}
