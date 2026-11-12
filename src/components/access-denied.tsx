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
    <div className="banner warning" role="alert">
      <strong>Two-factor authentication is required for your role.</strong> Reading, filtering and
      exporting still work, but the server refuses every change to organization data until an
      authenticator app is enrolled.{' '}
      <a href="/account/security">Set up two-factor authentication</a> — it takes about a minute
      and you will be asked for a six-digit code afterwards. This is deliberate: an owner or
      administrator account is the most valuable credential in the tenant.
    </div>
  );
}
