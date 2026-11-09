'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { authClient } from '@/lib/auth-client';

export function SignInForm({
  ssoLabel = null,
  initialError = null,
}: {
  /** Identity provider name when single sign-on is configured, otherwise null. */
  ssoLabel?: string | null;
  initialError?: string | null;
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [ssoPending, setSsoPending] = useState(false);
  const [error, setError] = useState<string | null>(initialError);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const email = String(data.get('email') ?? '');
    const password = String(data.get('password') ?? '');

    setPending(true);
    setError(null);

    const { error: signInError } = await authClient.signIn.email({ email, password });

    if (signInError) {
      // Generic message: do not disclose whether the account exists.
      setError(
        signInError.status === 429
          ? 'Too many sign-in attempts. Wait a minute and try again.'
          : 'Email or password is incorrect.',
      );
      setPending(false);
      return;
    }

    router.push('/app');
    router.refresh();
  }

  async function onSso() {
    setSsoPending(true);
    setError(null);

    // The browser leaves the page for the identity provider, so there is no
    // success branch here: only a refusal (or an unreachable provider) lands in
    // the result, and provider-side failures come back on /sign-in?error=.
    const { error: ssoError } = await authClient.signIn.social({
      provider: 'oidc',
      callbackURL: '/app',
      errorCallbackURL: '/sign-in',
    });

    if (ssoError) {
      setError(
        ssoError.status === 429
          ? 'Too many sign-in attempts. Wait a minute and try again.'
          : 'Single sign-on is unavailable right now. Try again, or sign in with your password.',
      );
      setSsoPending(false);
    }
  }

  const busy = pending || ssoPending;

  return (
    <div className="stack">
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
      {ssoLabel ? (
        <>
          <button type="button" className="secondary" onClick={onSso} disabled={busy}>
            {ssoPending ? 'Redirecting…' : `Continue with ${ssoLabel}`}
          </button>
          <p className="auth-divider small muted">or sign in with a password</p>
        </>
      ) : null}
      <form onSubmit={onSubmit} className="stack">
        <label className="field" htmlFor="email">
          Email
          <input id="email" name="email" type="email" autoComplete="username" required autoFocus />
        </label>
        <label className="field" htmlFor="password">
          Password
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </label>
        <button type="submit" disabled={busy}>
          {pending ? 'Signing in…' : 'Sign in'}
        </button>
        <p className="small muted">
          No account yet? <Link href="/sign-up">Create one</Link>.
        </p>
      </form>
    </div>
  );
}
