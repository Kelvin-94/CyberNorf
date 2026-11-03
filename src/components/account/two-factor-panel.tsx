'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { authClient } from '@/lib/auth-client';

interface EnrolledSecret {
  secret: string;
  uri: string;
  backupCodes: string[];
}

/**
 * Enrollment for privileged roles. Better Auth requires the current password
 * before issuing a secret, and the factor only becomes active after a valid
 * code is presented, so an abandoned setup cannot lock the account out.
 */
export function TwoFactorPanel({ enabled }: { enabled: boolean }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<EnrolledSecret | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function startEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const password = String(data.get('password') ?? '');

    setPending(true);
    setError(null);

    const { data: result, error: enableError } = await authClient.twoFactor.enable({ password });

    if (enableError || !result || result.method !== 'totp') {
      setError('Could not start enrollment. Check your password and try again.');
      setPending(false);
      return;
    }

    setEnrollment({
      secret: extractSecret(result.totpURI),
      uri: result.totpURI,
      backupCodes: result.backupCodes,
    });
    setPending(false);
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const code = String(data.get('code') ?? '').trim();

    setPending(true);
    setError(null);

    const { error: verifyError } = await authClient.twoFactor.verifyTotp({ code });

    if (verifyError) {
      setError('That code is not valid yet. Enter the current code from your authenticator.');
      setPending(false);
      return;
    }

    setEnrollment(null);
    setNotice('Two-factor authentication is now active for your account.');
    setPending(false);
    router.refresh();
  }

  async function disable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const password = String(data.get('password') ?? '');

    setPending(true);
    setError(null);

    const { error: disableError } = await authClient.twoFactor.disable({ password });

    if (disableError) {
      setError('Could not disable two-factor authentication. Check your password.');
      setPending(false);
      return;
    }

    setNotice('Two-factor authentication has been disabled.');
    setPending(false);
    router.refresh();
  }

  if (notice) {
    return (
      <p className="banner" role="status">
        {notice}
      </p>
    );
  }

  if (enabled) {
    return (
      <div className="stack">
        <p className="banner">
          Two-factor authentication is active. Keep a backup code somewhere safe: it is the only way
          in if you lose your authenticator.
        </p>
        <form onSubmit={disable} className="row">
          <label className="field" htmlFor="disable-password">
            Confirm password
            <input
              id="disable-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
          <button type="submit" className="danger" disabled={pending}>
            {pending ? 'Working…' : 'Disable two-factor'}
          </button>
        </form>
        {error ? (
          <p className="banner error" role="alert">
            {error}
          </p>
        ) : null}
      </div>
    );
  }

  if (enrollment) {
    return (
      <form onSubmit={confirm} className="stack">
        {error ? (
          <p className="banner error" role="alert">
            {error}
          </p>
        ) : null}
        <p className="small muted">
          Add this key to your authenticator app (manual entry), then enter the generated code to
          activate it.
        </p>
        <p className="mono" style={{ wordBreak: 'break-all' }}>
          {enrollment.secret}
        </p>
        <details>
          <summary className="small muted">Setup link</summary>
          <pre className="code-block">{enrollment.uri}</pre>
        </details>
        <div>
          <p className="small muted">Backup codes (shown once):</p>
          <pre className="code-block">{enrollment.backupCodes.join('\n')}</pre>
        </div>
        <label className="field" htmlFor="confirm-code">
          Code from your authenticator
          <input
            id="confirm-code"
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            required
            maxLength={6}
          />
        </label>
        <button type="submit" disabled={pending}>
          {pending ? 'Activating…' : 'Activate two-factor'}
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={startEnrollment} className="stack">
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
      <p className="small muted">
        Privileged roles must use an authenticator app before they can change organization data.
      </p>
      <label className="field" htmlFor="enroll-password">
        Confirm password
        <input
          id="enroll-password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
        />
      </label>
      <button type="submit" disabled={pending}>
        {pending ? 'Starting…' : 'Set up two-factor authentication'}
      </button>
    </form>
  );
}

function extractSecret(uri: string): string {
  try {
    const parsed = new URL(uri);
    return parsed.searchParams.get('secret') ?? uri;
  } catch {
    return uri;
  }
}
