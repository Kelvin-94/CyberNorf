'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { authClient } from '@/lib/auth-client';

export function TwoFactorChallenge() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [useBackupCode, setUseBackupCode] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const code = String(data.get('code') ?? '').trim();

    setPending(true);
    setError(null);

    const { error: verifyError } = useBackupCode
      ? await authClient.twoFactor.verifyBackupCode({ code })
      : await authClient.twoFactor.verifyTotp({ code });

    if (verifyError) {
      setError('That code is not valid. Check your authenticator and try again.');
      setPending(false);
      return;
    }

    router.push('/app');
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="stack">
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
      <label className="field" htmlFor="code">
        {useBackupCode ? 'Backup code' : 'Authenticator code'}
        <input
          id="code"
          name="code"
          inputMode={useBackupCode ? 'text' : 'numeric'}
          autoComplete="one-time-code"
          required
          autoFocus
          maxLength={useBackupCode ? 32 : 6}
        />
      </label>
      <button type="submit" disabled={pending}>
        {pending ? 'Verifying…' : 'Verify'}
      </button>
      <button
        type="button"
        className="secondary"
        onClick={() => {
          setUseBackupCode((current) => !current);
          setError(null);
        }}
      >
        {useBackupCode ? 'Use an authenticator code' : 'Use a backup code'}
      </button>
    </form>
  );
}
