'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { authClient } from '@/lib/auth-client';

export function SignInForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

  return (
    <form onSubmit={onSubmit} className="stack">
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
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
      <button type="submit" disabled={pending}>
        {pending ? 'Signing in…' : 'Sign in'}
      </button>
      <p className="small muted">
        No account yet? <Link href="/sign-up">Create one</Link>.
      </p>
    </form>
  );
}
