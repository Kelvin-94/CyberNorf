'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { authClient } from '@/lib/auth-client';

const MIN_PASSWORD_LENGTH = 12;

export function SignUpForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const name = String(data.get('name') ?? '').trim();
    const email = String(data.get('email') ?? '').trim();
    const password = String(data.get('password') ?? '');

    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Use at least ${MIN_PASSWORD_LENGTH} characters for your password.`);
      return;
    }

    setPending(true);
    setError(null);

    const { error: signUpError } = await authClient.signUp.email({ name, email, password });

    if (signUpError) {
      setError(
        signUpError.status === 422 || signUpError.status === 400
          ? 'That email address cannot be registered. If it already exists, sign in instead.'
          : 'Registration failed. Try again shortly.',
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
      <label className="field" htmlFor="name">
        Full name
        <input
          id="name"
          name="name"
          autoComplete="name"
          required
          minLength={2}
          maxLength={80}
          autoFocus
        />
      </label>
      <label className="field" htmlFor="email">
        Work email
        <input id="email" name="email" type="email" autoComplete="username" required />
      </label>
      <label className="field" htmlFor="password">
        Password
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_PASSWORD_LENGTH}
        />
        <span className="small muted">At least {MIN_PASSWORD_LENGTH} characters.</span>
      </label>
      <button type="submit" disabled={pending}>
        {pending ? 'Creating account…' : 'Create account'}
      </button>
      <p className="small muted">
        Already registered? <Link href="/sign-in">Sign in</Link>.
      </p>
    </form>
  );
}
