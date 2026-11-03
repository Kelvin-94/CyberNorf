import type { Metadata } from 'next';
import { redirect } from 'next/navigation';
import { SignInForm } from '@/components/auth/sign-in-form';
import { getSessionUser } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Sign in · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function SignInPage() {
  if (await getSessionUser()) {
    redirect('/app');
  }

  return (
    <main className="auth-shell">
      <section className="auth-card stack">
        <p className="eyebrow">CyberNorf</p>
        <h1>Sign in</h1>
        <p className="small muted">
          Sessions last eight hours. Privileged roles also need an authenticator code after signing
          in.
        </p>
        <SignInForm />
      </section>
    </main>
  );
}
