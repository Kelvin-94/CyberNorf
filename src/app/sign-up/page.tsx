import type { Metadata } from 'next';
import { redirect } from 'next/navigation';
import { SignUpForm } from '@/components/auth/sign-up-form';
import { getSessionUser } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Create account · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function SignUpPage() {
  if (await getSessionUser()) {
    redirect('/app');
  }

  return (
    <main className="auth-shell">
      <section className="auth-card stack">
        <p className="eyebrow">CyberNorf</p>
        <h1>Create your account</h1>
        <p className="small muted">
          Registration creates your identity only. You join an organization when an owner adds your
          email address, or you can create your own organization afterwards.
        </p>
        <SignUpForm />
      </section>
    </main>
  );
}
