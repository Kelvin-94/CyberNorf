import type { Metadata } from 'next';
import { TwoFactorChallenge } from '@/components/auth/two-factor-challenge';

export const metadata: Metadata = { title: 'Two-factor verification · CyberNorf' };
export const dynamic = 'force-dynamic';

export default function TwoFactorPage() {
  return (
    <main className="auth-shell">
      <section className="auth-card stack">
        <p className="eyebrow">CyberNorf</p>
        <h1>Verify your sign-in</h1>
        <p className="small muted">
          Enter the current code from your authenticator app, or use one of your saved backup codes.
        </p>
        <TwoFactorChallenge />
      </section>
    </main>
  );
}
