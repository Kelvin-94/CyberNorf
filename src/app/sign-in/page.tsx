import type { Metadata } from 'next';
import { redirect } from 'next/navigation';
import { SignInForm } from '@/components/auth/sign-in-form';
import { getOidcSignInLabel } from '@/server/auth/oidc';
import { getSessionUser } from '@/server/ui/session';

export const metadata: Metadata = { title: 'Sign in · CyberNorf' };
export const dynamic = 'force-dynamic';

/**
 * Better Auth sends the browser back here with `?error=<code>` when the
 * identity provider refuses or the exchange fails. Codes are mapped to fixed
 * text so a crafted query string cannot put arbitrary content on the page.
 */
const CALLBACK_ERRORS: Record<string, string> = {
  email_not_verified:
    'Your identity provider has not confirmed this email address. Confirm it with the provider, then try again.',
  access_denied: 'Single sign-on was cancelled before it finished.',
  signup_disabled: 'This deployment does not allow that identity to create an account.',
  account_not_linked:
    'That identity provider account is not linked to a CyberNorf account. Ask an administrator to link it.',
};

function readCallbackError(value: string | string[] | undefined): string | null {
  const code = Array.isArray(value) ? value[0] : value;
  if (!code) {
    return null;
  }
  return (
    CALLBACK_ERRORS[code] ??
    'Single sign-on could not be completed. Try again, or sign in with your password.'
  );
}

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string | string[] }>;
}) {
  if (await getSessionUser()) {
    redirect('/app');
  }

  const { error } = await searchParams;

  return (
    <main className="auth-shell">
      <section className="auth-card stack">
        <p className="eyebrow">CyberNorf</p>
        <h1>Sign in</h1>
        <p className="small muted">
          Sessions last eight hours. Privileged roles also need an authenticator code after signing
          in.
        </p>
        <SignInForm ssoLabel={getOidcSignInLabel()} initialError={readCallbackError(error)} />
      </section>
    </main>
  );
}
