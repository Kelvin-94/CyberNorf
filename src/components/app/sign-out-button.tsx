'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { authClient } from '@/lib/auth-client';

export function SignOutButton() {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  return (
    <button
      type="button"
      className="secondary"
      disabled={pending}
      onClick={async () => {
        setPending(true);
        await authClient.signOut();
        router.push('/sign-in');
        router.refresh();
      }}
    >
      {pending ? 'Signing out…' : 'Sign out'}
    </button>
  );
}
