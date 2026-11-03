'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, ApiClientError } from '@/lib/api-client';

interface CreateOrganizationResponse {
  organization: { slug: string };
}

export function CreateOrganizationForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const name = String(data.get('name') ?? '').trim();
    const description = String(data.get('description') ?? '').trim();

    setPending(true);
    setError(null);

    try {
      const result = await api.post<CreateOrganizationResponse>('/api/v1/organizations', {
        name,
        ...(description.length > 0 ? { description } : {}),
      });
      router.push(`/app/${result.organization.slug}`);
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiClientError
          ? caught.displayMessage
          : 'Could not create the organization.',
      );
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="stack">
      {error ? (
        <p className="banner error" role="alert">
          {error}
        </p>
      ) : null}
      <label className="field" htmlFor="org-name">
        Organization name
        <input id="org-name" name="name" required minLength={2} maxLength={80} autoFocus />
      </label>
      <label className="field" htmlFor="org-description">
        Description (optional)
        <textarea id="org-description" name="description" maxLength={500} />
      </label>
      <div className="row">
        <button type="submit" disabled={pending}>
          {pending ? 'Creating…' : 'Create organization'}
        </button>
      </div>
    </form>
  );
}
