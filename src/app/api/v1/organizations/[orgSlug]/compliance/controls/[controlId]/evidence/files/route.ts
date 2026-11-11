import { jsonResponse, withTenantApi } from '@/server/api/handler';
import { MAX_EVIDENCE_BYTES } from '@/server/domain/quotas';
import { readMultipartForm } from '@/server/http/multipart';
import { badRequest } from '@/server/errors';
import { listEvidenceFiles, uploadEvidenceFile } from '@/server/services/evidence-files';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; controlId: string };

export const GET = withTenantApi<Params>('compliance.read', {}, async ({ meta, ctx, params }) => {
  const files = await listEvidenceFiles(ctx, params.controlId);
  return jsonResponse({ files }, meta);
});

/**
 * Uploads one artifact as evidence for a control.
 *
 * The rate limit is deliberately tighter than a normal write: each request can
 * write up to 10 MB and hold a quota lock, so a burst is far more expensive here
 * than elsewhere.
 */
export const POST = withTenantApi<Params>(
  'compliance.evidence',
  { rateLimit: { limit: 30, windowSeconds: 60 } },
  async ({ request, meta, ctx, params }) => {
    const parsed = await readMultipartForm(request, {
      maxFileBytes: MAX_EVIDENCE_BYTES,
      fieldNames: ['capturedAt', 'note'],
    });
    if (!parsed.file) {
      throw badRequest('Attach the evidence file in a "file" field.');
    }

    // A declared type of `application/octet-stream` is what a browser sends when
    // it cannot tell; it is not an accepted evidence format, so it is refused
    // rather than guessed from the file extension.
    const capturedAt = parsed.fields.capturedAt ? new Date(parsed.fields.capturedAt) : null;
    if (capturedAt && Number.isNaN(capturedAt.getTime())) {
      throw badRequest('capturedAt must be a valid ISO 8601 date and time.');
    }
    if (capturedAt && capturedAt.getTime() > Date.now() + 60_000) {
      throw badRequest('capturedAt cannot be in the future.');
    }

    const file = await uploadEvidenceFile(ctx, params.controlId, {
      fileName: parsed.file.name,
      contentType: parsed.file.type,
      capturedAt,
      note: parsed.fields.note ?? null,
      body: parsed.file.stream(),
      declaredLength: parsed.file.size,
    });

    return jsonResponse({ file }, meta, 201);
  },
);
