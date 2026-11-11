import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { emptyResponse, securityHeaders, withTenantApi } from '@/server/api/handler';
import { notFound } from '@/server/errors';
import { deleteEvidenceFile, getEvidenceFileForDownload } from '@/server/services/evidence-files';
import { sanitiseFileName } from '@/server/services/evidence-storage';

export const dynamic = 'force-dynamic';

type Params = { orgSlug: string; controlId: string; evidenceId: string };

/**
 * Streams the stored artifact back.
 *
 * The response is always an attachment, never rendered inline. The bytes were
 * supplied by a user and are only ever checked for their hash, not their content,
 * so a text/plain part that is actually markup must not be displayed as a page
 * in this origin. `nosniff` is already global; `attachment` plus a sandboxing CSP
 * on this response closes the remaining path where a browser might decide to
 * render instead of download.
 */
export const GET = withTenantApi<Params>('compliance.read', {}, async ({ meta, ctx, params }) => {
  const { view, path } = await getEvidenceFileForDownload(ctx, params.evidenceId);

  // The row can outlive the file if storage was restored from an older backup or
  // a volume was lost. Reporting that as 404 with an explicit code is more useful
  // than a 500, and it matches what the integrity check records.
  const info = await stat(path).catch(() => null);
  if (!info || !info.isFile()) {
    throw notFound(
      'The stored file is missing from evidence storage. Run the integrity check to record it.',
    );
  }

  const body = Readable.toWeb(createReadStream(path)) as unknown as ReadableStream<Uint8Array>;
  return new Response(body, {
    status: 200,
    headers: securityHeaders(meta, {
      'Content-Type': view.contentType,
      'Content-Length': String(info.size),
      'Content-Disposition': `attachment; filename="${sanitiseFileName(view.fileName)}"`,
      'Content-Security-Policy': "default-src 'none'; sandbox",
      // The hash is repeated in the response so a downloader can verify what
      // arrived without calling the metadata endpoint separately.
      'X-Evidence-Sha256': view.sha256,
      'Cache-Control': 'private, no-store',
    }),
  });
});

export const DELETE = withTenantApi<Params>(
  'compliance.manage',
  {},
  async ({ meta, ctx, params }) => {
    const result = await deleteEvidenceFile(ctx, params.evidenceId);
    // A blob that could not be removed is reported rather than hidden: the record
    // is gone either way, but the operator needs to know there is an orphan.
    if (!result.blobRemoved) {
      return emptyResponse(meta, 200, { 'X-Evidence-Blob-Removed': 'false' });
    }
    return emptyResponse(meta);
  },
);
