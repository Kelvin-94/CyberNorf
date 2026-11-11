import { AppError, badRequest } from '@/server/errors';

/**
 * Bounded multipart/form-data parsing.
 *
 * `Request.formData()` buffers the whole body in memory, so an unbounded call is
 * a memory-exhaustion primitive. The declared `Content-Length` is therefore
 * checked *before* parsing and the multipart envelope overhead is budgeted
 * explicitly, so a request that would exceed the limit is refused without the
 * body ever being read.
 *
 * A request with no `Content-Length` (chunked transfer encoding) is refused
 * rather than parsed: without a declared length the only remaining bound would be
 * applied after buffering, which is exactly the case this guard exists to
 * prevent. Browsers always send a length for a file input, so the practical cost
 * is nil, and an operator uploading from a script can set one.
 */

/** Room for the multipart boundaries, part headers and small text fields. */
const ENVELOPE_OVERHEAD_BYTES = 64 * 1024;

export interface ParsedMultipart {
  /** The uploaded file, or null when the request carried only fields. */
  file: { name: string; type: string; size: number; stream: () => ReadableStream<Uint8Array> } | null;
  fields: Record<string, string>;
}

export async function readMultipartForm(
  request: Request,
  options: { maxFileBytes: number; fieldNames: readonly string[] },
): Promise<ParsedMultipart> {
  const contentType = (request.headers.get('content-type') ?? '').toLowerCase();
  if (!contentType.startsWith('multipart/form-data')) {
    throw new AppError(
      415,
      'UNSUPPORTED_MEDIA_TYPE',
      'Uploads must use multipart/form-data with the file in a "file" field.',
    );
  }

  const declared = request.headers.get('content-length');
  if (declared === null) {
    throw new AppError(
      411,
      'BAD_REQUEST',
      'A Content-Length header is required so the upload can be bounded before it is read.',
    );
  }
  const declaredBytes = Number(declared);
  if (!Number.isFinite(declaredBytes) || declaredBytes < 0) {
    throw badRequest('Content-Length is not a valid length.');
  }
  const ceiling = options.maxFileBytes + ENVELOPE_OVERHEAD_BYTES;
  if (declaredBytes > ceiling) {
    throw new AppError(
      413,
      'PAYLOAD_TOO_LARGE',
      `The upload is too large: the limit is ${Math.round(options.maxFileBytes / (1024 * 1024))} MB.`,
    );
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    throw badRequest('The multipart body could not be parsed.');
  }

  const fields: Record<string, string> = {};
  for (const name of options.fieldNames) {
    const value = form.get(name);
    // Repeated fields are collapsed by `get`, which is intended: a client sending
    // the same field twice is trying to smuggle a second value past validation.
    if (typeof value === 'string' && value.trim().length > 0) {
      fields[name] = value.trim();
    }
  }

  const raw = form.get('file');
  if (raw === null || typeof raw === 'string') {
    return { file: null, fields };
  }
  if (raw.size > options.maxFileBytes) {
    throw new AppError(
      413,
      'PAYLOAD_TOO_LARGE',
      `The file is too large: the limit is ${Math.round(options.maxFileBytes / (1024 * 1024))} MB.`,
    );
  }
  if (raw.size === 0) {
    throw badRequest('The uploaded file is empty.');
  }

  return {
    file: { name: raw.name, type: raw.type, size: raw.size, stream: () => raw.stream() },
    fields,
  };
}
