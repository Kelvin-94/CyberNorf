export interface ApiErrorDetail {
  path: string;
  message: string;
}

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: ApiErrorDetail[];
  readonly requestId: string | undefined;

  constructor(
    status: number,
    body: { code?: string; message?: string; details?: ApiErrorDetail[]; requestId?: string },
  ) {
    super(body.message ?? 'The request failed.');
    this.name = 'ApiClientError';
    this.status = status;
    this.code = body.code ?? 'UNKNOWN';
    this.details = body.details ?? [];
    this.requestId = body.requestId;
  }

  /** Message that includes field-level validation details when present. */
  get displayMessage(): string {
    if (this.details.length === 0) {
      return this.message;
    }
    return `${this.message} ${this.details.map((detail) => detail.message).join(' ')}`;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const payload: unknown = text.length > 0 ? safeParse(text) : null;

  if (!response.ok) {
    const errorBody = (
      payload as {
        error?: { code?: string; message?: string; details?: ApiErrorDetail[]; requestId?: string };
      }
    )?.error;
    throw new ApiClientError(response.status, errorBody ?? {});
  }

  return payload as T;
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body),
};
