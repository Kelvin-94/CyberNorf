import { z } from 'zod';

export const MAX_PAGE_SIZE = 100;

export const cuidLikeSchema = z
  .string()
  .trim()
  .min(1, 'Identifier is required.')
  .max(64, 'Identifier is too long.')
  .regex(/^[A-Za-z0-9_-]+$/, 'Identifier has an invalid format.');

const optionalText = (max: number) =>
  z
    .string()
    .trim()
    .max(max, `Must be ${max} characters or fewer.`)
    .transform((value) => (value.length === 0 ? null : value))
    .nullable();

export const optionalDescription = (max = 5000) => optionalText(max).optional();
export const optionalShortText = (max = 200) => optionalText(max).optional();

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).max(10000).default(1),
  pageSize: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(20),
});

export const searchSchema = z
  .string()
  .trim()
  .max(120, 'Search terms must be 120 characters or fewer.')
  .optional()
  .transform((value) => (value && value.length > 0 ? value : undefined));

export const sortDirectionSchema = z.enum(['asc', 'desc']).default('desc');

/**
 * Drops `undefined` from optional properties while preserving which keys are
 * required. Zod marks absent optional fields as `undefined` and the server
 * layer uses `exactOptionalPropertyTypes`, so the two only line up once absent
 * fields are removed from the payload instead of passed through.
 */
export type StripUndefined<T> = {
  [K in keyof T]: undefined extends T[K] ? Exclude<T[K], undefined> : T[K];
};

export function withoutUndefined<T extends object>(value: T): StripUndefined<T> {
  const result: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (entry !== undefined) {
      result[key] = entry;
    }
  }
  return result as StripUndefined<T>;
}

export type RawSearchParams = Record<string, string | string[] | undefined>;

/**
 * Reads one search parameter as trimmed text. Repeated keys and non-string
 * values are ignored so a crafted URL cannot turn into a runtime type error.
 */
export function searchParam(raw: RawSearchParams, key: string): string | undefined {
  const value = raw[key];
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Reads one search parameter and keeps it only when it is a member of the
 * allowed set. List pages use this so an unknown filter value (for example
 * `?severity=NOPE`) renders an unfiltered page instead of throwing.
 */
export function enumSearchParam<T extends string>(
  raw: RawSearchParams,
  key: string,
  schema: z.ZodType<T>,
): T | undefined {
  const value = searchParam(raw, key);
  if (value === undefined) {
    return undefined;
  }
  const parsed = schema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

export function firstValueQuery(request: Request): Record<string, string> {
  const query: Record<string, string> = {};
  for (const [key, value] of new URL(request.url).searchParams) {
    if (!(key in query)) {
      query[key] = value;
    }
  }
  return query;
}

export function parseQuery<T extends z.ZodTypeAny>(request: Request, schema: T): z.infer<T> {
  return schema.parse(firstValueQuery(request));
}

export const isoDateTimeSchema = z
  .string()
  .trim()
  .refine((value) => !Number.isNaN(Date.parse(value)), 'Must be a valid ISO 8601 date and time.')
  .transform((value) => new Date(value));

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254)
  .pipe(z.email('Enter a valid email address.'));
