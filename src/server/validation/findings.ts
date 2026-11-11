import { z } from 'zod';
import {
  cuidLikeSchema,
  isoDateTimeSchema,
  optionalDescription,
  optionalShortText,
} from './common';

export const findingSeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
export const incidentSeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
export const findingStatusSchema = z.enum([
  'OPEN',
  'TRIAGED',
  'IN_PROGRESS',
  'RESOLVED',
  'ACCEPTED_RISK',
  'FALSE_POSITIVE',
]);
export const incidentStatusSchema = z.enum([
  'OPEN',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'CLOSED',
]);

const cveIdSchema = z
  .string()
  .trim()
  .toUpperCase()
  .regex(/^CVE-\d{4}-\d{4,}$/, 'Use the CVE-YYYY-NNNN format.')
  .nullable();

const cvssScoreSchema = z
  .number()
  .min(0, 'CVSS score must be between 0 and 10.')
  .max(10, 'CVSS score must be between 0 and 10.')
  .refine((value) => Number.isInteger(value * 10), 'CVSS score supports one decimal place.')
  .nullable();

export const createFindingSchema = z.object({
  title: z
    .string()
    .trim()
    .min(3, 'Title must be at least 3 characters.')
    .max(200, 'Title is too long.'),
  description: optionalDescription(5000),
  severity: findingSeveritySchema,
  assetId: cuidLikeSchema.nullable().optional(),
  assignedToId: cuidLikeSchema.nullable().optional(),
  incidentId: cuidLikeSchema.nullable().optional(),
  cveId: cveIdSchema.optional(),
  cvssScore: cvssScoreSchema.optional(),
  remediation: optionalDescription(5000),
  firstSeenAt: isoDateTimeSchema.optional(),
});

export const updateFindingSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(3, 'Title must be at least 3 characters.')
      .max(200, 'Title is too long.')
      .optional(),
    description: optionalDescription(5000),
    severity: findingSeveritySchema.optional(),
    assetId: cuidLikeSchema.nullable().optional(),
    assignedToId: cuidLikeSchema.nullable().optional(),
    incidentId: cuidLikeSchema.nullable().optional(),
    cveId: cveIdSchema.optional(),
    cvssScore: cvssScoreSchema.optional(),
    remediation: optionalDescription(5000),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'Provide at least one field to update.',
  });

export const changeFindingStatusSchema = z.object({
  status: findingStatusSchema,
  note: optionalDescription(1000),
});

export const findingQuerySchema = z.object({
  search: optionalShortText(),
  status: findingStatusSchema.optional(),
  severity: findingSeveritySchema.optional(),
  assetId: cuidLikeSchema.optional(),
  incidentId: cuidLikeSchema.optional(),
  assignedToId: cuidLikeSchema.optional(),
  // Explicit string parsing: z.coerce.boolean() would treat "false" as true.
  overdue: z
    .enum(['true', 'false'])
    .transform((value) => value === 'true')
    .optional(),
  page: z.coerce.number().int().min(1).max(10000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  sort: z
    .enum([
      'createdAt',
      'updatedAt',
      'severity',
      'status',
      'title',
      'lastSeenAt',
      'riskScore',
      'dueAt',
    ])
    .default('createdAt'),
  direction: z.enum(['asc', 'desc']).default('desc'),
});

const importItemSchema = z.object({
  title: z
    .string()
    .trim()
    .min(3, 'Title must be at least 3 characters.')
    .max(200, 'Title is too long.'),
  description: optionalDescription(5000),
  severity: findingSeveritySchema,
  assetId: cuidLikeSchema.optional(),
  assetIdentifier: z.string().trim().toLowerCase().min(1).max(255).optional(),
  cveId: z
    .string()
    .trim()
    .toUpperCase()
    .regex(/^CVE-\d{4}-\d{4,}$/, 'Use the CVE-YYYY-NNNN format.')
    .optional(),
  cvssScore: z.number().min(0).max(10).optional(),
  remediation: optionalDescription(5000),
});

export const importFindingsSchema = z.object({
  findings: z
    .array(importItemSchema)
    .min(1, 'Provide at least one finding.')
    .max(500, 'Import at most 500 findings per request.'),
});

export const createIncidentSchema = z.object({
  title: z
    .string()
    .trim()
    .min(3, 'Title must be at least 3 characters.')
    .max(200, 'Title is too long.'),
  description: optionalDescription(5000),
  severity: incidentSeveritySchema,
  assignedToId: cuidLikeSchema.nullable().optional(),
  detectedAt: isoDateTimeSchema.optional(),
});

export const updateIncidentSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(3, 'Title must be at least 3 characters.')
      .max(200, 'Title is too long.')
      .optional(),
    description: optionalDescription(5000),
    severity: incidentSeveritySchema.optional(),
    assignedToId: cuidLikeSchema.nullable().optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'Provide at least one field to update.',
  });

export const changeIncidentStatusSchema = z.object({
  status: incidentStatusSchema,
  note: optionalDescription(1000),
});

export const incidentNoteSchema = z.object({
  body: z.string().trim().min(1, 'Note cannot be empty.').max(5000, 'Note is too long.'),
});

export const linkFindingsSchema = z.object({
  findingIds: z.array(cuidLikeSchema).min(1).max(50),
});

export const incidentQuerySchema = z.object({
  search: optionalShortText(),
  status: incidentStatusSchema.optional(),
  severity: incidentSeveritySchema.optional(),
  assignedToId: cuidLikeSchema.optional(),
  page: z.coerce.number().int().min(1).max(10000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  sort: z
    .enum(['createdAt', 'updatedAt', 'severity', 'status', 'title', 'detectedAt'])
    .default('createdAt'),
  direction: z.enum(['asc', 'desc']).default('desc'),
});
