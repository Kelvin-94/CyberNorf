import { z } from 'zod';
import { emailSchema, optionalDescription, optionalShortText } from './common';

const slugSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(2, 'Slug must be at least 2 characters.')
  .max(40, 'Slug must be 40 characters or fewer.')
  .regex(
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/,
    'Use lowercase letters, numbers, and single hyphens.',
  );

export const createOrganizationSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, 'Name must be at least 2 characters.')
    .max(80, 'Name is too long.'),
  slug: slugSchema.optional(),
  description: optionalDescription(500),
});

export const updateOrganizationSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(2, 'Name must be at least 2 characters.')
      .max(80, 'Name is too long.')
      .optional(),
    description: optionalDescription(500),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'Provide at least one field to update.',
  });

export const addMemberSchema = z.object({
  email: emailSchema,
  role: z.enum(['ADMIN', 'ANALYST', 'VIEWER']),
});

export const changeMemberRoleSchema = z.object({
  role: z.enum(['OWNER', 'ADMIN', 'ANALYST', 'VIEWER']),
});

export const assetTypeSchema = z.enum([
  'DOMAIN',
  'IP_ADDRESS',
  'CIDR',
  'HOSTNAME',
  'WEB_APPLICATION',
  'CLOUD_ACCOUNT',
  'OTHER',
]);

export const assetCriticalitySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export const assetStatusSchema = z.enum(['ACTIVE', 'INACTIVE', 'RETIRED']);

const identifierSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(1, 'Identifier is required.')
  .max(255, 'Identifier is too long.')
  .refine((value) => !/[\s<>"'`\\]/.test(value), 'Identifier contains unsupported characters.');

export const createAssetSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, 'Name must be at least 2 characters.')
    .max(120, 'Name is too long.'),
  type: assetTypeSchema,
  identifier: identifierSchema,
  description: optionalDescription(2000),
  criticality: assetCriticalitySchema.default('MEDIUM'),
  status: assetStatusSchema.default('ACTIVE'),
});

export const updateAssetSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(2, 'Name must be at least 2 characters.')
      .max(120, 'Name is too long.')
      .optional(),
    type: assetTypeSchema.optional(),
    identifier: identifierSchema.optional(),
    description: optionalDescription(2000),
    criticality: assetCriticalitySchema.optional(),
    status: assetStatusSchema.optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'Provide at least one field to update.',
  });

export const assetQuerySchema = z.object({
  search: optionalShortText(),
  type: assetTypeSchema.optional(),
  status: assetStatusSchema.optional(),
  criticality: assetCriticalitySchema.optional(),
  page: z.coerce.number().int().min(1).max(10000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  sort: z.enum(['name', 'createdAt', 'updatedAt', 'criticality']).default('createdAt'),
  direction: z.enum(['asc', 'desc']).default('desc'),
});
