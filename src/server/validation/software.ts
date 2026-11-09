import { z } from 'zod';
import { PACKAGE_ECOSYSTEMS } from '@/server/domain/software';
import { isValidVersionRange } from '@/server/domain/versions';
import { cuidLikeSchema, isoDateTimeSchema, optionalShortText, searchSchema } from './common';

export const packageEcosystemSchema = z.enum(PACKAGE_ECOSYSTEMS);

/**
 * Packages a single run may report. An inventory large enough to describe a
 * desktop is well under this; the cap keeps one payload from turning into an
 * unbounded write.
 */
export const MAX_INVENTORY_ITEMS = 800;

/** Advisories accepted in one import. Operators paste feeds in batches. */
export const MAX_ADVISORIES_PER_IMPORT = 500;

const packageNameSchema = z
  .string()
  .trim()
  .min(1, 'Package name is required.')
  .max(200, 'Package name must be 200 characters or fewer.')
  .regex(
    /^[A-Za-z0-9@][A-Za-z0-9@._+/:-]*$/,
    'Use the package name exactly as the package manager reports it.',
  );

/**
 * One package observed on a host. The name and version are matched verbatim
 * against imported advisories, so they are kept to printable identifiers.
 */
export const softwareItemSchema = z
  .object({
    ecosystem: packageEcosystemSchema,
    name: packageNameSchema,
    version: z
      .string()
      .trim()
      .min(1, 'Package version is required.')
      .max(100, 'Package version must be 100 characters or fewer.')
      .regex(/^[0-9A-Za-z][0-9A-Za-z.+~:_-]*$/, 'Use the version string as reported.'),
  })
  .strict();

export type SoftwareItemInput = z.infer<typeof softwareItemSchema>;

const advisoryIdentifierSchema = z
  .string()
  .trim()
  .min(3, 'Advisory identifier is required.')
  .max(64, 'Advisory identifier must be 64 characters or fewer.')
  .regex(/^[A-Za-z][A-Za-z0-9._:-]*$/, 'Use a published identifier such as CVE-2024-3094.');

/**
 * One advisory row. `affectedRange` is validated with the same parser that the
 * matcher uses, so an advisory cannot be stored with a range the platform
 * would silently treat as "no versions affected".
 */
export const advisorySchema = z
  .object({
    identifier: advisoryIdentifierSchema,
    packageName: packageNameSchema,
    ecosystem: packageEcosystemSchema,
    summary: z.string().trim().min(3, 'Summary is required.').max(300),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
    affectedRange: z
      .string()
      .trim()
      .min(1, 'Affected range is required.')
      .max(200, 'Affected range must be 200 characters or fewer.')
      .refine(isValidVersionRange, {
        message: 'Use a version range such as ">= 1.2.0, < 1.2.9" or "^2.0.0".',
      }),
    fixedVersion: optionalShortText(100),
    cvssScore: z.number().min(0).max(10).optional(),
    referenceUrl: z.url().max(500).optional(),
    publishedAt: isoDateTimeSchema.optional(),
  })
  .strict();

export type AdvisoryInput = z.infer<typeof advisorySchema>;

export const advisoryImportSchema = z
  .object({
    advisories: z
      .array(advisorySchema)
      .min(1, 'Provide at least one advisory.')
      .max(MAX_ADVISORIES_PER_IMPORT, `Import at most ${MAX_ADVISORIES_PER_IMPORT} advisories.`),
  })
  .strict()
  .superRefine((value, ctx) => {
    const seen = new Set<string>();
    value.advisories.forEach((advisory, index) => {
      const key = `${advisory.identifier}::${advisory.packageName}`;
      if (seen.has(key)) {
        ctx.addIssue({
          code: 'custom',
          path: ['advisories', index, 'identifier'],
          message: `Advisory ${advisory.identifier} for ${advisory.packageName} appears twice in this import.`,
        });
      }
      seen.add(key);
    });
  });

export type AdvisoryImportInput = z.infer<typeof advisoryImportSchema>;

export const advisoryQuerySchema = z.object({
  search: searchSchema,
  ecosystem: packageEcosystemSchema.optional(),
  page: z.coerce.number().int().min(1).max(10000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});

export const advisoryIdParamSchema = z.object({ advisoryId: cuidLikeSchema });
