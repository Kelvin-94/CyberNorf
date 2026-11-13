import { z } from 'zod';
import {
  APPROVAL_STATES,
  CONNECTOR_FAIL_MODES,
  CONNECTOR_KINDS,
  CONNECTOR_STATUSES,
  DETECTION_SEVERITIES,
  DETECTION_STATUSES,
  DEVICE_STATUSES,
  ENFORCEMENT_KINDS,
  POLICY_EFFECTS,
  POSTURE_CHECK_STATUSES,
  RELEASE_STATUSES,
  SENSITIVITIES,
  SUBJECT_KINDS,
  TRUST_STATES,
  ZONES,
  isSemver,
  isValidCidr,
} from '@/server/domain/zero-trust';
import {
  cuidLikeSchema,
  isoDateTimeSchema,
  optionalDescription,
  optionalShortText,
  paginationSchema,
  searchSchema,
} from './common';

/**
 * Input contracts for the zero trust control plane.
 *
 * Facts an operator cannot be trusted to assert are never accepted from the
 * request body: role, attributes, device trust and the zone a caller sits in
 * are all resolved server-side. What remains here is the operator's intent
 * (which subject, which resource, which action) plus the few observations only
 * the caller can supply, such as the source address and whether the session
 * carried a second factor.
 */

export const deviceStatusSchema = z.enum(DEVICE_STATUSES);
export const trustStateSchema = z.enum(TRUST_STATES);
export const policyEffectSchema = z.enum(POLICY_EFFECTS);
export const policySubjectKindSchema = z.enum(SUBJECT_KINDS);
export const sensitivitySchema = z.enum(SENSITIVITIES);
export const zoneSchema = z.enum(ZONES);
export const connectorKindSchema = z.enum(CONNECTOR_KINDS);
export const connectorStatusSchema = z.enum(CONNECTOR_STATUSES);
export const connectorFailModeSchema = z.enum(CONNECTOR_FAIL_MODES);
export const detectionSeveritySchema = z.enum(DETECTION_SEVERITIES);
export const detectionStatusSchema = z.enum(DETECTION_STATUSES);
export const enforcementKindSchema = z.enum(ENFORCEMENT_KINDS);
export const releaseStatusSchema = z.enum(RELEASE_STATUSES);
export const approvalStateSchema = z.enum(APPROVAL_STATES);
export const postureCheckStatusSchema = z.enum(POSTURE_CHECK_STATUSES);

const booleanParam = z.enum(['true', 'false']).transform((value) => value === 'true');

const ipv4Schema = z
  .string()
  .trim()
  .max(45, 'Address is too long.')
  .refine((value) => {
    const parts = value.split('.');
    return (
      parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
    );
  }, 'Enter an IPv4 address.');

const portSchema = z.coerce.number().int().min(0).max(65535);

const bytesSchema = z.coerce.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

// ---------------------------------------------------------------------------
// Devices and posture
// ---------------------------------------------------------------------------

export const registerDeviceSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, 'A device name is required.')
    .max(120, 'Device name must be 120 characters or fewer.'),
  hardwareId: z
    .string()
    .trim()
    .min(8, 'A hardware identifier of at least 8 characters is required.')
    .max(200, 'Hardware identifier must be 200 characters or fewer.')
    .regex(/^[A-Za-z0-9:_-]+$/, 'Hardware identifier has an invalid format.'),
  publicKey: z
    .string()
    .trim()
    .min(40, 'A public key is required.')
    .max(2000, 'Public key must be 2000 characters or fewer.'),
  attestationKind: z.enum(['NONE', 'TPM', 'SECURE_ENCLAVE', 'VTPM']).default('NONE'),
  attestationVerified: z.boolean().default(false),
  managed: z.boolean().default(false),
  os: optionalShortText(80),
  osVersion: optionalShortText(60),
  ownerUserId: cuidLikeSchema.nullish(),
});

export type RegisterDeviceInput = z.infer<typeof registerDeviceSchema>;

export const updateDeviceSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(1, 'A device name is required.')
      .max(120, 'Device name must be 120 characters or fewer.')
      .optional(),
    os: optionalShortText(80),
    osVersion: optionalShortText(60),
    managed: z.boolean().optional(),
    ownerUserId: cuidLikeSchema.nullish(),
    publicKey: z
      .string()
      .trim()
      .min(40, 'A public key is required.')
      .max(2000, 'Public key must be 2000 characters or fewer.')
      .optional(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Provide at least one field to update.',
  });

export type UpdateDeviceInput = z.infer<typeof updateDeviceSchema>;

export const deviceListQuerySchema = paginationSchema.extend({
  status: deviceStatusSchema.optional(),
  trustState: trustStateSchema.optional(),
  managed: booleanParam.optional(),
  q: searchSchema,
});

export type DeviceListQuery = z.infer<typeof deviceListQuerySchema>;

/**
 * Activating a device needs no justification; withdrawing one does, because the
 * reason is what a later reviewer sees when asking why a device went dark.
 */
export const deviceLifecycleSchema = z
  .object({
    action: z.enum(['activate', 'suspend', 'retire']),
    reason: optionalShortText(500),
  })
  .refine(
    (value) =>
      value.action === 'activate' ||
      (typeof value.reason === 'string' && value.reason.trim().length >= 3),
    { message: 'Suspending or retiring a device requires a reason.', path: ['reason'] },
  );

export type DeviceLifecycleInput = z.infer<typeof deviceLifecycleSchema>;

export const postureCheckSchema = z.object({
  id: z
    .string()
    .trim()
    .min(1, 'A check id is required.')
    .max(80, 'Check id must be 80 characters or fewer.')
    .regex(/^[A-Za-z0-9._-]+$/, 'Check id has an invalid format.'),
  status: postureCheckStatusSchema,
  detail: z.string().trim().max(500, 'Detail must be 500 characters or fewer.').optional(),
});

export const submitPostureSchema = z.object({
  collectedAt: isoDateTimeSchema,
  ttlSeconds: z.coerce.number().int().min(300).max(604800).optional(),
  checks: z
    .array(postureCheckSchema)
    .max(200, 'A report may contain at most 200 checks.')
    .refine(
      (checks) => new Set(checks.map((check) => check.id)).size === checks.length,
      'Check ids must be unique within a report.',
    ),
  signature: z.string().trim().min(1).max(4000).optional(),
});

export type SubmitPostureInput = z.infer<typeof submitPostureSchema>;

// ---------------------------------------------------------------------------
// Policy rules
// ---------------------------------------------------------------------------

const primitiveSchema = z.union([z.string().trim().max(200), z.number(), z.boolean()]);

const shortStringListSchema = (max: number) => z.array(z.string().trim().min(1).max(120)).max(max);

/**
 * Mirrors `PolicyConditionSet`. Unknown keys are rejected so a typo such as
 * `deviceTrustAtleast` fails to save instead of silently matching nothing and
 * turning an intended ALLOW into a default deny.
 */
export const policyConditionsSchema = z
  .object({
    roleIn: shortStringListSchema(50).optional(),
    attributeEquals: z.record(z.string().max(64), primitiveSchema).optional(),
    attributeIn: z.record(z.string().max(64), z.array(primitiveSchema).min(1).max(50)).optional(),
    deviceTrustAtLeast: trustStateSchema.optional(),
    deviceManaged: z.boolean().optional(),
    postureFresh: z.boolean().optional(),
    postureCheckPassed: shortStringListSchema(100).optional(),
    postureCheckFailed: shortStringListSchema(100).optional(),
    mfaSatisfied: z.boolean().optional(),
    zoneIn: z.array(zoneSchema).min(1).max(ZONES.length).optional(),
    connectorStatusIn: z.array(connectorStatusSchema).min(1).max(3).optional(),
    sensitivityAtLeast: sensitivitySchema.optional(),
    riskAtLeast: z.number().int().min(0).max(100).optional(),
    resourceTypeIn: shortStringListSchema(50).optional(),
    actionIn: shortStringListSchema(50).optional(),
    approvalStateIn: z.array(approvalStateSchema).min(1).max(4).optional(),
    outsideBusinessHours: z.boolean().optional(),
  })
  .strict()
  .refine(
    (value) => Object.keys(value).length > 0,
    'A rule must declare at least one condition; an empty condition set matches every request.',
  );

export type PolicyConditionsInput = z.infer<typeof policyConditionsSchema>;

const policyRuleFields = {
  name: z
    .string()
    .trim()
    .min(1, 'A rule name is required.')
    .max(120, 'Rule name must be 120 characters or fewer.'),
  description: optionalDescription(2000),
  priority: z.coerce.number().int().min(1).max(10000).default(100),
  effect: policyEffectSchema,
  enabled: z.boolean().default(true),
  conditions: policyConditionsSchema,
};

export const createPolicyRuleSchema = z.object(policyRuleFields);

export type CreatePolicyRuleInput = z.infer<typeof createPolicyRuleSchema>;

export const updatePolicyRuleSchema = z
  .object({
    name: policyRuleFields.name.optional(),
    description: policyRuleFields.description,
    priority: z.coerce.number().int().min(1).max(10000).optional(),
    effect: policyEffectSchema.optional(),
    enabled: z.boolean().optional(),
    conditions: policyConditionsSchema.optional(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Provide at least one field to update.',
  });

export type UpdatePolicyRuleInput = z.infer<typeof updatePolicyRuleSchema>;

export const policyRuleListQuerySchema = paginationSchema.extend({
  effect: policyEffectSchema.optional(),
  enabled: booleanParam.optional(),
  q: searchSchema,
});

export type PolicyRuleListQuery = z.infer<typeof policyRuleListQuerySchema>;

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export const evaluationRequestSchema = z.object({
  subject: z.object({
    kind: policySubjectKindSchema,
    id: cuidLikeSchema,
  }),
  action: z
    .string()
    .trim()
    .min(1, 'An action is required.')
    .max(120, 'Action must be 120 characters or fewer.'),
  resource: z.object({
    type: z
      .string()
      .trim()
      .min(1, 'A resource type is required.')
      .max(80, 'Resource type must be 80 characters or fewer.'),
    id: cuidLikeSchema.nullish(),
    sensitivity: sensitivitySchema,
  }),
  deviceId: cuidLikeSchema.nullish(),
  sourceAddress: ipv4Schema.nullish(),
  mfaSatisfied: z.boolean().default(false),
  approvalState: approvalStateSchema.default('NONE'),
  correlationId: z
    .string()
    .trim()
    .min(8, 'Correlation id must be at least 8 characters.')
    .max(120, 'Correlation id must be 120 characters or fewer.')
    .optional(),
});

export type EvaluationRequestInput = z.infer<typeof evaluationRequestSchema>;

export const policyDecisionListQuerySchema = paginationSchema.extend({
  verdict: policyEffectSchema.optional(),
  subjectKind: policySubjectKindSchema.optional(),
  subjectId: cuidLikeSchema.optional(),
  q: searchSchema,
});

export type PolicyDecisionListQuery = z.infer<typeof policyDecisionListQuerySchema>;

// ---------------------------------------------------------------------------
// Network connectors, segments and flows
// ---------------------------------------------------------------------------

export const createConnectorSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, 'A connector name is required.')
    .max(120, 'Connector name must be 120 characters or fewer.'),
  kind: connectorKindSchema,
  endpointUrl: z
    .url('Enter a valid endpoint URL.')
    .max(500, 'Endpoint URL must be 500 characters or fewer.')
    .optional(),
  failMode: connectorFailModeSchema.default('CLOSED'),
  capabilities: z
    .array(z.string().trim().min(1).max(60))
    .max(30, 'At most 30 capabilities can be declared.')
    .default([]),
});

export type CreateConnectorInput = z.infer<typeof createConnectorSchema>;

export const updateConnectorSchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    endpointUrl: z
      .url('Enter a valid endpoint URL.')
      .max(500, 'Endpoint URL must be 500 characters or fewer.')
      .nullish(),
    failMode: connectorFailModeSchema.optional(),
    status: connectorStatusSchema.optional(),
    capabilities: z.array(z.string().trim().min(1).max(60)).max(30).optional(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Provide at least one field to update.',
  });

export type UpdateConnectorInput = z.infer<typeof updateConnectorSchema>;

export const connectorListQuerySchema = paginationSchema.extend({
  kind: connectorKindSchema.optional(),
  status: connectorStatusSchema.optional(),
  q: searchSchema,
});

export type ConnectorListQuery = z.infer<typeof connectorListQuerySchema>;

export const connectorHeartbeatSchema = z.object({
  status: connectorStatusSchema,
});

export type ConnectorHeartbeatInput = z.infer<typeof connectorHeartbeatSchema>;

export const createSegmentSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, 'A segment name is required.')
    .max(120, 'Segment name must be 120 characters or fewer.'),
  cidr: z
    .string()
    .trim()
    .max(64, 'CIDR must be 64 characters or fewer.')
    .refine(isValidCidr, 'Enter an IPv4 CIDR such as 10.20.0.0/16.'),
  zone: zoneSchema,
  sensitivity: sensitivitySchema.default('INTERNAL'),
  connectorId: cuidLikeSchema.nullish(),
});

export type CreateSegmentInput = z.infer<typeof createSegmentSchema>;

export const updateSegmentSchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    cidr: z.string().trim().max(64).refine(isValidCidr, 'Enter an IPv4 CIDR.').optional(),
    zone: zoneSchema.optional(),
    sensitivity: sensitivitySchema.optional(),
    connectorId: cuidLikeSchema.nullish(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Provide at least one field to update.',
  });

export type UpdateSegmentInput = z.infer<typeof updateSegmentSchema>;

export const segmentListQuerySchema = paginationSchema.extend({
  zone: zoneSchema.optional(),
  q: searchSchema,
});

export type SegmentListQuery = z.infer<typeof segmentListQuerySchema>;

export const flowInputSchema = z.object({
  sourceAddress: ipv4Schema,
  sourcePort: portSchema.nullish(),
  destinationAddress: ipv4Schema,
  destinationPort: portSchema.nullish(),
  protocol: z
    .string()
    .trim()
    .min(1, 'A protocol is required.')
    .max(16)
    .transform((value) => value.toUpperCase()),
  bytes: bytesSchema.default(0),
  observedAt: isoDateTimeSchema,
});

/**
 * One ingestion batch. Bounded so a single connector cannot flood the table,
 * and the window is capped because detections only reason about a batch.
 */
export const ingestFlowsSchema = z.object({
  connectorId: cuidLikeSchema.nullish(),
  flows: z
    .array(flowInputSchema)
    .min(1, 'At least one flow is required.')
    .max(500, 'A batch may contain at most 500 flows.'),
});

export type IngestFlowsInput = z.infer<typeof ingestFlowsSchema>;

export const flowListQuerySchema = paginationSchema.extend({
  sourceAddress: ipv4Schema.optional(),
  destinationAddress: ipv4Schema.optional(),
  protocol: z.string().trim().max(16).optional(),
  since: isoDateTimeSchema.optional(),
});

export type FlowListQuery = z.infer<typeof flowListQuerySchema>;

export const detectionListQuerySchema = paginationSchema.extend({
  status: detectionStatusSchema.optional(),
  severity: detectionSeveritySchema.optional(),
  ruleKey: z.string().trim().max(80).optional(),
  q: searchSchema,
});

export type DetectionListQuery = z.infer<typeof detectionListQuerySchema>;

export const updateDetectionSchema = z.object({
  status: detectionStatusSchema,
  note: optionalShortText(500),
});

export type UpdateDetectionInput = z.infer<typeof updateDetectionSchema>;

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

export const admissionRequestSchema = z.object({
  deviceId: cuidLikeSchema,
  subject: z.object({
    kind: policySubjectKindSchema,
    id: cuidLikeSchema,
  }),
  action: z.string().trim().min(1).max(120).default('network.admit'),
  requestedZone: zoneSchema,
  sourceAddress: ipv4Schema.nullish(),
  connectorId: cuidLikeSchema.nullish(),
  mfaSatisfied: z.boolean().default(false),
  resource: z
    .object({
      type: z.string().trim().min(1).max(80).default('network_segment'),
      id: cuidLikeSchema.nullish(),
      sensitivity: sensitivitySchema.default('INTERNAL'),
    })
    .default({ type: 'network_segment', sensitivity: 'INTERNAL' }),
});

export type AdmissionRequestInput = z.infer<typeof admissionRequestSchema>;

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

const enforcementPayloadValueSchema = z.union([
  z.string().trim().max(500),
  z.number(),
  z.boolean(),
]);

export const requestEnforcementSchema = z.object({
  kind: enforcementKindSchema,
  targetType: z
    .string()
    .trim()
    .min(1, 'A target type is required.')
    .max(60, 'Target type must be 60 characters or fewer.'),
  targetId: cuidLikeSchema,
  targetLabel: z
    .string()
    .trim()
    .min(1, 'A target label is required.')
    .max(200, 'Target label must be 200 characters or fewer.'),
  connectorId: cuidLikeSchema.nullish(),
  payload: z.record(z.string().max(64), enforcementPayloadValueSchema).default({}),
  idempotencyKey: z
    .string()
    .trim()
    .min(8, 'Idempotency key must be at least 8 characters.')
    .max(120, 'Idempotency key must be 120 characters or fewer.')
    .regex(/^[A-Za-z0-9:_-]+$/, 'Idempotency key has an invalid format.'),
  reason: optionalShortText(500),
  expiresInSeconds: z.coerce.number().int().min(60).max(86400).default(3600),
});

export type RequestEnforcementInput = z.infer<typeof requestEnforcementSchema>;

export const enforcementActionQuerySchema = paginationSchema.extend({
  state: z
    .enum([
      'REQUESTED',
      'APPROVED',
      'REJECTED',
      'DISPATCHED',
      'ACKNOWLEDGED',
      'VERIFIED',
      'FAILED',
      'EXPIRED',
    ])
    .optional(),
  kind: enforcementKindSchema.optional(),
  q: searchSchema,
});

export type EnforcementActionQuery = z.infer<typeof enforcementActionQuerySchema>;

export const approveEnforcementSchema = z.object({
  note: optionalShortText(500),
});

export const rejectEnforcementSchema = z.object({
  reason: z
    .string()
    .trim()
    .min(1, 'A rejection reason is required.')
    .max(500, 'Reason must be 500 characters or fewer.'),
});

export const enforcementResultSchema = z.object({
  result: z.record(z.string().max(64), enforcementPayloadValueSchema).default({}),
});

export const failEnforcementSchema = z.object({
  reason: z
    .string()
    .trim()
    .min(1, 'A failure reason is required.')
    .max(500, 'Failure reason must be 500 characters or fewer.'),
});

// ---------------------------------------------------------------------------
// Secure updates
// ---------------------------------------------------------------------------

const versionSchema = z
  .string()
  .trim()
  .max(64, 'Version must be 64 characters or fewer.')
  .refine(isSemver, 'Enter a semantic version such as 2.4.1.');

export const compatibilitySchema = z
  .object({
    os: z.array(z.string().trim().min(1).max(40)).max(10).default([]),
    minOsVersion: versionSchema.nullish(),
    maxOsVersion: versionSchema.nullish(),
  })
  .default({ os: [], minOsVersion: null, maxOsVersion: null });

export type CompatibilityInput = z.infer<typeof compatibilitySchema>;

export const publishReleaseSchema = z.object({
  product: z
    .string()
    .trim()
    .min(1, 'A product is required.')
    .max(80, 'Product must be 80 characters or fewer.')
    .regex(/^[a-z0-9][a-z0-9._-]*$/, 'Product must be a lowercase slug.'),
  version: versionSchema,
  channel: z
    .string()
    .trim()
    .min(1)
    .max(40)
    .regex(/^[a-z][a-z0-9_-]*$/, 'Channel must be a lowercase slug.')
    .default('stable'),
  artifactUrl: z
    .url('Enter a valid artifact URL.')
    .max(1000, 'Artifact URL must be 1000 characters or fewer.')
    .refine((value) => value.startsWith('https://'), 'Artifacts must be fetched over HTTPS.'),
  sha256: z
    .string()
    .trim()
    .length(64, 'A SHA-256 digest is 64 hexadecimal characters.')
    .regex(/^[0-9a-fA-F]{64}$/, 'Digest must be hexadecimal.'),
  manifestSignature: z
    .string()
    .trim()
    .min(40, 'A manifest signature is required.')
    .max(4000, 'Signature must be 4000 characters or fewer.'),
  publisherKeyId: z
    .string()
    .trim()
    .min(1, 'A publisher key id is required.')
    .max(80, 'Publisher key id must be 80 characters or fewer.'),
  minVersion: versionSchema.nullish(),
  compatibility: compatibilitySchema,
  canaryPercent: z.coerce.number().int().min(1).max(100).default(10),
});

export type PublishReleaseInput = z.infer<typeof publishReleaseSchema>;

export const releaseListQuerySchema = paginationSchema.extend({
  product: z.string().trim().max(80).optional(),
  status: releaseStatusSchema.optional(),
  q: searchSchema,
});

export type ReleaseListQuery = z.infer<typeof releaseListQuerySchema>;

export const advanceReleaseSchema = z.object({
  to: z.enum(['CANARY', 'ROLLING', 'RELEASED']),
  canaryPercent: z.coerce.number().int().min(1).max(100).optional(),
});

export type AdvanceReleaseInput = z.infer<typeof advanceReleaseSchema>;

export const rollbackReleaseSchema = z.object({
  reason: z
    .string()
    .trim()
    .min(1, 'A rollback reason is required.')
    .max(500, 'Reason must be 500 characters or fewer.'),
});

export const offerUpdateSchema = z.object({
  deviceIds: z
    .array(cuidLikeSchema)
    .min(1, 'Select at least one device.')
    .max(500, 'At most 500 devices can be targeted at once.'),
});

export type OfferUpdateInput = z.infer<typeof offerUpdateSchema>;

export const deviceUpdateStateSchema = z.enum([
  'DOWNLOADING',
  'INSTALLING',
  'INSTALLED',
  'FAILED',
  'ROLLED_BACK',
]);

export const recordUpdateResultSchema = z.object({
  deviceId: cuidLikeSchema,
  state: deviceUpdateStateSchema,
  result: z.record(z.string().max(64), enforcementPayloadValueSchema).optional(),
  version: versionSchema.optional(),
});

export type RecordUpdateResultInput = z.infer<typeof recordUpdateResultSchema>;

export const updateListQuerySchema = paginationSchema.extend({
  deviceId: cuidLikeSchema.optional(),
  releaseId: cuidLikeSchema.optional(),
  state: z
    .enum(['OFFERED', 'DOWNLOADING', 'INSTALLING', 'INSTALLED', 'FAILED', 'ROLLED_BACK'])
    .optional(),
});

export type UpdateListQuery = z.infer<typeof updateListQuerySchema>;

export const checkUpdateSchema = z.object({
  deviceId: cuidLikeSchema,
  product: z.string().trim().min(1).max(80),
  channel: z.string().trim().min(1).max(40).default('stable'),
  currentVersion: versionSchema,
  os: z.string().trim().min(1).max(40),
  osVersion: versionSchema,
});

export type CheckUpdateInput = z.infer<typeof checkUpdateSchema>;
