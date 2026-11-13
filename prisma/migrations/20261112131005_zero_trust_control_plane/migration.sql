-- CreateEnum
CREATE TYPE "DeviceStatus" AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'RETIRED');

-- CreateEnum
CREATE TYPE "DeviceTrustState" AS ENUM ('UNTRUSTED', 'UNKNOWN', 'PARTIAL', 'TRUSTED');

-- CreateEnum
CREATE TYPE "PolicySubjectKind" AS ENUM ('USER', 'DEVICE', 'IDENTITY');

-- CreateEnum
CREATE TYPE "PolicyEffect" AS ENUM ('ALLOW', 'DENY', 'STEP_UP', 'QUARANTINE');

-- CreateEnum
CREATE TYPE "ResourceSensitivity" AS ENUM ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED');

-- CreateEnum
CREATE TYPE "NetworkConnectorKind" AS ENUM ('RADIUS', 'GATEWAY', 'FIREWALL', 'EDR', 'SWITCH');

-- CreateEnum
CREATE TYPE "ConnectorStatus" AS ENUM ('ONLINE', 'DEGRADED', 'OFFLINE');

-- CreateEnum
CREATE TYPE "ConnectorFailMode" AS ENUM ('CLOSED', 'OPEN');

-- CreateEnum
CREATE TYPE "NetworkZone" AS ENUM ('CORPORATE', 'GUEST', 'OT', 'QUARANTINE', 'EXTERNAL');

-- CreateEnum
CREATE TYPE "DetectionSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "DetectionStatus" AS ENUM ('OPEN', 'ACKNOWLEDGED', 'CLOSED');

-- CreateEnum
CREATE TYPE "EnforcementKind" AS ENUM ('SESSION_REVOKE', 'ENDPOINT_ISOLATE', 'NETWORK_QUARANTINE', 'FIREWALL_BLOCK', 'CERT_REVOKE');

-- CreateEnum
CREATE TYPE "EnforcementState" AS ENUM ('REQUESTED', 'APPROVED', 'REJECTED', 'DISPATCHED', 'ACKNOWLEDGED', 'VERIFIED', 'FAILED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "ReleaseStatus" AS ENUM ('DRAFT', 'CANARY', 'ROLLING', 'RELEASED', 'ROLLED_BACK');

-- CreateEnum
CREATE TYPE "DeviceUpdateState" AS ENUM ('OFFERED', 'DOWNLOADING', 'INSTALLING', 'INSTALLED', 'FAILED', 'ROLLED_BACK');

-- AlterTable
ALTER TABLE "memberships" ADD COLUMN     "attributes" JSONB;

-- CreateTable
CREATE TABLE "devices" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "hardwareId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "keyAlgorithm" TEXT NOT NULL DEFAULT 'ed25519',
    "attestationKind" TEXT NOT NULL DEFAULT 'NONE',
    "attestationVerified" BOOLEAN NOT NULL DEFAULT false,
    "managed" BOOLEAN NOT NULL DEFAULT false,
    "os" TEXT,
    "osVersion" TEXT,
    "status" "DeviceStatus" NOT NULL DEFAULT 'PENDING',
    "trustState" "DeviceTrustState" NOT NULL DEFAULT 'UNKNOWN',
    "trustScore" INTEGER NOT NULL DEFAULT 0,
    "ownerUserId" TEXT,
    "lastSeenAt" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_posture_reports" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "collectedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "signature" TEXT,
    "signatureVerified" BOOLEAN NOT NULL DEFAULT false,
    "checks" JSONB NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'AGENT',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_posture_reports_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "policy_rules" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "effect" "PolicyEffect" NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "conditions" JSONB NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "policy_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "policy_decisions" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "correlationId" TEXT NOT NULL,
    "subjectKind" "PolicySubjectKind" NOT NULL,
    "subjectId" TEXT NOT NULL,
    "subjectLabel" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT,
    "resourceSensitivity" "ResourceSensitivity" NOT NULL,
    "action" TEXT NOT NULL,
    "verdict" "PolicyEffect" NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "matchedRuleId" TEXT,
    "requestContext" JSONB NOT NULL,
    "facts" JSONB NOT NULL,
    "explanation" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "policy_decisions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "network_connectors" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" "NetworkConnectorKind" NOT NULL,
    "endpointUrl" TEXT,
    "tokenHash" TEXT NOT NULL,
    "status" "ConnectorStatus" NOT NULL DEFAULT 'OFFLINE',
    "failMode" "ConnectorFailMode" NOT NULL DEFAULT 'CLOSED',
    "capabilities" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "lastHeartbeatAt" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "network_connectors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "network_segments" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "cidr" TEXT NOT NULL,
    "zone" "NetworkZone" NOT NULL,
    "sensitivity" "ResourceSensitivity" NOT NULL DEFAULT 'INTERNAL',
    "connectorId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "network_segments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "network_flows" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "connectorId" TEXT,
    "sourceAddress" TEXT NOT NULL,
    "sourcePort" INTEGER,
    "destinationAddress" TEXT NOT NULL,
    "destinationPort" INTEGER,
    "protocol" TEXT NOT NULL,
    "bytes" INTEGER NOT NULL DEFAULT 0,
    "observedAt" TIMESTAMP(3) NOT NULL,
    "deviceId" TEXT,
    "segmentId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "network_flows_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "network_detections" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "ruleKey" TEXT NOT NULL,
    "subjectKey" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "DetectionSeverity" NOT NULL,
    "status" "DetectionStatus" NOT NULL DEFAULT 'OPEN',
    "deviceId" TEXT,
    "observations" JSONB NOT NULL,
    "freshUntil" TIMESTAMP(3) NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "network_detections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "enforcement_actions" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "kind" "EnforcementKind" NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "targetLabel" TEXT NOT NULL,
    "connectorId" TEXT,
    "payload" JSONB NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "state" "EnforcementState" NOT NULL DEFAULT 'REQUESTED',
    "requestedById" TEXT NOT NULL,
    "approvedById" TEXT,
    "rejectedReason" TEXT,
    "dispatchedAt" TIMESTAMP(3),
    "acknowledgedAt" TIMESTAMP(3),
    "verifiedAt" TIMESTAMP(3),
    "failureReason" TEXT,
    "result" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "enforcement_actions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "software_releases" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "product" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "channel" TEXT NOT NULL DEFAULT 'stable',
    "artifactUrl" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "manifest" JSONB NOT NULL,
    "manifestSignature" TEXT NOT NULL,
    "publisherKeyId" TEXT NOT NULL,
    "minVersion" TEXT,
    "compatibility" JSONB NOT NULL,
    "status" "ReleaseStatus" NOT NULL DEFAULT 'DRAFT',
    "canaryPercent" INTEGER NOT NULL DEFAULT 0,
    "createdById" TEXT,
    "releasedAt" TIMESTAMP(3),
    "rolledBackAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "software_releases_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_updates" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "releaseId" TEXT NOT NULL,
    "state" "DeviceUpdateState" NOT NULL DEFAULT 'OFFERED',
    "offeredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "installedAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "result" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "device_updates_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "devices_organizationId_trustState_idx" ON "devices"("organizationId", "trustState");

-- CreateIndex
CREATE INDEX "devices_organizationId_status_idx" ON "devices"("organizationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "devices_organizationId_hardwareId_key" ON "devices"("organizationId", "hardwareId");

-- CreateIndex
CREATE INDEX "device_posture_reports_deviceId_collectedAt_idx" ON "device_posture_reports"("deviceId", "collectedAt");

-- CreateIndex
CREATE INDEX "device_posture_reports_organizationId_expiresAt_idx" ON "device_posture_reports"("organizationId", "expiresAt");

-- CreateIndex
CREATE INDEX "policy_rules_organizationId_enabled_priority_idx" ON "policy_rules"("organizationId", "enabled", "priority");

-- CreateIndex
CREATE UNIQUE INDEX "policy_rules_organizationId_name_key" ON "policy_rules"("organizationId", "name");

-- CreateIndex
CREATE INDEX "policy_decisions_organizationId_createdAt_idx" ON "policy_decisions"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "policy_decisions_organizationId_verdict_createdAt_idx" ON "policy_decisions"("organizationId", "verdict", "createdAt");

-- CreateIndex
CREATE INDEX "policy_decisions_organizationId_subjectKind_subjectId_creat_idx" ON "policy_decisions"("organizationId", "subjectKind", "subjectId", "createdAt");

-- CreateIndex
CREATE INDEX "network_connectors_organizationId_status_idx" ON "network_connectors"("organizationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "network_connectors_organizationId_name_key" ON "network_connectors"("organizationId", "name");

-- CreateIndex
CREATE INDEX "network_segments_organizationId_zone_idx" ON "network_segments"("organizationId", "zone");

-- CreateIndex
CREATE UNIQUE INDEX "network_segments_organizationId_name_key" ON "network_segments"("organizationId", "name");

-- CreateIndex
CREATE INDEX "network_flows_organizationId_observedAt_idx" ON "network_flows"("organizationId", "observedAt");

-- CreateIndex
CREATE INDEX "network_flows_organizationId_sourceAddress_observedAt_idx" ON "network_flows"("organizationId", "sourceAddress", "observedAt");

-- CreateIndex
CREATE INDEX "network_detections_organizationId_status_severity_idx" ON "network_detections"("organizationId", "status", "severity");

-- CreateIndex
CREATE INDEX "network_detections_organizationId_lastSeenAt_idx" ON "network_detections"("organizationId", "lastSeenAt");

-- CreateIndex
CREATE UNIQUE INDEX "network_detections_organizationId_ruleKey_subjectKey_key" ON "network_detections"("organizationId", "ruleKey", "subjectKey");

-- CreateIndex
CREATE INDEX "enforcement_actions_organizationId_state_createdAt_idx" ON "enforcement_actions"("organizationId", "state", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "enforcement_actions_organizationId_idempotencyKey_key" ON "enforcement_actions"("organizationId", "idempotencyKey");

-- CreateIndex
CREATE INDEX "software_releases_organizationId_product_status_idx" ON "software_releases"("organizationId", "product", "status");

-- CreateIndex
CREATE UNIQUE INDEX "software_releases_organizationId_product_version_key" ON "software_releases"("organizationId", "product", "version");

-- CreateIndex
CREATE INDEX "device_updates_organizationId_state_idx" ON "device_updates"("organizationId", "state");

-- CreateIndex
CREATE UNIQUE INDEX "device_updates_deviceId_releaseId_key" ON "device_updates"("deviceId", "releaseId");

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_posture_reports" ADD CONSTRAINT "device_posture_reports_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_posture_reports" ADD CONSTRAINT "device_posture_reports_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policy_rules" ADD CONSTRAINT "policy_rules_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policy_decisions" ADD CONSTRAINT "policy_decisions_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_connectors" ADD CONSTRAINT "network_connectors_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_segments" ADD CONSTRAINT "network_segments_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_segments" ADD CONSTRAINT "network_segments_connectorId_fkey" FOREIGN KEY ("connectorId") REFERENCES "network_connectors"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_flows" ADD CONSTRAINT "network_flows_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_flows" ADD CONSTRAINT "network_flows_connectorId_fkey" FOREIGN KEY ("connectorId") REFERENCES "network_connectors"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_flows" ADD CONSTRAINT "network_flows_segmentId_fkey" FOREIGN KEY ("segmentId") REFERENCES "network_segments"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_detections" ADD CONSTRAINT "network_detections_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "enforcement_actions" ADD CONSTRAINT "enforcement_actions_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "enforcement_actions" ADD CONSTRAINT "enforcement_actions_connectorId_fkey" FOREIGN KEY ("connectorId") REFERENCES "network_connectors"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "software_releases" ADD CONSTRAINT "software_releases_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_updates" ADD CONSTRAINT "device_updates_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_updates" ADD CONSTRAINT "device_updates_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_updates" ADD CONSTRAINT "device_updates_releaseId_fkey" FOREIGN KEY ("releaseId") REFERENCES "software_releases"("id") ON DELETE CASCADE ON UPDATE CASCADE;
