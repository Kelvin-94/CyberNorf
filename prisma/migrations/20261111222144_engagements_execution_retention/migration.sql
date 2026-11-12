-- CreateEnum
CREATE TYPE "EngagementStatus" AS ENUM ('DRAFT', 'ACTIVE', 'PAUSED', 'CLOSED');

-- CreateEnum
CREATE TYPE "ScopeEntryKind" AS ENUM ('INCLUDE', 'EXCLUDE');

-- CreateEnum
CREATE TYPE "ScopeTargetType" AS ENUM ('DOMAIN', 'IP_ADDRESS', 'CIDR', 'URL');

-- CreateEnum
CREATE TYPE "AuthorizationStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED');

-- CreateEnum
CREATE TYPE "ExecutionCapability" AS ENUM ('DNS_LOOKUP', 'HTTP_PROBE', 'TLS_INSPECTION', 'PORT_SCAN');

-- CreateEnum
CREATE TYPE "ExecutionRisk" AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- CreateEnum
CREATE TYPE "ExecutionJobStatus" AS ENUM ('PENDING_REVIEW', 'QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'DENIED');

-- CreateEnum
CREATE TYPE "ExecutionReviewStatus" AS ENUM ('NOT_REQUIRED', 'PENDING', 'APPROVED', 'REJECTED');

-- CreateEnum
CREATE TYPE "ExecutionWorkerStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'RETIRED');

-- CreateEnum
CREATE TYPE "ExecutionEventType" AS ENUM ('REQUESTED', 'REVIEW_REQUESTED', 'REVIEW_APPROVED', 'REVIEW_REJECTED', 'DISPATCH_DENIED', 'EXECUTION_DENIED', 'QUEUED', 'STARTED', 'COMPLETED', 'FAILED', 'CANCELLED');

-- AlterTable
ALTER TABLE "access_reviews" ADD COLUMN     "reviewerId" TEXT;

-- CreateTable
CREATE TABLE "engagements" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "status" "EngagementStatus" NOT NULL DEFAULT 'DRAFT',
    "startsAt" TIMESTAMP(3) NOT NULL,
    "endsAt" TIMESTAMP(3) NOT NULL,
    "closedAt" TIMESTAMP(3),
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "engagements_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "engagement_scope_entries" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "kind" "ScopeEntryKind" NOT NULL,
    "targetType" "ScopeTargetType" NOT NULL,
    "value" TEXT NOT NULL,
    "note" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "engagement_scope_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "engagement_authorizations" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "status" "AuthorizationStatus" NOT NULL DEFAULT 'PENDING',
    "reference" TEXT,
    "conditions" TEXT,
    "requestedById" TEXT NOT NULL,
    "decidedById" TEXT,
    "decidedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revokedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "engagement_authorizations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "execution_workers" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" "ExecutionWorkerStatus" NOT NULL DEFAULT 'ACTIVE',
    "isolated" BOOLEAN NOT NULL DEFAULT false,
    "egressAllowlist" TEXT[],
    "attestationRef" TEXT,
    "lastHeartbeatAt" TIMESTAMP(3),
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "execution_workers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "execution_jobs" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "engagementId" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "workerId" TEXT,
    "capability" "ExecutionCapability" NOT NULL,
    "targetType" "ScopeTargetType" NOT NULL,
    "targetValue" TEXT NOT NULL,
    "requestedById" TEXT NOT NULL,
    "risk" "ExecutionRisk" NOT NULL,
    "reviewStatus" "ExecutionReviewStatus" NOT NULL DEFAULT 'NOT_REQUIRED',
    "reviewedById" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "status" "ExecutionJobStatus" NOT NULL DEFAULT 'QUEUED',
    "approvedAddresses" TEXT[],
    "limits" JSONB NOT NULL,
    "denialReason" TEXT,
    "cancelRequestedAt" TIMESTAMP(3),
    "cancelledById" TEXT,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "execution_jobs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "execution_job_events" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "jobId" TEXT NOT NULL,
    "type" "ExecutionEventType" NOT NULL,
    "message" TEXT NOT NULL,
    "metadata" JSONB,
    "actorId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "execution_job_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organization_retention_policies" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "agentRunDays" INTEGER NOT NULL DEFAULT 90,
    "notificationEventDays" INTEGER NOT NULL DEFAULT 90,
    "softwareItemDays" INTEGER NOT NULL DEFAULT 180,
    "executionJobDays" INTEGER NOT NULL DEFAULT 180,
    "updatedById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organization_retention_policies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "engagements_organizationId_status_endsAt_idx" ON "engagements"("organizationId", "status", "endsAt");

-- CreateIndex
CREATE UNIQUE INDEX "engagements_organizationId_name_key" ON "engagements"("organizationId", "name");

-- CreateIndex
CREATE INDEX "engagement_scope_entries_organizationId_idx" ON "engagement_scope_entries"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "engagement_scope_entries_engagementId_kind_targetType_value_key" ON "engagement_scope_entries"("engagementId", "kind", "targetType", "value");

-- CreateIndex
CREATE INDEX "engagement_authorizations_engagementId_status_idx" ON "engagement_authorizations"("engagementId", "status");

-- CreateIndex
CREATE INDEX "engagement_authorizations_organizationId_expiresAt_idx" ON "engagement_authorizations"("organizationId", "expiresAt");

-- CreateIndex
CREATE INDEX "execution_workers_organizationId_status_lastHeartbeatAt_idx" ON "execution_workers"("organizationId", "status", "lastHeartbeatAt");

-- CreateIndex
CREATE UNIQUE INDEX "execution_workers_organizationId_name_key" ON "execution_workers"("organizationId", "name");

-- CreateIndex
CREATE INDEX "execution_jobs_organizationId_status_createdAt_idx" ON "execution_jobs"("organizationId", "status", "createdAt");

-- CreateIndex
CREATE INDEX "execution_jobs_engagementId_status_idx" ON "execution_jobs"("engagementId", "status");

-- CreateIndex
CREATE INDEX "execution_jobs_workerId_status_idx" ON "execution_jobs"("workerId", "status");

-- CreateIndex
CREATE INDEX "execution_job_events_jobId_createdAt_idx" ON "execution_job_events"("jobId", "createdAt");

-- CreateIndex
CREATE INDEX "execution_job_events_organizationId_createdAt_idx" ON "execution_job_events"("organizationId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "organization_retention_policies_organizationId_key" ON "organization_retention_policies"("organizationId");

-- AddForeignKey
ALTER TABLE "access_reviews" ADD CONSTRAINT "access_reviews_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagements" ADD CONSTRAINT "engagements_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagements" ADD CONSTRAINT "engagements_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_scope_entries" ADD CONSTRAINT "engagement_scope_entries_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_scope_entries" ADD CONSTRAINT "engagement_scope_entries_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "engagements"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_scope_entries" ADD CONSTRAINT "engagement_scope_entries_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_authorizations" ADD CONSTRAINT "engagement_authorizations_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_authorizations" ADD CONSTRAINT "engagement_authorizations_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "engagements"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_authorizations" ADD CONSTRAINT "engagement_authorizations_requestedById_fkey" FOREIGN KEY ("requestedById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_authorizations" ADD CONSTRAINT "engagement_authorizations_decidedById_fkey" FOREIGN KEY ("decidedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "engagement_authorizations" ADD CONSTRAINT "engagement_authorizations_revokedById_fkey" FOREIGN KEY ("revokedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_workers" ADD CONSTRAINT "execution_workers_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_workers" ADD CONSTRAINT "execution_workers_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_engagementId_fkey" FOREIGN KEY ("engagementId") REFERENCES "engagements"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_authorizationId_fkey" FOREIGN KEY ("authorizationId") REFERENCES "engagement_authorizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_workerId_fkey" FOREIGN KEY ("workerId") REFERENCES "execution_workers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_requestedById_fkey" FOREIGN KEY ("requestedById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_reviewedById_fkey" FOREIGN KEY ("reviewedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_jobs" ADD CONSTRAINT "execution_jobs_cancelledById_fkey" FOREIGN KEY ("cancelledById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_job_events" ADD CONSTRAINT "execution_job_events_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_job_events" ADD CONSTRAINT "execution_job_events_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "execution_jobs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_job_events" ADD CONSTRAINT "execution_job_events_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_retention_policies" ADD CONSTRAINT "organization_retention_policies_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_retention_policies" ADD CONSTRAINT "organization_retention_policies_updatedById_fkey" FOREIGN KEY ("updatedById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- An engagement window must be ordered. A zero-length or inverted window could
-- otherwise be activated and then never authorize anything, which reads as a
-- broken control rather than a bad request.
ALTER TABLE "engagements"
  ADD CONSTRAINT "engagements_window_check" CHECK ("endsAt" > "startsAt");

-- An approval cannot be created already expired.
ALTER TABLE "engagement_authorizations"
  ADD CONSTRAINT "engagement_authorizations_expiry_check" CHECK ("expiresAt" > "createdAt");

-- Tenant retention is bounded so one bad value cannot purge everything younger
-- than a day or retain beyond a decade.
ALTER TABLE "organization_retention_policies"
  ADD CONSTRAINT "organization_retention_policies_days_check" CHECK (
    "agentRunDays" BETWEEN 1 AND 3650
    AND "notificationEventDays" BETWEEN 1 AND 3650
    AND "softwareItemDays" BETWEEN 1 AND 3650
    AND "executionJobDays" BETWEEN 1 AND 3650
  );
