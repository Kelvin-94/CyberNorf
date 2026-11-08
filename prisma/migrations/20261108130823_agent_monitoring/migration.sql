-- CreateEnum
CREATE TYPE "AgentSource" AS ENUM ('BUILTIN', 'OPENAI', 'ANTHROPIC', 'CUSTOM', 'OTHER');

-- CreateEnum
CREATE TYPE "AgentStatus" AS ENUM ('PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'REVOKED');

-- CreateEnum
CREATE TYPE "AgentRunStatus" AS ENUM ('COMPLETED', 'PARTIAL', 'FAILED');

-- AlterEnum
ALTER TYPE "AuditActorType" ADD VALUE 'AGENT';

-- AlterEnum
ALTER TYPE "FindingSource" ADD VALUE 'AGENT';

-- AlterTable
ALTER TABLE "findings" ADD COLUMN "agentId" TEXT;

-- CreateTable
CREATE TABLE "agents" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "source" "AgentSource" NOT NULL,
    "status" "AgentStatus" NOT NULL DEFAULT 'PENDING_APPROVAL',
    "scopes" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "tokenHash" TEXT,
    "tokenPrefix" TEXT,
    "tokenExpiresAt" TIMESTAMP(3),
    "lastSeenAt" TIMESTAMP(3),
    "lastRunAt" TIMESTAMP(3),
    "runCount" INTEGER NOT NULL DEFAULT 0,
    "createdById" TEXT NOT NULL,
    "approvedById" TEXT,
    "approvedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_runs" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "status" "AgentRunStatus" NOT NULL,
    "hostname" TEXT,
    "platform" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL,
    "finishedAt" TIMESTAMP(3),
    "durationMs" INTEGER,
    "checkCount" INTEGER NOT NULL DEFAULT 0,
    "passCount" INTEGER NOT NULL DEFAULT 0,
    "failCount" INTEGER NOT NULL DEFAULT 0,
    "skipCount" INTEGER NOT NULL DEFAULT 0,
    "findingsCreated" INTEGER NOT NULL DEFAULT 0,
    "findingsRefreshed" INTEGER NOT NULL DEFAULT 0,
    "checks" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_runs_pkey" PRIMARY KEY ("id")
);

-- Integrity rules that hold even when rows are written outside the app.
ALTER TABLE "agents"
    ADD CONSTRAINT "agents_revoked_timestamp_check"
        CHECK ("status" <> 'REVOKED' OR "revokedAt" IS NOT NULL),
    ADD CONSTRAINT "agents_token_hash_shape_check"
        CHECK ("tokenHash" IS NULL OR "tokenHash" ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT "agents_token_prefix_shape_check"
        CHECK ("tokenPrefix" IS NULL OR "tokenPrefix" ~ '^cna_[A-Za-z0-9_-]{6}$');

ALTER TABLE "agent_runs"
    ADD CONSTRAINT "agent_runs_check_counts_check"
        CHECK (
            "checkCount" >= 0
            AND "passCount" >= 0
            AND "failCount" >= 0
            AND "skipCount" >= 0
            AND "checkCount" = "passCount" + "failCount" + "skipCount"
        ),
    ADD CONSTRAINT "agent_runs_status_matches_counts_check"
        CHECK (
            ("status" <> 'FAILED' OR "checkCount" = 0)
            AND ("status" <> 'PARTIAL' OR "skipCount" > 0)
            AND ("status" <> 'COMPLETED' OR ("checkCount" > 0 AND "skipCount" = 0))
        );

-- CreateIndex
CREATE UNIQUE INDEX "agents_tokenHash_key" ON "agents"("tokenHash");

-- CreateIndex
CREATE INDEX "agents_organizationId_status_idx" ON "agents"("organizationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "agents_organizationId_name_key" ON "agents"("organizationId", "name");

-- CreateIndex
CREATE INDEX "agent_runs_organizationId_startedAt_idx" ON "agent_runs"("organizationId", "startedAt");

-- CreateIndex
CREATE INDEX "agent_runs_agentId_startedAt_idx" ON "agent_runs"("agentId", "startedAt");

-- CreateIndex
CREATE INDEX "findings_organizationId_agentId_idx" ON "findings"("organizationId", "agentId");

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agents" ADD CONSTRAINT "agents_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agents" ADD CONSTRAINT "agents_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agents" ADD CONSTRAINT "agents_approvedById_fkey" FOREIGN KEY ("approvedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_runs" ADD CONSTRAINT "agent_runs_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_runs" ADD CONSTRAINT "agent_runs_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
