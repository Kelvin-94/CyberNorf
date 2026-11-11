-- CreateEnum
CREATE TYPE "IdentityKind" AS ENUM ('HUMAN', 'MACHINE');

-- CreateEnum
CREATE TYPE "IdentityType" AS ENUM ('USER', 'SERVICE_ACCOUNT', 'MONITORING_AGENT', 'API_CLIENT', 'SERVER', 'NETWORK_DEVICE', 'IOT_DEVICE', 'CONTAINER', 'OTHER');

-- CreateEnum
CREATE TYPE "IdentityStatus" AS ENUM ('PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'DEPROVISIONED');

-- CreateEnum
CREATE TYPE "IdentitySource" AS ENUM ('MANUAL', 'IMPORT');

-- CreateEnum
CREATE TYPE "IdentityCriticality" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "IdentityEventType" AS ENUM ('CREATED', 'UPDATED', 'OWNER_ASSIGNED', 'SUBMITTED_FOR_APPROVAL', 'APPROVED', 'SUSPENDED', 'REACTIVATED', 'DEPROVISIONED', 'CREDENTIAL_ISSUED', 'CREDENTIAL_REVOKED', 'ACCESS_REVOKED');

-- CreateEnum
CREATE TYPE "AccessReviewStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "AccessReviewDecision" AS ENUM ('PENDING', 'RETAIN', 'REVOKE');

-- CreateTable
CREATE TABLE "identities" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "kind" "IdentityKind" NOT NULL,
    "type" "IdentityType" NOT NULL,
    "displayName" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "description" TEXT,
    "department" TEXT,
    "criticality" "IdentityCriticality" NOT NULL DEFAULT 'MEDIUM',
    "status" "IdentityStatus" NOT NULL DEFAULT 'ACTIVE',
    "source" "IdentitySource" NOT NULL DEFAULT 'MANUAL',
    "approvedScopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "ownerUserId" TEXT,
    "linkedUserId" TEXT,
    "credentialTtlDays" INTEGER NOT NULL DEFAULT 90,
    "lastSeenAt" TIMESTAMP(3),
    "createdById" TEXT NOT NULL,
    "approvedById" TEXT,
    "approvedAt" TIMESTAMP(3),
    "suspendedAt" TIMESTAMP(3),
    "deprovisionedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "identities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_credentials" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "identityId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "keyPrefix" TEXT NOT NULL,
    "scopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "revokedReason" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "identity_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_events" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "identityId" TEXT NOT NULL,
    "type" "IdentityEventType" NOT NULL,
    "actorId" TEXT,
    "summary" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "identity_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "access_reviews" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "status" "AccessReviewStatus" NOT NULL DEFAULT 'ACTIVE',
    "dueAt" TIMESTAMP(3) NOT NULL,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),
    "cancelledAt" TIMESTAMP(3),

    CONSTRAINT "access_reviews_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "access_review_items" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "reviewId" TEXT NOT NULL,
    "membershipId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "userName" TEXT NOT NULL,
    "userEmail" TEXT NOT NULL,
    "roleAtReview" "OrgRole" NOT NULL,
    "decision" "AccessReviewDecision" NOT NULL DEFAULT 'PENDING',
    "decidedById" TEXT,
    "decidedAt" TIMESTAMP(3),
    "note" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "access_review_items_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "identities_organizationId_kind_status_idx" ON "identities"("organizationId", "kind", "status");

-- CreateIndex
CREATE INDEX "identities_organizationId_type_idx" ON "identities"("organizationId", "type");

-- CreateIndex
CREATE INDEX "identities_organizationId_linkedUserId_idx" ON "identities"("organizationId", "linkedUserId");

-- CreateIndex
CREATE INDEX "identities_organizationId_ownerUserId_idx" ON "identities"("organizationId", "ownerUserId");

-- CreateIndex
CREATE UNIQUE INDEX "identities_organizationId_identifier_key" ON "identities"("organizationId", "identifier");

-- CreateIndex
CREATE UNIQUE INDEX "identity_credentials_keyHash_key" ON "identity_credentials"("keyHash");

-- CreateIndex
CREATE INDEX "identity_credentials_organizationId_identityId_idx" ON "identity_credentials"("organizationId", "identityId");

-- CreateIndex
CREATE INDEX "identity_credentials_identityId_revokedAt_idx" ON "identity_credentials"("identityId", "revokedAt");

-- CreateIndex
CREATE INDEX "identity_credentials_organizationId_expiresAt_idx" ON "identity_credentials"("organizationId", "expiresAt");

-- CreateIndex
CREATE INDEX "identity_events_organizationId_createdAt_idx" ON "identity_events"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "identity_events_identityId_createdAt_idx" ON "identity_events"("identityId", "createdAt");

-- CreateIndex
CREATE INDEX "access_reviews_organizationId_status_idx" ON "access_reviews"("organizationId", "status");

-- CreateIndex
CREATE INDEX "access_reviews_organizationId_dueAt_idx" ON "access_reviews"("organizationId", "dueAt");

-- CreateIndex
CREATE INDEX "access_review_items_organizationId_reviewId_decision_idx" ON "access_review_items"("organizationId", "reviewId", "decision");

-- CreateIndex
CREATE INDEX "access_review_items_decidedById_idx" ON "access_review_items"("decidedById");

-- CreateIndex
CREATE UNIQUE INDEX "access_review_items_reviewId_membershipId_key" ON "access_review_items"("reviewId", "membershipId");

-- AddForeignKey
ALTER TABLE "identities" ADD CONSTRAINT "identities_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identities" ADD CONSTRAINT "identities_ownerUserId_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identities" ADD CONSTRAINT "identities_linkedUserId_fkey" FOREIGN KEY ("linkedUserId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identities" ADD CONSTRAINT "identities_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identities" ADD CONSTRAINT "identities_approvedById_fkey" FOREIGN KEY ("approvedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_credentials" ADD CONSTRAINT "identity_credentials_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_credentials" ADD CONSTRAINT "identity_credentials_identityId_fkey" FOREIGN KEY ("identityId") REFERENCES "identities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_credentials" ADD CONSTRAINT "identity_credentials_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_events" ADD CONSTRAINT "identity_events_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_events" ADD CONSTRAINT "identity_events_identityId_fkey" FOREIGN KEY ("identityId") REFERENCES "identities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_events" ADD CONSTRAINT "identity_events_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "access_reviews" ADD CONSTRAINT "access_reviews_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "access_reviews" ADD CONSTRAINT "access_reviews_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "access_review_items" ADD CONSTRAINT "access_review_items_reviewId_fkey" FOREIGN KEY ("reviewId") REFERENCES "access_reviews"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "access_review_items" ADD CONSTRAINT "access_review_items_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "access_review_items" ADD CONSTRAINT "access_review_items_membershipId_fkey" FOREIGN KEY ("membershipId") REFERENCES "memberships"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "access_review_items" ADD CONSTRAINT "access_review_items_decidedById_fkey" FOREIGN KEY ("decidedById") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Canonical identifiers: the service normalizes before writing, and the database
-- refuses a value that bypassed it. This is what makes the per-tenant unique
-- index meaningful against case-only duplicates.
ALTER TABLE "identities"
  ADD CONSTRAINT "identities_identifier_canonical_check"
  CHECK ("identifier" = lower(btrim("identifier")) AND length("identifier") > 0);

-- A machine identity is a workload, never a console account. Linking it to a
-- user would let inventory state imply human access that does not exist.
ALTER TABLE "identities"
  ADD CONSTRAINT "identities_machine_not_linked_check"
  CHECK ("kind" <> 'MACHINE' OR "linkedUserId" IS NULL);

ALTER TABLE "identities"
  ADD CONSTRAINT "identities_credential_ttl_check"
  CHECK ("credentialTtlDays" >= 1 AND "credentialTtlDays" <= 365);

ALTER TABLE "access_reviews"
  ADD CONSTRAINT "access_reviews_due_after_creation_check"
  CHECK ("dueAt" > "createdAt");

-- A decision is only complete when a reviewer and timestamp are both present;
-- a PENDING item cannot carry either. This keeps "no decision" distinguishable
-- from "retained" even for a direct database writer.
ALTER TABLE "access_review_items"
  ADD CONSTRAINT "access_review_items_decision_check"
  CHECK (
    ("decision" = 'PENDING' AND "decidedById" IS NULL AND "decidedAt" IS NULL)
    OR
    ("decision" <> 'PENDING' AND "decidedById" IS NOT NULL AND "decidedAt" IS NOT NULL)
  );

-- Object history is evidence. Like audit_events, identity_events cannot be
-- rewritten or deleted through the application's database role.
CREATE OR REPLACE FUNCTION cybernorf_identity_events_append_only()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'identity_events is append-only: % is not permitted', TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER identity_events_append_only
  BEFORE UPDATE OR DELETE ON "identity_events"
  FOR EACH ROW
  EXECUTE FUNCTION cybernorf_identity_events_append_only();
