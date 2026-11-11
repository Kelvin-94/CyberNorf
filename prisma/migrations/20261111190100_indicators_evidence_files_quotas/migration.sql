-- Indicators of compromise, file-backed evidence with integrity metadata,
-- deployment configuration state, and per-tenant quota overrides.

-- ---------------------------------------------------------------------------
-- Evidence: uploaded artifacts
-- ---------------------------------------------------------------------------

-- File-backed evidence stores the artifact on disk and keeps only metadata and
-- a content hash here, so the database stays small and a backup of the database
-- alone is not a backup of the evidence. The application refuses a row without a
-- hash, and the CHECK constraint below enforces the same rule for direct SQL.
ALTER TABLE "control_evidence"
  ADD COLUMN "fileName"           TEXT,
  ADD COLUMN "contentType"        TEXT,
  ADD COLUMN "sizeBytes"          INTEGER,
  ADD COLUMN "sha256"             TEXT,
  ADD COLUMN "blobKey"            TEXT,
  ADD COLUMN "capturedAt"         TIMESTAMP(3),
  ADD COLUMN "integrityStatus"    "EvidenceIntegrity" NOT NULL DEFAULT 'UNVERIFIED',
  ADD COLUMN "integrityCheckedAt" TIMESTAMP(3);

-- Exactly one target, now including FILE. Dropped and recreated rather than
-- altered because a CHECK constraint cannot be extended in place.
ALTER TABLE "control_evidence" DROP CONSTRAINT IF EXISTS "control_evidence_single_target_check";
ALTER TABLE "control_evidence"
  ADD CONSTRAINT "control_evidence_single_target_check" CHECK (
    ("kind" = 'FINDING'   AND "findingId" IS NOT NULL AND "incidentId" IS NULL AND "assetId" IS NULL AND "reference" IS NULL AND "blobKey" IS NULL) OR
    ("kind" = 'INCIDENT'  AND "incidentId" IS NOT NULL AND "findingId" IS NULL AND "assetId" IS NULL AND "reference" IS NULL AND "blobKey" IS NULL) OR
    ("kind" = 'ASSET'     AND "assetId" IS NOT NULL AND "findingId" IS NULL AND "incidentId" IS NULL AND "reference" IS NULL AND "blobKey" IS NULL) OR
    ("kind" = 'REFERENCE' AND "reference" IS NOT NULL AND "findingId" IS NULL AND "incidentId" IS NULL AND "assetId" IS NULL AND "blobKey" IS NULL) OR
    ("kind" = 'FILE'      AND "blobKey" IS NOT NULL AND "fileName" IS NOT NULL AND "sha256" IS NOT NULL AND "sizeBytes" IS NOT NULL
                          AND "findingId" IS NULL AND "incidentId" IS NULL AND "assetId" IS NULL AND "reference" IS NULL)
  );

-- A hash is either absent (non-file evidence) or a full lower-case SHA-256.
ALTER TABLE "control_evidence"
  ADD CONSTRAINT "control_evidence_sha256_shape" CHECK ("sha256" IS NULL OR "sha256" ~ '^[0-9a-f]{64}$');
ALTER TABLE "control_evidence"
  ADD CONSTRAINT "control_evidence_file_size" CHECK ("sizeBytes" IS NULL OR ("sizeBytes" > 0 AND "sizeBytes" <= 10485760));

-- blobKey is generated from the evidence id, never from user input, so it can be
-- constrained to the exact shape the application produces. This makes a path
-- traversal in a stored key impossible even if a future code path tried.
ALTER TABLE "control_evidence"
  ADD CONSTRAINT "control_evidence_blob_key_shape" CHECK ("blobKey" IS NULL OR "blobKey" ~ '^[a-z0-9]{20,40}$');

CREATE INDEX "control_evidence_organizationId_integrityStatus_idx" ON "control_evidence"("organizationId", "integrityStatus");

-- ---------------------------------------------------------------------------
-- Indicators of compromise
-- ---------------------------------------------------------------------------

CREATE TABLE "indicators" (
  "id"             TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "type"           "IndicatorType" NOT NULL,
  "value"          TEXT NOT NULL,
  "displayValue"   TEXT,
  "status"         "IndicatorStatus" NOT NULL DEFAULT 'ACTIVE',
  "confidence"     INTEGER NOT NULL DEFAULT 50,
  "sourceKind"     "IndicatorSourceKind" NOT NULL DEFAULT 'MANUAL',
  "sourceName"     TEXT NOT NULL,
  "sourceUrl"      TEXT,
  "sourceRef"      TEXT,
  "firstSeenAt"    TIMESTAMP(3) NOT NULL,
  "lastSeenAt"     TIMESTAMP(3) NOT NULL,
  "expiresAt"      TIMESTAMP(3),
  "note"           TEXT,
  "createdById"    TEXT NOT NULL,
  "createdAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"      TIMESTAMP(3) NOT NULL,
  CONSTRAINT "indicators_pkey" PRIMARY KEY ("id")
);

-- One row per distinct indicator per tenant. A feed that repeats a value updates
-- the existing row instead of creating a duplicate that splits its history.
CREATE UNIQUE INDEX "indicators_organizationId_type_value_key" ON "indicators"("organizationId", "type", "value");
CREATE INDEX "indicators_organizationId_status_lastSeenAt_idx" ON "indicators"("organizationId", "status", "lastSeenAt");

ALTER TABLE "indicators" ADD CONSTRAINT "indicators_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "indicators" ADD CONSTRAINT "indicators_createdById_fkey"
  FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Confidence is a percentage; a caller cannot smuggle in a score above 100 that
-- would sort like a certainty.
ALTER TABLE "indicators" ADD CONSTRAINT "indicators_confidence_range" CHECK ("confidence" BETWEEN 0 AND 100);
-- lastSeenAt may never precede firstSeenAt, which would make the feed appear to
-- have gone back in time.
ALTER TABLE "indicators" ADD CONSTRAINT "indicators_seen_order" CHECK ("lastSeenAt" >= "firstSeenAt");
-- A stored value is normalised, so it is lower-case, trimmed and non-empty.
ALTER TABLE "indicators" ADD CONSTRAINT "indicators_value_normalised"
  CHECK ("value" = lower(btrim("value")) AND length("value") BETWEEN 1 AND 2048);
ALTER TABLE "indicators" ADD CONSTRAINT "indicators_source_named" CHECK (length(btrim("sourceName")) > 0);

CREATE TABLE "indicator_links" (
  "id"             TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "indicatorId"    TEXT NOT NULL,
  "findingId"      TEXT,
  "incidentId"     TEXT,
  "relation"       "IndicatorRelation" NOT NULL DEFAULT 'REFERENCED',
  "note"           TEXT,
  "createdById"    TEXT NOT NULL,
  "createdAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "indicator_links_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "indicator_links_organizationId_indicatorId_idx" ON "indicator_links"("organizationId", "indicatorId");
CREATE INDEX "indicator_links_findingId_idx" ON "indicator_links"("findingId");
CREATE INDEX "indicator_links_incidentId_idx" ON "indicator_links"("incidentId");

-- Partial unique indexes rather than one composite unique: PostgreSQL treats
-- NULLs as distinct, so UNIQUE(indicatorId, findingId) would happily store the
-- same finding link twice, and UNIQUE(indicatorId, findingId, incidentId) would
-- allow the same incident link twice for the same reason.
CREATE UNIQUE INDEX "indicator_links_finding_pair_key" ON "indicator_links"("indicatorId", "findingId") WHERE "findingId" IS NOT NULL;
CREATE UNIQUE INDEX "indicator_links_incident_pair_key" ON "indicator_links"("indicatorId", "incidentId") WHERE "incidentId" IS NOT NULL;

ALTER TABLE "indicator_links" ADD CONSTRAINT "indicator_links_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "indicator_links" ADD CONSTRAINT "indicator_links_indicatorId_fkey"
  FOREIGN KEY ("indicatorId") REFERENCES "indicators"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "indicator_links" ADD CONSTRAINT "indicator_links_findingId_fkey"
  FOREIGN KEY ("findingId") REFERENCES "findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "indicator_links" ADD CONSTRAINT "indicator_links_incidentId_fkey"
  FOREIGN KEY ("incidentId") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "indicator_links" ADD CONSTRAINT "indicator_links_createdById_fkey"
  FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- A link points at exactly one record. Without this, a row could claim to belong
-- to both a finding and an incident and appear twice in an investigation.
ALTER TABLE "indicator_links" ADD CONSTRAINT "indicator_links_single_target_check" CHECK (
  ("findingId" IS NOT NULL AND "incidentId" IS NULL) OR
  ("findingId" IS NULL AND "incidentId" IS NOT NULL)
);

-- ---------------------------------------------------------------------------
-- Deployment-level state
-- ---------------------------------------------------------------------------

-- Not tenant data: this table records what the installation has applied, such as
-- the fingerprint of the effective configuration. Deliberately has no
-- organizationId, and is only reachable from scripts and startup code.
CREATE TABLE "system_settings" (
  "key"       TEXT NOT NULL,
  "value"     JSONB NOT NULL,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "system_settings_pkey" PRIMARY KEY ("key")
);

-- ---------------------------------------------------------------------------
-- Resource quotas
-- ---------------------------------------------------------------------------

-- NULL means "use the tier default". Storing overrides separately from the
-- organization keeps the default itself in code, so changing a tier limit for
-- everyone does not require a data migration.
CREATE TABLE "organization_quotas" (
  "organizationId"    TEXT NOT NULL,
  "assets"            INTEGER,
  "findings"          INTEGER,
  "incidents"         INTEGER,
  "identities"        INTEGER,
  "agents"            INTEGER,
  "indicators"        INTEGER,
  "apiKeys"           INTEGER,
  "evidenceStorageMb" INTEGER,
  "updatedAt"         TIMESTAMP(3) NOT NULL,
  CONSTRAINT "organization_quotas_pkey" PRIMARY KEY ("organizationId")
);

ALTER TABLE "organization_quotas" ADD CONSTRAINT "organization_quotas_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- A limit is a positive number or absent. Zero would mean "this tenant may never
-- create one", which is a different feature (a disabled capability) and is not
-- what a quota is for.
ALTER TABLE "organization_quotas" ADD CONSTRAINT "organization_quotas_positive"
  CHECK (
    ("assets"            IS NULL OR "assets"            > 0) AND
    ("findings"          IS NULL OR "findings"          > 0) AND
    ("incidents"         IS NULL OR "incidents"         > 0) AND
    ("identities"        IS NULL OR "identities"        > 0) AND
    ("agents"            IS NULL OR "agents"            > 0) AND
    ("indicators"        IS NULL OR "indicators"        > 0) AND
    ("apiKeys"           IS NULL OR "apiKeys"           > 0) AND
    ("evidenceStorageMb" IS NULL OR "evidenceStorageMb" > 0)
  );
