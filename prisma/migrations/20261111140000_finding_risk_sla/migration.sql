-- Risk prioritisation and remediation SLAs for findings.
--
-- riskScore is derived from severity, CVSS and asset criticality; dueAt is the
-- remediation deadline. Both are recalculated by the application whenever the
-- inputs change, so the columns stay consistent with src/server/domain/risk.ts.
--
-- Existing rows are backfilled from data already present on the row: the score
-- uses severity only (asset criticality is applied when the finding or its asset
-- is next written), and the deadline uses firstSeenAt plus the severity window.

-- AlterTable
ALTER TABLE "findings" ADD COLUMN "riskScore" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN "dueAt" TIMESTAMP(3);

-- Backfill: severity base score (CRITICAL 90, HIGH 70, MEDIUM 45, LOW 20, INFO 5).
UPDATE "findings"
SET "riskScore" = CASE "severity"
    WHEN 'CRITICAL' THEN 90
    WHEN 'HIGH' THEN 70
    WHEN 'MEDIUM' THEN 45
    WHEN 'LOW' THEN 20
    ELSE 5
END;

-- Backfill: remediation deadline from the first observed exposure.
UPDATE "findings"
SET "dueAt" = "firstSeenAt" + CASE "severity"
    WHEN 'CRITICAL' THEN INTERVAL '7 days'
    WHEN 'HIGH' THEN INTERVAL '30 days'
    WHEN 'MEDIUM' THEN INTERVAL '90 days'
    WHEN 'LOW' THEN INTERVAL '180 days'
    ELSE INTERVAL '365 days'
END;

-- CreateIndex
CREATE INDEX "findings_organizationId_riskScore_idx" ON "findings"("organizationId", "riskScore");

-- CreateIndex
CREATE INDEX "findings_organizationId_dueAt_idx" ON "findings"("organizationId", "dueAt");
