-- New enum values and types for indicators of compromise, file-backed evidence,
-- and evidence integrity.
--
-- The enum values live in their own migration because PostgreSQL refuses to use
-- a value added by ALTER TYPE ... ADD VALUE in the same transaction: the CHECK
-- constraint and column defaults that reference 'FILE' are in the next
-- migration, which runs after this one commits.

-- A control can now be evidenced by an uploaded artifact, not only by a pointer
-- to an existing record.
ALTER TYPE "EvidenceKind" ADD VALUE IF NOT EXISTS 'FILE';

-- Result of re-reading a stored artifact and comparing it to the recorded hash.
CREATE TYPE "EvidenceIntegrity" AS ENUM ('UNVERIFIED', 'INTACT', 'MISMATCH', 'MISSING');

-- Indicators of compromise. Type and status are enums rather than free text so a
-- typo cannot create a parallel taxonomy that silently stops matching.
CREATE TYPE "IndicatorType" AS ENUM ('IPV4', 'IPV6', 'DOMAIN', 'URL', 'SHA256', 'MD5', 'EMAIL');
CREATE TYPE "IndicatorStatus" AS ENUM ('ACTIVE', 'EXPIRED', 'FALSE_POSITIVE');
CREATE TYPE "IndicatorSourceKind" AS ENUM ('MANUAL', 'IMPORT');
CREATE TYPE "IndicatorRelation" AS ENUM ('OBSERVED', 'REFERENCED');
