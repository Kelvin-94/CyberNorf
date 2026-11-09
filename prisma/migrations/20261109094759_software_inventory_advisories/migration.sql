-- CreateEnum
CREATE TYPE "PackageEcosystem" AS ENUM ('APT', 'RPM', 'BREW', 'NPM', 'PYPI', 'GO', 'CARGO', 'RUBYGEMS', 'MAVEN', 'NUGET', 'OTHER');

-- CreateTable
CREATE TABLE "advisories" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "ecosystem" "PackageEcosystem" NOT NULL,
    "summary" TEXT NOT NULL,
    "severity" "FindingSeverity" NOT NULL,
    "affectedRange" TEXT NOT NULL,
    "fixedVersion" TEXT,
    "cvssScore" DECIMAL(3,1),
    "referenceUrl" TEXT,
    "publishedAt" TIMESTAMP(3),
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "advisories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "software_items" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "assetId" TEXT,
    "ecosystem" "PackageEcosystem" NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "software_items_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "advisories_organizationId_ecosystem_packageName_idx" ON "advisories"("organizationId", "ecosystem", "packageName");

-- CreateIndex
CREATE INDEX "advisories_organizationId_identifier_idx" ON "advisories"("organizationId", "identifier");

-- CreateIndex
CREATE UNIQUE INDEX "advisories_organizationId_identifier_packageName_key" ON "advisories"("organizationId", "identifier", "packageName");

-- CreateIndex
CREATE INDEX "software_items_organizationId_ecosystem_name_idx" ON "software_items"("organizationId", "ecosystem", "name");

-- CreateIndex
CREATE INDEX "software_items_organizationId_assetId_idx" ON "software_items"("organizationId", "assetId");

-- CreateIndex
CREATE UNIQUE INDEX "software_items_agentId_ecosystem_name_key" ON "software_items"("agentId", "ecosystem", "name");

-- AddForeignKey
ALTER TABLE "advisories" ADD CONSTRAINT "advisories_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "advisories" ADD CONSTRAINT "advisories_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "software_items" ADD CONSTRAINT "software_items_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "software_items" ADD CONSTRAINT "software_items_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "software_items" ADD CONSTRAINT "software_items_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;
