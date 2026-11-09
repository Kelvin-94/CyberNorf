-- CreateTable
CREATE TABLE "check_control_maps" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "checkId" TEXT NOT NULL,
    "organizationControlId" TEXT NOT NULL,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "check_control_maps_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "check_control_maps_organizationId_checkId_idx" ON "check_control_maps"("organizationId", "checkId");

-- CreateIndex
CREATE INDEX "check_control_maps_organizationControlId_idx" ON "check_control_maps"("organizationControlId");

-- CreateIndex
CREATE UNIQUE INDEX "check_control_maps_organizationId_checkId_organizationContr_key" ON "check_control_maps"("organizationId", "checkId", "organizationControlId");

-- AddForeignKey
ALTER TABLE "check_control_maps" ADD CONSTRAINT "check_control_maps_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "check_control_maps" ADD CONSTRAINT "check_control_maps_organizationControlId_fkey" FOREIGN KEY ("organizationControlId") REFERENCES "organization_controls"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "check_control_maps" ADD CONSTRAINT "check_control_maps_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- A check identifier is bounded at the API edge; the database keeps the same
-- bound so an out-of-band writer cannot store an unusable mapping key.
ALTER TABLE "check_control_maps" ADD CONSTRAINT "check_control_maps_check_id_length" CHECK (char_length("checkId") BETWEEN 2 AND 80);
