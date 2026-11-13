-- AlterTable
ALTER TABLE "enforcement_actions" ADD COLUMN     "expiresAt" TIMESTAMP(3),
ADD COLUMN     "reason" TEXT;
