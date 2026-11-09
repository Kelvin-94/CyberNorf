-- CreateEnum
CREATE TYPE "NotificationChannelKind" AS ENUM ('WEBHOOK');

-- CreateEnum
CREATE TYPE "NotificationEventType" AS ENUM ('AGENT_OFFLINE', 'AGENT_RECOVERED', 'TEST');

-- CreateEnum
CREATE TYPE "NotificationStatus" AS ENUM ('PENDING', 'SENT', 'FAILED');

-- AlterTable
ALTER TABLE "agents" ADD COLUMN     "expectedIntervalMinutes" INTEGER,
ADD COLUMN     "offlineNotifiedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "notification_channels" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" "NotificationChannelKind" NOT NULL DEFAULT 'WEBHOOK',
    "url" TEXT NOT NULL,
    "secretSealed" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastDeliveredAt" TIMESTAMP(3),
    "lastError" TEXT,

    CONSTRAINT "notification_channels_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_events" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "channelId" TEXT NOT NULL,
    "type" "NotificationEventType" NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "NotificationStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deliveredAt" TIMESTAMP(3),
    "lastError" TEXT,
    "dedupeKey" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notification_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "notification_channels_organizationId_enabled_idx" ON "notification_channels"("organizationId", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "notification_channels_organizationId_name_key" ON "notification_channels"("organizationId", "name");

-- CreateIndex
CREATE INDEX "notification_events_status_nextAttemptAt_idx" ON "notification_events"("status", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "notification_events_organizationId_createdAt_idx" ON "notification_events"("organizationId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "notification_events_channelId_dedupeKey_key" ON "notification_events"("channelId", "dedupeKey");

-- CreateIndex
CREATE INDEX "agents_organizationId_status_lastRunAt_idx" ON "agents"("organizationId", "status", "lastRunAt");

-- AddForeignKey
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_events" ADD CONSTRAINT "notification_events_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_events" ADD CONSTRAINT "notification_events_channelId_fkey" FOREIGN KEY ("channelId") REFERENCES "notification_channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;
