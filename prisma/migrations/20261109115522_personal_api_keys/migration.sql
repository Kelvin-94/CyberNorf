-- CreateTable
CREATE TABLE "user_api_keys" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "keyPrefix" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_api_keys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_api_keys_keyHash_key" ON "user_api_keys"("keyHash");

-- CreateIndex
CREATE INDEX "user_api_keys_userId_organizationId_idx" ON "user_api_keys"("userId", "organizationId");

-- CreateIndex
CREATE INDEX "user_api_keys_organizationId_idx" ON "user_api_keys"("organizationId");

-- AddForeignKey
ALTER TABLE "user_api_keys" ADD CONSTRAINT "user_api_keys_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_api_keys" ADD CONSTRAINT "user_api_keys_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- A stored key is always a SHA-256 digest and the display prefix never contains
-- more than six secret characters. The application enforces both; these checks
-- keep a future bug from writing a plaintext credential or a full key.
ALTER TABLE "user_api_keys"
    ADD CONSTRAINT "user_api_keys_hash_shape" CHECK ("keyHash" ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT "user_api_keys_prefix_shape" CHECK ("keyPrefix" ~ '^cnk_[A-Za-z0-9_-]{6}$');
