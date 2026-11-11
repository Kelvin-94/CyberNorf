-- Authentication activity lives outside the per-organization audit chain: a
-- sign-in happens before any tenant is known, so there is no organization to
-- chain it to. The table is append-only for the same reason audit_events is:
-- a credential trail that can be edited is not evidence.

CREATE TABLE "auth_events" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "action" TEXT NOT NULL,
    "outcome" "AuditOutcome" NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_events_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "auth_events_userId_createdAt_idx" ON "auth_events"("userId", "createdAt");
CREATE INDEX "auth_events_action_createdAt_idx" ON "auth_events"("action", "createdAt");

ALTER TABLE "auth_events" ADD CONSTRAINT "auth_events_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE OR REPLACE FUNCTION cybernorf_auth_events_append_only()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'auth_events is append-only: % is not permitted', TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER auth_events_append_only
  BEFORE UPDATE OR DELETE ON "auth_events"
  FOR EACH ROW
  EXECUTE FUNCTION cybernorf_auth_events_append_only();
