-- Audit events are append-only. Row-level triggers reject modification and
-- deletion through the application database role. Administrative retention or
-- disaster-recovery work requires an explicit database-operator procedure, and
-- TRUNCATE (which bypasses row triggers) is reserved for test resets.

CREATE OR REPLACE FUNCTION cybernorf_audit_events_append_only()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_append_only ON "audit_events";

CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON "audit_events"
  FOR EACH ROW
  EXECUTE FUNCTION cybernorf_audit_events_append_only();
