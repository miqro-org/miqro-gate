-- ADR-0030: a portal user's own MCP credential.
--
-- Consumers began as anonymous machine identities (V13): the MCP access control
-- keys on the consumer, so with no owner there was no way to answer "which
-- services may this person reach", and the self-service surface (issue #1) could
-- not be built to the ACL-consistent standard it requires.
--
-- The column is nullable on purpose: existing machine consumers stay ownerless
-- and keep working unchanged. The unique index is partial so that only user-owned
-- rows are constrained (many ownerless consumers remain legal).
--
-- ON DELETE CASCADE matches mcp_access_grants.consumer_id (V25, also CASCADE):
-- deleting a user removes their credential and, through it, the ACL entries that
-- name it. Nothing keeps a dangling grant behind.

ALTER TABLE api_consumers ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE;

CREATE UNIQUE INDEX uq_api_consumers_tenant_user ON api_consumers (tenant_id, user_id) WHERE user_id IS NOT NULL;
