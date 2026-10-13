-- V74: MCP upstream identity passthrough (ADR-0028, accepted 2026-10-13).
--
-- The gateway injects a signed caller identity so an upstream MCP can attribute a
-- tool call and authorise it per caller (e.g. cancel only one's own jobs). It is
-- OFF by default and flips per service, independently of the data plane's other
-- switches: a service whose upstream is not ready for the header must not receive
-- one.
--
-- Shape mirrors V38's backend credential on purpose — same AES-GCM triple, same
-- "mode and ciphertext must agree" constraint. The MAC key is a secret, so it is
-- write-only: no read surface returns it, and it is never carried in the route
-- snapshot (only its non-secret settings are).
--
-- SIGNED additionally requires a header name: the principal goes into that header,
-- and the two companions (timestamp, signature) are derived from it. Without a name
-- there is nowhere to write the identity, so the combination is rejected here
-- rather than at request time.
--
-- NOTE ON VERSION: this file takes V74 because the open ADR-0030 branch takes V73.
-- Whoever merges second must renumber (the repository has done this before — see
-- V63's header note about the V62 collision).

ALTER TABLE mcp_services
    ADD COLUMN identity_forwarding varchar(16) NOT NULL DEFAULT 'OFF'
        CHECK (identity_forwarding IN ('OFF', 'SIGNED')),
    ADD COLUMN identity_header_name varchar(64),
    ADD COLUMN identity_secret_ciphertext bytea,
    ADD COLUMN identity_secret_nonce bytea,
    ADD COLUMN identity_secret_key_version varchar(32),
    ADD COLUMN identity_secret_updated_at timestamptz;

-- Mode and ciphertext must always agree: SIGNED iff a full ciphertext triple exists.
ALTER TABLE mcp_services
    ADD CONSTRAINT ck_mcp_services_identity_secret
        CHECK ((identity_forwarding = 'SIGNED') = (identity_secret_ciphertext IS NOT NULL
               AND identity_secret_nonce IS NOT NULL AND identity_secret_key_version IS NOT NULL));

-- SIGNED needs a header name to write the principal into.
ALTER TABLE mcp_services
    ADD CONSTRAINT ck_mcp_services_identity_header
        CHECK (identity_forwarding = 'OFF'
               OR (identity_header_name IS NOT NULL AND length(btrim(identity_header_name)) > 0));
