-- ADR-0028（选项 A）：门户用户自助 MCP 凭据 = 每用户一个「门户消费者」。
--
-- 归属列可空：存量外部系统消费者保持 NULL（自助面只认 owner_user_id 非空的行）。
-- 同租户同用户至多一条（部分唯一索引，NULL 不参与唯一性）。
-- 删除用户时连同其门户消费者一并清理：mcp_access_grants.consumer_id 已是
-- ON DELETE CASCADE，因此授权行也随之消失——不留「没人拥有但还能用」的孤儿凭据。
ALTER TABLE api_consumers
    ADD COLUMN owner_user_id uuid REFERENCES users (id) ON DELETE CASCADE;

CREATE UNIQUE INDEX uq_api_consumers_portal_owner
    ON api_consumers (tenant_id, owner_user_id)
    WHERE owner_user_id IS NOT NULL;
