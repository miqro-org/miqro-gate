package com.miqroera.miqrokey.controlplane.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * A portal user's own MCP credential, metadata only (ADR-0030). The plaintext
 * key exists solely in the response that creates it — see
 * {@link MeMcpCredentialIssueView} — so this view can be fetched freely.
 */
public record MeMcpCredentialView(UUID id, String name, String keyPrefix, String status, List<String> capabilities,
        Instant createdAt, Instant expiresAt) {
}
