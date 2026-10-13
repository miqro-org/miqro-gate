package com.miqroera.miqrokey.controlplane.dto;

/**
 * The one-time answer to issuing a self-service MCP credential (ADR-0030): the
 * plaintext {@code apiKey} is shown here and nowhere else — it is not stored,
 * and every later read returns metadata only.
 */
public record MeMcpCredentialIssueView(MeMcpCredentialView credential, String apiKey) {
}
