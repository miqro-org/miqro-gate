package com.miqroera.miqrokey.domain.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The signed-identity contract (ADR-0028). The upstream verifies against this
 * exact string, so its shape is the interface — a field order or separator
 * change here is a breaking change there, and these cases are what makes that
 * visible.
 */
@DisplayName("McpIdentitySignature")
class McpIdentitySignatureTest {

    private static final byte[] KEY = "an-identity-mac-key".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("the canonical string is the six fields, newline-joined, in order")
    void canonicalShapeIsPinned() {
        assertThat(McpIdentitySignature.canonical("slurm", "consumer-1", "tools/call", "submit_slurm_job", 1700000000L,
                "req-1")).isEqualTo("slurm\nconsumer-1\ntools/call\nsubmit_slurm_job\n1700000000\nreq-1");
    }

    @Test
    @DisplayName("fields the request did not carry are empty, not omitted")
    void absentFieldsBecomeEmptyStrings() {
        // A non-tool RPC has no tool name, and an unparsed body has no method yet.
        assertThat(McpIdentitySignature.canonical("slurm", "consumer-1", null, null, 1700000000L, "req-1"))
                .isEqualTo("slurm\nconsumer-1\n\n\n1700000000\nreq-1");
    }

    @Test
    @DisplayName("the signature is deterministic lower-case hex")
    void signatureIsDeterministicHex() {
        String canonical = McpIdentitySignature.canonical("slurm", "consumer-1", "tools/call", "check_job_status",
                1700000000L, "req-1");

        String first = McpIdentitySignature.sign(KEY, canonical);
        String second = McpIdentitySignature.sign(KEY, canonical);

        assertThat(first).isEqualTo(second).matches("[0-9a-f]{64}");
    }

    @Test
    @DisplayName("a different key or a different canonical string changes the signature")
    void signatureIsKeyAndContentSensitive() {
        String canonical = McpIdentitySignature.canonical("slurm", "consumer-1", "tools/call", "cancel_slurm_job",
                1700000000L, "req-1");
        String otherConsumer = McpIdentitySignature.canonical("slurm", "consumer-2", "tools/call", "cancel_slurm_job",
                1700000000L, "req-1");

        assertThat(McpIdentitySignature.sign(KEY, canonical))
                .isNotEqualTo(McpIdentitySignature.sign("another-key".getBytes(StandardCharsets.UTF_8), canonical));
        assertThat(McpIdentitySignature.sign(KEY, canonical))
                .isNotEqualTo(McpIdentitySignature.sign(KEY, otherConsumer));
    }

    @Test
    @DisplayName("the timestamp participates, so a signature cannot outlive its window")
    void timestampParticipates() {
        String now = McpIdentitySignature.canonical("slurm", "consumer-1", "tools/call", "get_job_output", 1700000000L,
                "req-1");
        String later = McpIdentitySignature.canonical("slurm", "consumer-1", "tools/call", "get_job_output",
                1700000060L, "req-1");

        assertThat(McpIdentitySignature.sign(KEY, now)).isNotEqualTo(McpIdentitySignature.sign(KEY, later));
    }

    @Test
    @DisplayName("the companion header names are the reserved ones")
    void headerNamesAreReserved() {
        assertThat(McpIdentitySignature.TIMESTAMP_HEADER).isEqualTo("X-MiqroKey-Identity-Timestamp");
        assertThat(McpIdentitySignature.SIGNATURE_HEADER).isEqualTo("X-MiqroKey-Identity-Signature");
        // The MAC covers the request id, so it has to reach the upstream too.
        assertThat(McpIdentitySignature.REQUEST_ID_HEADER).isEqualTo("X-MiqroKey-Identity-Request-Id");
    }
}
