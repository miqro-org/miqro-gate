package com.miqroera.miqrokey.domain.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

/**
 * The signed caller identity the gateway writes into an upstream MCP request
 * (ADR-0028).
 *
 * <p>
 * Four headers, three of which are fixed: the principal goes into a per-service
 * header (an upstream that already reads its own name needs no change), while
 * the request id, the timestamp and the signature always carry these names. The
 * request id is sent because the MAC covers it — without it on the wire the
 * upstream could not rebuild the signed string. The signature covers the
 * request's metadata — service, principal, RPC method, tool, timestamp, request
 * id — and deliberately <em>not</em> the body: reading the body would cross
 * ADR-0013's "the gateway never parses the args" line, and the metadata is what
 * an upstream needs to attribute and authorise a call.
 * </p>
 *
 * <p>
 * The upstream checks the MAC and the window; this class only produces both. A
 * replay inside the window is not blocked here — the window plus TLS is the
 * bound (ADR-0028 §4), and a nonce cache would mean a stateful component shared
 * across gateway replicas.
 * </p>
 */
public final class McpIdentitySignature {

    /** Epoch seconds the signature was produced at. */
    public static final String TIMESTAMP_HEADER = "X-MiqroKey-Identity-Timestamp";

    /** Lower-case hex HMAC-SHA256 over {@link #canonical}. */
    public static final String SIGNATURE_HEADER = "X-MiqroKey-Identity-Signature";

    /**
     * The request id the signature was computed over — the upstream needs it to
     * verify.
     */
    public static final String REQUEST_ID_HEADER = "X-MiqroKey-Identity-Request-Id";

    private static final String ALGORITHM = "HmacSHA256";

    private McpIdentitySignature() {
    }

    /**
     * The exact string the MAC covers, newline-joined in this order. A field the
     * request did not carry — no RPC method yet, a call that is not a tool call —
     * is written empty, so both sides build the same string without agreeing on a
     * placeholder.
     */
    public static String canonical(String serviceName, String principalId, String rpcMethod, String toolName,
            long timestampEpochSeconds, String requestId) {
        return String.join("\n", nullToEmpty(serviceName), nullToEmpty(principalId), nullToEmpty(rpcMethod),
                nullToEmpty(toolName), Long.toString(timestampEpochSeconds), nullToEmpty(requestId));
    }

    /** Lower-case hex HMAC-SHA256 of {@code canonical} under {@code key}. */
    public static String sign(byte[] key, String canonical) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable in this runtime", e);
        }
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
