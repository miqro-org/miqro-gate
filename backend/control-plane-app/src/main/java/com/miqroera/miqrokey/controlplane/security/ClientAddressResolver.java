package com.miqroera.miqrokey.controlplane.security;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

/**
 * The client address a security decision must be made on (#445), shared by
 * every caller that needs it.
 *
 * <p>
 * The direct peer is the answer unless it is one of our trusted proxies, in
 * which case the {@code X-Forwarded-For} chain is walked from the RIGHT —
 * trusted-proxy entries are skipped and the first non-trusted entry (what the
 * nearest trusted proxy actually observed) wins. Rightmost-walk is correct for
 * both append- and replace-style proxies; trusting the LEFTMOST entry let any
 * client prepend a forged address.
 * </p>
 *
 * <p>
 * This lives in one place on purpose. The IP allowlist and the auth-endpoint
 * throttle (ADR-0029 decision 2) both decide on "who is calling": if they
 * resolved that differently, an address the allowlist sees could be a different
 * address than the one the throttle counts, which is a bypass in itself.
 * </p>
 */
public final class ClientAddressResolver {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private final List<IpCidrMatcher> trustedProxies;

    public ClientAddressResolver(List<IpCidrMatcher> trustedProxies) {
        this.trustedProxies = List.copyOf(trustedProxies);
    }

    /** The address the decision must be made on; never null unless the peer is. */
    public String resolve(HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        if (!isTrusted(peer)) {
            return peer;
        }
        String header = request.getHeader(X_FORWARDED_FOR);
        if (header == null || header.isBlank()) {
            return peer;
        }
        String[] parts = header.split(",", -1);
        for (int i = parts.length - 1; i >= 0; i--) {
            String candidate = parts[i].trim();
            if (candidate.isEmpty() || "unknown".equalsIgnoreCase(candidate)) {
                continue;
            }
            if (!isTrusted(candidate)) {
                return candidate;
            }
        }
        // The whole chain is our own infrastructure — fall back to the peer.
        return peer;
    }

    private boolean isTrusted(String address) {
        return address != null && trustedProxies.stream().anyMatch(m -> m.matches(address));
    }
}
