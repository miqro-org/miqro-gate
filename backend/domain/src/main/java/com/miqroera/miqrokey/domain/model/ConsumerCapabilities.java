package com.miqroera.miqrokey.domain.model;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * API consumer capability scope (issue #316, mirror of the F60 admin-key scope
 * pattern): {@code null} capabilities mean full access; a non-null list narrows
 * the consumer to the listed channels. Two channels exist today:
 * {@code billing:read} (control-plane /api/v1/billing/**) and {@code mcp:call}
 * (MCP data plane). An unset scope is full access by design (not fail-closed)
 * and is the state every consumer starts in — creation takes no capabilities —
 * so least privilege must be set explicitly; a non-null list denies every
 * channel it does not name.
 */
public final class ConsumerCapabilities {

    public static final String BILLING_READ = "billing:read";
    public static final String MCP_CALL = "mcp:call";

    private static final Set<String> ALL = Set.of(BILLING_READ, MCP_CALL);

    private ConsumerCapabilities() {
    }

    /** Every entry must be a known code; duplicates and nulls are rejected. */
    public static boolean isValid(List<String> capabilities) {
        if (capabilities == null) {
            return true;
        }
        Set<String> seen = new HashSet<>();
        for (String code : capabilities) {
            if (code == null || !ALL.contains(code) || !seen.add(code)) {
                return false;
            }
        }
        return true;
    }
}
