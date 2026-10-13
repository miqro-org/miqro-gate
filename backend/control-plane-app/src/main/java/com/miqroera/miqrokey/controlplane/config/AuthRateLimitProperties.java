package com.miqroera.miqrokey.controlplane.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Per-source rate limit on the authentication surface (ADR-0029 decision 2).
 *
 * <p>
 * Scoped to the endpoints that accept credentials — the surfaces where guessing
 * happens — and deliberately not to the inference data plane, whose "no rate
 * limiting" product decision has its own reasoning (ADR-0026).
 * </p>
 *
 * <p>
 * The default is generous on purpose. Everyone behind one NAT shares one
 * address, so a tight limit would lock a whole office out the morning everyone
 * logs in; sixty requests per five minutes still removes the unlimited-guessing
 * regime without standing in the way of a normal login burst.
 * </p>
 */
@ConfigurationProperties(prefix = "miqrokey.auth-rate-limit")
public record AuthRateLimitProperties(@DefaultValue("true") boolean enabled, @DefaultValue("60") int maxRequests,
        @DefaultValue("5m") Duration window) {

    public AuthRateLimitProperties {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("auth-rate-limit window must be positive");
        }
        if (maxRequests <= 0) {
            throw new IllegalArgumentException("auth-rate-limit max-requests must be positive");
        }
    }
}
