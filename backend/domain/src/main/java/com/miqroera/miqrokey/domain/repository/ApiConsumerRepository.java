package com.miqroera.miqrokey.domain.repository;

import com.miqroera.miqrokey.domain.model.ApiConsumer;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link ApiConsumer} (ADR-0010 external-system API channel).
 */
public interface ApiConsumerRepository {

    ApiConsumer insert(ApiConsumer consumer);

    List<ApiConsumer> findAllByTenantId(UUID tenantId);

    Optional<ApiConsumer> findByIdAndTenantId(UUID id, UUID tenantId);

    /** Digest lookup for the auth filter (whole-tenant match is implicit). */
    Optional<ApiConsumer> findByKeyDigest(byte[] keyDigest);

    /** Name lookup for JWT auth (whole-tenant match is implicit). */
    Optional<ApiConsumer> findByName(String name);

    ApiConsumer update(ApiConsumer consumer);

    /** Replaces the capability scope (null = full access); bumps the version. */
    ApiConsumer updateCapabilities(UUID id, UUID tenantId, List<String> capabilities);

    /**
     * ACTIVE consumers expiring inside the window (issue #322 notifier); rows
     * without an expiry are never returned.
     */
    List<ApiConsumer> findActiveExpiringBetween(UUID tenantId, Instant from, Instant to);

    /**
     * The consumer a portal user owns, if one has been issued (ADR-0030). One user
     * maps to at most one consumer (partial unique index), and this is the only
     * place that mapping is answered, so every caller that needs it agrees.
     */
    Optional<ApiConsumer> findByTenantIdAndUserId(UUID tenantId, UUID userId);

    /**
     * Inserts a consumer owned by a portal user (ADR-0030). Ownership is written
     * with the row rather than carried on {@link ApiConsumer}: it is a lookup key
     * for the self-service surface, and the authentication path never needs it.
     */
    ApiConsumer insertOwnedBy(ApiConsumer consumer, UUID userId);
}
