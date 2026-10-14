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
     * The portal consumer owned by a user (ADR-0028 option A): at most one per
     * tenant + user, identified by the non-null {@code owner_user_id}.
     */
    Optional<ApiConsumer> findByOwnerUserId(UUID tenantId, UUID ownerUserId);

    /**
     * Replaces the key material in place (self-service rotation): new digest and
     * prefix, status back to ACTIVE, version bumped. The consumer row — and with it
     * the ACL grants — stays the same.
     */
    ApiConsumer rotateKey(UUID id, UUID tenantId, byte[] keyDigest, String keyPrefix);

    /**
     * ACTIVE consumers expiring inside the window (issue #322 notifier); rows
     * without an expiry are never returned.
     */
    List<ApiConsumer> findActiveExpiringBetween(UUID tenantId, Instant from, Instant to);
}
