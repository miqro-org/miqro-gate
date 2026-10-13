package com.miqroera.miqrokey.controlplane.service;

import com.miqroera.miqrokey.controlplane.dto.McpServiceAccessView;
import com.miqroera.miqrokey.domain.model.ApiConsumer;
import com.miqroera.miqrokey.domain.model.ConsumerCapabilities;
import com.miqroera.miqrokey.domain.model.McpAclMode;
import com.miqroera.miqrokey.domain.model.McpAccessPolicy;
import com.miqroera.miqrokey.domain.model.McpService;
import com.miqroera.miqrokey.domain.repository.ApiConsumerRepository;
import com.miqroera.miqrokey.domain.repository.McpAccessRepository;
import com.miqroera.miqrokey.domain.repository.McpServiceRepository;
import com.miqroera.miqrokey.domain.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * A portal user's own MCP credential (ADR-0030): one consumer per user, issued
 * on first use and owned by that user, plus the self-service view of which
 * services that credential may call (issue #1).
 *
 * <p>
 * The credential is an ordinary API consumer — key digest, capability scope,
 * expiry, two-level ACL, access-log attribution all already apply. What was
 * missing was ownership: consumers began as anonymous machine identities, so
 * "which services may this person reach" had no answer.
 * </p>
 *
 * <p>
 * <b>Consistency with the data plane is the point.</b> The visible list is
 * decided by the same {@link McpAccessPolicy} the gateway applies, over the
 * same server-level list (grants with no tool), with a missing access row
 * meaning {@code NONE} exactly as the route snapshot's LEFT JOIN yields. The
 * URLs come from {@link McpOnboardingService}, the same builder the admin
 * console's "connection" view uses. If any of that were re-derived here, the
 * list could promise a service the gateway then refuses.
 * </p>
 */
@Service
public class UserMcpCredentialService {

    private static final Logger LOG = LoggerFactory.getLogger(UserMcpCredentialService.class);

    /**
     * Every self-service credential carries exactly this. It is the narrowest scope
     * that lets it call MCP at all, and it matches what the admin path asks for.
     */
    private static final List<String> CAPABILITIES = List.of(ConsumerCapabilities.MCP_CALL);

    private final ApiConsumerRepository consumerRepository;
    private final McpServiceRepository mcpServiceRepository;
    private final McpAccessRepository mcpAccessRepository;
    private final McpOnboardingService onboardingService;
    private final AuditService auditService;
    private final RouteRefreshPublisher routeRefreshPublisher;

    public UserMcpCredentialService(ApiConsumerRepository consumerRepository, McpServiceRepository mcpServiceRepository,
            McpAccessRepository mcpAccessRepository, McpOnboardingService onboardingService, AuditService auditService,
            RouteRefreshPublisher routeRefreshPublisher) {
        this.consumerRepository = consumerRepository;
        this.mcpServiceRepository = mcpServiceRepository;
        this.mcpAccessRepository = mcpAccessRepository;
        this.onboardingService = onboardingService;
        this.auditService = auditService;
        this.routeRefreshPublisher = routeRefreshPublisher;
    }

    /** The caller's own consumer, if one has been issued. */
    public Optional<ApiConsumer> current(UUID tenantId, UUID userId) {
        return consumerRepository.findByTenantIdAndUserId(tenantId, userId);
    }

    /**
     * The credential the caller uses for MCP. Created on first request, or returned
     * as it stands — the plaintext key exists only in the response that created it,
     * so a later call reports the prefix and nothing more.
     */
    @Transactional
    public IssuedCredential issueOrGet(UUID tenantId, UUID userId, String username, String requestId) {
        Optional<ApiConsumer> existing = current(tenantId, userId);
        if (existing.isPresent()) {
            return new IssuedCredential(existing.get(), null);
        }

        ApiConsumer.GeneratedKey key = ApiConsumer.generateKey();
        // The name is display-only, but it must be unique per tenant, so it is
        // derived rather than free-form: an administrator who already used it gets a
        // clear conflict instead of a silent second credential for the same person.
        String name = "user:" + username;
        ApiConsumer consumer = new ApiConsumer(UUID.randomUUID(), tenantId, name, key.digest(), key.prefix(), "ACTIVE",
                null, null, null, 0, Instant.now(), Instant.now(), CAPABILITIES, null);
        try {
            consumerRepository.insertOwnedBy(consumer, userId);
        } catch (DuplicateKeyException e) {
            throw new ApiException(HttpStatus.CONFLICT, "CONSUMER_NAME_TAKEN", "已存在同名消费者（" + name + "），请联系管理员改名后重试。");
        }
        routeRefreshPublisher.publishChanged();
        auditService.record(tenantId, userId, "USER_MCP_CREDENTIAL_ISSUE", "CONSUMER", consumer.id(),
                AuditSummaries.summary("name", AuditSummaries.sanitize(name)), requestId);
        LOG.info("Issued MCP credential {} to user {}", consumer.id(), userId);
        return new IssuedCredential(consumer, key.plaintext());
    }

    /**
     * The ONLINE services this user's credential may call — computed by the
     * gateway's own access rule, so the list never promises a call the data plane
     * would refuse. An unauthorised service is not merely filtered out; it is never
     * named.
     */
    public List<McpServiceAccessView> visibleServices(UUID tenantId, UUID userId) {
        UUID consumerId = current(tenantId, userId).map(ApiConsumer::id).orElse(null);
        if (consumerId == null) {
            return List.of();
        }
        List<McpServiceAccessView> visible = new ArrayList<>();
        for (McpService service : mcpServiceRepository.findAllOnlineByTenantId(tenantId)) {
            if (!allows(tenantId, service.id(), consumerId)) {
                continue;
            }
            visible.add(onboardingService.access(tenantId, service.id()));
        }
        return visible;
    }

    /**
     * The server layer of {@link McpAccessPolicy}, read the way the snapshot reads
     * it.
     */
    private boolean allows(UUID tenantId, UUID serviceId, UUID consumerId) {
        Optional<com.miqroera.miqrokey.domain.model.McpServiceAccess> access = mcpAccessRepository.findService(tenantId,
                serviceId);
        if (access.isEmpty()) {
            // No access row: the snapshot's LEFT JOIN yields no mode, which the data
            // plane parses as NONE — everyone with a consumer credential may call.
            return McpAccessPolicy.isAllowed(McpAclMode.NONE, List.of(), null, List.of(), consumerId);
        }
        List<UUID> serverList = mcpAccessRepository.findGrants(tenantId, access.get().id()).stream()
                .filter(grant -> grant.toolId() == null).map(grant -> grant.consumerId()).toList();
        return McpAccessPolicy.isAllowed(access.get().mode(), serverList, null, List.of(), consumerId);
    }

    /**
     * The issued credential. {@code apiKey} is non-null only in the response that
     * created it — the plaintext is never stored and never shown again.
     */
    public record IssuedCredential(ApiConsumer consumer, String apiKey) {
    }
}
