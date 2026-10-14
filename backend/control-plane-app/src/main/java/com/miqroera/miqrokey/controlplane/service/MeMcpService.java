package com.miqroera.miqrokey.controlplane.service;

import com.miqroera.miqrokey.controlplane.dto.ApiConsumerView;
import com.miqroera.miqrokey.controlplane.dto.McpServiceAccessView;
import com.miqroera.miqrokey.domain.model.ApiConsumer;
import com.miqroera.miqrokey.domain.model.ConsumerCapabilities;
import com.miqroera.miqrokey.domain.model.McpAccessGrant;
import com.miqroera.miqrokey.domain.model.McpAccessPolicy;
import com.miqroera.miqrokey.domain.model.McpAclMode;
import com.miqroera.miqrokey.domain.model.McpService;
import com.miqroera.miqrokey.domain.model.McpServiceAccess;
import com.miqroera.miqrokey.domain.model.McpTool;
import com.miqroera.miqrokey.domain.model.User;
import com.miqroera.miqrokey.domain.repository.ApiConsumerRepository;
import com.miqroera.miqrokey.domain.repository.McpAccessRepository;
import com.miqroera.miqrokey.domain.repository.McpServiceRepository;
import com.miqroera.miqrokey.domain.repository.McpToolRepository;
import com.miqroera.miqrokey.domain.service.AuditService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Self-service MCP onboarding for portal users (ADR-0028, option A): every user
 * owns at most one "portal consumer" ({@code <username>@portal}, bound by
 * {@code owner_user_id}), and the services/tools they may call are exactly the
 * ones that consumer is granted — decided by the same {@link McpAccessPolicy}
 * the data plane applies, so the list can never drift from what a call would be
 * allowed to do.
 *
 * <p>
 * The credential is a normal consumer key (ADR-0010): issued once and shown
 * once, rotatable in place (the row — and therefore the ACL grants — survives
 * rotation), revocable by disabling the row. Everything is audited with the
 * user as the actor.
 * </p>
 */
@Service
public class MeMcpService {

    /** Naming convention that keeps portal credentials recognisable to admins. */
    static final String PORTAL_SUFFIX = "@portal";

    /** The MCP data plane is the only channel a portal credential needs. */
    private static final List<String> PORTAL_CAPABILITIES = List.of(ConsumerCapabilities.MCP_CALL);

    private static final String HINT_NOT_ISSUED = "先签发你的 MCP 凭据；可用范围由管理员按你的消费者授权，签发后这里会列出可用服务。";
    private static final String HINT_NOTHING_GRANTED = "你的凭据还没有被授权任何 MCP 服务；请联系管理员在「MCP 服务 → 访问控制」里为它授权。";

    private final ApiConsumerRepository consumerRepository;
    private final ApiConsumerService consumerService;
    private final McpServiceRepository serviceRepository;
    private final McpToolRepository toolRepository;
    private final McpAccessRepository accessRepository;
    private final McpOnboardingService onboardingService;
    private final AuditService auditService;
    private final RouteRefreshPublisher routeRefreshPublisher;

    public MeMcpService(ApiConsumerRepository consumerRepository, ApiConsumerService consumerService,
            McpServiceRepository serviceRepository, McpToolRepository toolRepository,
            McpAccessRepository accessRepository, McpOnboardingService onboardingService, AuditService auditService,
            RouteRefreshPublisher routeRefreshPublisher) {
        this.consumerRepository = consumerRepository;
        this.consumerService = consumerService;
        this.serviceRepository = serviceRepository;
        this.toolRepository = toolRepository;
        this.accessRepository = accessRepository;
        this.onboardingService = onboardingService;
        this.auditService = auditService;
        this.routeRefreshPublisher = routeRefreshPublisher;
    }

    // ------------------------------------------------------------------
    // credential
    // ------------------------------------------------------------------

    /**
     * Metadata of the caller's portal credential; {@code issued=false} when absent.
     */
    public McpCredentialView credential(User user) {
        return consumerRepository.findByOwnerUserId(user.tenantId(), user.id()).map(MeMcpService::view)
                .orElseGet(McpCredentialView::notIssued);
    }

    /** First issuance: creates the portal consumer. The key is shown only here. */
    @Transactional
    public IssuedCredential issue(User user, String requestId) {
        if (consumerRepository.findByOwnerUserId(user.tenantId(), user.id()).isPresent()) {
            throw new ApiException(HttpStatus.CONFLICT, "MCP_CREDENTIAL_ALREADY_ISSUED", "你已经有一把 MCP 凭据；要换 Key 请用轮换。");
        }
        String name = nameFor(user);
        ApiConsumerService.CreatedConsumer created;
        try {
            created = consumerService.create(user.tenantId(), user.id(), name, null, PORTAL_CAPABILITIES, user.id(),
                    requestId);
        } catch (ApiException e) {
            if ("CONSUMER_NAME_TAKEN".equals(e.getCode())) {
                throw new ApiException(HttpStatus.CONFLICT, "MCP_CREDENTIAL_NAME_TAKEN",
                        "凭据名 " + name + " 已被占用（通常由管理员手工创建）；请联系管理员处理后再试。");
            }
            throw e;
        }
        return new IssuedCredential(view(created.consumer()), created.apiKey());
    }

    /**
     * In-place key replacement: the consumer row (and its ACL grants) stays, so a
     * rotation never loses the user's access. Revoked credentials come back ACTIVE.
     */
    @Transactional
    public IssuedCredential rotate(User user, String requestId) {
        ApiConsumer mine = requireOwn(user);
        ApiConsumer.GeneratedKey key = ApiConsumer.generateKey();
        ApiConsumer rotated = consumerRepository.rotateKey(mine.id(), user.tenantId(), key.digest(), key.prefix());
        routeRefreshPublisher.publishChanged();
        auditService.record(user.tenantId(), user.id(), "CONSUMER_KEY_ROTATE", "CONSUMER", mine.id(), AuditSummaries
                .summary("name", AuditSummaries.sanitize(mine.name()), "from", mine.keyPrefix(), "to", key.prefix()),
                requestId);
        return new IssuedCredential(view(rotated), key.plaintext());
    }

    /** Disables the caller's credential; idempotent (a second call is a no-op). */
    @Transactional
    public McpCredentialView revoke(User user, String requestId) {
        ApiConsumer mine = requireOwn(user);
        if (!"DISABLED".equals(mine.status())) {
            consumerService.disable(user.tenantId(), user.id(), mine.id(), requestId);
        }
        return view(consumerRepository.findByIdAndTenantId(mine.id(), user.tenantId()).orElseThrow());
    }

    // ------------------------------------------------------------------
    // discovery
    // ------------------------------------------------------------------

    /**
     * Services (and their tools) the caller may call. The list is derived from the
     * caller's portal consumer through {@link McpAccessPolicy}: a service that
     * denies the consumer simply does not appear (issue #1's acceptance), a tool
     * that the ACL narrows away or that is disabled does not appear either.
     */
    public ServicesView services(User user) {
        Optional<ApiConsumer> mine = consumerRepository.findByOwnerUserId(user.tenantId(), user.id());
        List<McpServiceView> visible = new ArrayList<>();
        if (mine.isPresent()) {
            UUID consumerId = mine.get().id();
            for (McpService service : serviceRepository.findAllByTenantId(user.tenantId())) {
                McpServiceAccess access = accessRepository.findService(user.tenantId(), service.id()).orElse(null);
                McpAclMode serverMode = access == null ? McpAclMode.NONE : access.mode();
                List<McpAccessGrant> grants = access == null
                        ? List.of()
                        : accessRepository.findGrants(user.tenantId(), access.id());
                Set<UUID> serverConsumers = consumersOf(grants.stream().filter(g -> g.toolId() == null).toList());
                if (!McpAccessPolicy.isAllowed(serverMode, serverConsumers, null, List.of(), consumerId)) {
                    continue;
                }
                List<McpToolView> tools = new ArrayList<>();
                for (McpTool tool : toolRepository.findAllByService(user.tenantId(), service.id())) {
                    if (!"ENABLED".equals(tool.status())) {
                        continue;
                    }
                    List<McpAccessGrant> toolGrants = grants.stream().filter(g -> tool.id().equals(g.toolId()))
                            .toList();
                    McpAclMode override = toolGrants.isEmpty() ? null : toolGrants.get(0).mode();
                    if (!McpAccessPolicy.isAllowed(serverMode, serverConsumers, override, consumersOf(toolGrants),
                            consumerId)) {
                        continue;
                    }
                    tools.add(new McpToolView(tool.id(), tool.toolName(), tool.description()));
                }
                McpServiceAccessView urls = onboardingService.access(user.tenantId(), service.id());
                visible.add(new McpServiceView(service.id(), service.name(), service.description(), service.status(),
                        urls.mcpUrl(), urls.sseUrl(), tools));
            }
        }
        McpCredentialView credential = mine.map(MeMcpService::view).orElseGet(McpCredentialView::notIssued);
        String hint = credential.issued() ? (visible.isEmpty() ? HINT_NOTHING_GRANTED : null) : HINT_NOT_ISSUED;
        return new ServicesView(credential, McpOnboardingService.AUTH_HINT, hint, visible);
    }

    // ------------------------------------------------------------------

    private ApiConsumer requireOwn(User user) {
        return consumerRepository.findByOwnerUserId(user.tenantId(), user.id()).orElseThrow(
                () -> new ApiException(HttpStatus.NOT_FOUND, "MCP_CREDENTIAL_NOT_ISSUED", "你还没有 MCP 凭据，请先签发。"));
    }

    private static String nameFor(User user) {
        return user.username() + PORTAL_SUFFIX;
    }

    private static McpCredentialView view(ApiConsumer consumer) {
        return new McpCredentialView(true, consumer.id(), consumer.name(), consumer.keyPrefix(), consumer.status(),
                consumer.capabilities() == null ? null : List.copyOf(consumer.capabilities()), consumer.createdAt(),
                consumer.expiresAt());
    }

    /** Same shape from the service's own view type (used by the issue path). */
    private static McpCredentialView view(ApiConsumerView consumer) {
        return new McpCredentialView(true, consumer.id(), consumer.name(), consumer.keyPrefix(), consumer.status(),
                consumer.capabilities() == null ? null : List.copyOf(consumer.capabilities()), consumer.createdAt(),
                consumer.expiresAt());
    }

    private static Set<UUID> consumersOf(List<McpAccessGrant> grants) {
        Set<UUID> consumers = new LinkedHashSet<>();
        for (McpAccessGrant grant : grants) {
            consumers.add(grant.consumerId());
        }
        return consumers;
    }

    /** Credential metadata — never contains key material. */
    public record McpCredentialView(boolean issued, UUID consumerId, String name, String keyPrefix, String status,
            List<String> capabilities, Instant createdAt, Instant expiresAt) {

        static McpCredentialView notIssued() {
            return new McpCredentialView(false, null, null, null, null, null, null, null);
        }
    }

    /** Issue/rotate response: the plaintext key appears exactly once. */
    public record IssuedCredential(McpCredentialView credential, String apiKey, boolean shownOnce) {

        IssuedCredential(McpCredentialView credential, String apiKey) {
            this(credential, apiKey, true);
        }
    }

    public record McpToolView(UUID toolId, String toolName, String description) {
    }

    public record McpServiceView(UUID serviceId, String name, String description, String status, String mcpUrl,
            String sseUrl, List<McpToolView> tools) {
    }

    /**
     * {@code hint} is a user-facing one-liner, set only when {@code services} is
     * empty.
     */
    public record ServicesView(McpCredentialView credential, String authHint, String hint,
            List<McpServiceView> services) {
    }
}
