package com.miqroera.miqrokey.controlplane.service;

import com.miqroera.miqrokey.controlplane.dto.McpServiceAccessView;
import com.miqroera.miqrokey.domain.model.ApiConsumer;
import com.miqroera.miqrokey.domain.model.ConsumerCapabilities;
import com.miqroera.miqrokey.domain.model.McpAclMode;
import com.miqroera.miqrokey.domain.model.McpAccessGrant;
import com.miqroera.miqrokey.domain.model.McpServiceAccess;
import com.miqroera.miqrokey.domain.model.McpService;
import com.miqroera.miqrokey.domain.repository.ApiConsumerRepository;
import com.miqroera.miqrokey.domain.repository.McpAccessRepository;
import com.miqroera.miqrokey.domain.repository.McpServiceRepository;
import com.miqroera.miqrokey.domain.service.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Self-service MCP credentials (ADR-0030). The listing is the interesting half:
 * it must agree with what the gateway would allow, and an unauthorised service
 * must not be named at all.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserMcpCredentialService")
class UserMcpCredentialServiceTest {

    private static final UUID TENANT = UUID.randomUUID();
    private static final UUID USER = UUID.randomUUID();
    private static final UUID CONSUMER = UUID.randomUUID();
    private static final UUID SERVICE = UUID.randomUUID();
    private static final UUID ACCESS = UUID.randomUUID();

    @Mock
    ApiConsumerRepository consumerRepository;
    @Mock
    McpServiceRepository mcpServiceRepository;
    @Mock
    McpAccessRepository mcpAccessRepository;
    @Mock
    McpOnboardingService onboardingService;
    @Mock
    AuditService auditService;
    @Mock
    RouteRefreshPublisher routeRefreshPublisher;

    UserMcpCredentialService service;

    @BeforeEach
    void setUp() {
        service = new UserMcpCredentialService(consumerRepository, mcpServiceRepository, mcpAccessRepository,
                onboardingService, auditService, routeRefreshPublisher);
    }

    @Test
    @DisplayName("a user with no credential yet sees no services")
    void noCredentialNoServices() {
        when(consumerRepository.findByTenantIdAndUserId(TENANT, USER)).thenReturn(Optional.empty());

        assertThat(service.visibleServices(TENANT, USER)).isEmpty();
    }

    @Test
    @DisplayName("with no access row the service is open, exactly as the data plane reads it")
    void missingAccessRowMeansOpen() {
        givenCredential();
        givenOnlineService();
        when(mcpAccessRepository.findService(TENANT, SERVICE)).thenReturn(Optional.empty());
        when(onboardingService.access(TENANT, SERVICE)).thenReturn(view());

        assertThat(service.visibleServices(TENANT, USER)).hasSize(1);
    }

    @Test
    @DisplayName("an ALLOW list without the caller hides the service entirely")
    void allowListWithoutTheCallerHidesTheService() {
        givenCredential();
        givenOnlineService();
        when(mcpAccessRepository.findService(TENANT, SERVICE)).thenReturn(Optional.of(access(McpAclMode.ALLOW)));
        when(mcpAccessRepository.findGrants(TENANT, ACCESS)).thenReturn(List.of(grant(UUID.randomUUID(), null)));

        assertThat(service.visibleServices(TENANT, USER)).isEmpty();
    }

    @Test
    @DisplayName("an ALLOW list naming the caller shows it")
    void allowListNamingTheCallerShowsIt() {
        givenCredential();
        givenOnlineService();
        when(mcpAccessRepository.findService(TENANT, SERVICE)).thenReturn(Optional.of(access(McpAclMode.ALLOW)));
        when(mcpAccessRepository.findGrants(TENANT, ACCESS)).thenReturn(List.of(grant(CONSUMER, null)));
        when(onboardingService.access(TENANT, SERVICE)).thenReturn(view());

        assertThat(service.visibleServices(TENANT, USER)).hasSize(1);
    }

    @Test
    @DisplayName("a DENY list naming the caller hides it")
    void denyListNamingTheCallerHidesIt() {
        givenCredential();
        givenOnlineService();
        when(mcpAccessRepository.findService(TENANT, SERVICE)).thenReturn(Optional.of(access(McpAclMode.DENY)));
        when(mcpAccessRepository.findGrants(TENANT, ACCESS)).thenReturn(List.of(grant(CONSUMER, null)));

        assertThat(service.visibleServices(TENANT, USER)).isEmpty();
    }

    @Test
    @DisplayName("a tool-level grant is not a server-level one")
    void toolLevelGrantsAreNotReadAsServerGrants() {
        givenCredential();
        givenOnlineService();
        when(mcpAccessRepository.findService(TENANT, SERVICE)).thenReturn(Optional.of(access(McpAclMode.ALLOW)));
        // Only a tool-scoped grant exists, so the server layer is an empty ALLOW list.
        when(mcpAccessRepository.findGrants(TENANT, ACCESS)).thenReturn(List.of(grant(CONSUMER, UUID.randomUUID())));

        assertThat(service.visibleServices(TENANT, USER)).isEmpty();
    }

    @Test
    @DisplayName("issuing creates one owned consumer carrying only mcp:call")
    void issuingCreatesAnOwnedConsumer() {
        when(consumerRepository.findByTenantIdAndUserId(TENANT, USER)).thenReturn(Optional.empty());

        UserMcpCredentialService.IssuedCredential issued = service.issueOrGet(TENANT, USER, "alice", "req-1");

        assertThat(issued.apiKey()).startsWith("mqk_api_");
        assertThat(issued.consumer().capabilities()).containsExactly(ConsumerCapabilities.MCP_CALL);
        ArgumentCaptor<ApiConsumer> inserted = ArgumentCaptor.forClass(ApiConsumer.class);
        verify(consumerRepository).insertOwnedBy(inserted.capture(), eq(USER));
        assertThat(inserted.getValue().name()).isEqualTo("user:alice");
    }

    @Test
    @DisplayName("issuing twice does not mint a second key")
    void issuingIsIdempotent() {
        when(consumerRepository.findByTenantIdAndUserId(TENANT, USER)).thenReturn(Optional.of(consumer()));

        UserMcpCredentialService.IssuedCredential issued = service.issueOrGet(TENANT, USER, "alice", "req-1");

        assertThat(issued.apiKey()).isNull();
        verify(consumerRepository, org.mockito.Mockito.never()).insertOwnedBy(any(), any());
    }

    // ------------------------------------------------------------------

    private void givenCredential() {
        when(consumerRepository.findByTenantIdAndUserId(TENANT, USER)).thenReturn(Optional.of(consumer()));
    }

    private void givenOnlineService() {
        when(mcpServiceRepository.findAllOnlineByTenantId(TENANT)).thenReturn(List.of(serviceRecord()));
    }

    private static ApiConsumer consumer() {
        return new ApiConsumer(CONSUMER, TENANT, "user:alice", new byte[32], "abcd1234", "ACTIVE", null, null, null, 0,
                Instant.now(), Instant.now(), List.of(ConsumerCapabilities.MCP_CALL), null);
    }

    private static McpService serviceRecord() {
        return new McpService(SERVICE, TENANT, "slurm", "desc", "https://mcp.example/mcp", "STREAMABLE_HTTP", "ONLINE",
                "HEALTHY", Instant.now(), 0, 1, 30, 5, 3, 1, "/health", 0, UUID.randomUUID(), Instant.now(),
                Instant.now(), "VISITOR", null, 60000, "HEALTH_PATH");
    }

    private static McpServiceAccess access(McpAclMode mode) {
        return new McpServiceAccess(ACCESS, TENANT, SERVICE, mode, UUID.randomUUID(), 0, Instant.now(), Instant.now());
    }

    private static McpAccessGrant grant(UUID consumerId, UUID toolId) {
        return new McpAccessGrant(UUID.randomUUID(), TENANT, ACCESS, toolId, consumerId, McpAclMode.ALLOW,
                UUID.randomUUID(), 0, Instant.now(), Instant.now());
    }

    private static McpServiceAccessView view() {
        return new McpServiceAccessView(SERVICE, "slurm", "https://gw/mcpservers/slurm/mcp",
                "https://gw/mcpservers/slurm/sse", "auth hint");
    }
}
