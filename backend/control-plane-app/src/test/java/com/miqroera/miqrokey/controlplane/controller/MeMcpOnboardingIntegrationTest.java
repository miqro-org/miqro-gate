package com.miqroera.miqrokey.controlplane.controller;

import tools.jackson.databind.ObjectMapper;
import com.miqroera.miqrokey.controlplane.AbstractControlPlaneIntegrationTest;
import com.miqroera.miqrokey.controlplane.controller.AdminProviderApiIntegrationTest.BootstrapHelper;
import com.miqroera.miqrokey.controlplane.dto.BootstrapRequest;
import com.miqroera.miqrokey.controlplane.dto.PasswordChangeRequest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Portal self-service MCP onboarding (ADR-0028 option A, issue #30).
 *
 * <p>
 * Two things must hold at once: the credential is an ordinary consumer key with
 * exactly the {@code mcp:call} channel, and the discovered service/tool list is
 * derived from the same {@code McpAccessPolicy} the data plane enforces — so a
 * service or tool the user could not call never appears, and granting or
 * narrowing access changes the list immediately.
 * </p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Tag("integration")
@DisplayName("Portal self-service MCP onboarding integration tests (PostgreSQL)")
class MeMcpOnboardingIntegrationTest {

    static {
        AbstractControlPlaneIntegrationTest.POSTGRES.getJdbcUrl();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        AbstractControlPlaneIntegrationTest.configureProperties(registry);
        registry.add("miqrokey.bootstrap-secret-file", () -> BootstrapHelper.secretFile().toAbsolutePath().toString());
    }

    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    NamedParameterJdbcTemplate jdbc;

    private Cookie adminSession;
    private Cookie adminCsrf;
    private String adminCsrfToken;
    private UUID adminUserId;

    @BeforeEach
    void setUp() throws Exception {
        for (String table : List.of("mcp_access_grants", "mcp_service_access", "mcp_tools", "mcp_services",
                "api_consumers", "admin_audit_events", "user_sessions", "users")) {
            jdbc.update("DELETE FROM " + table, new MapSqlParameterSource());
        }
        MvcResult boot = mockMvc
                .perform(post("/api/v1/auth/bootstrap").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new BootstrapRequest(BootstrapHelper.secret(), "portal_admin", "Admin"))))
                .andExpect(status().isCreated()).andReturn();
        adminSession = cookie(boot, "MIQROKEY_SESSION");
        adminCsrf = cookie(boot, "MIQROKEY_CSRF");
        adminCsrfToken = adminCsrf == null ? "" : adminCsrf.getValue();
        Map<?, ?> body = objectMapper.readValue(boot.getResponse().getContentAsString(), Map.class);
        mockMvc.perform(post("/api/v1/auth/password").contentType(MediaType.APPLICATION_JSON)
                .cookie(adminSession, adminCsrf).header("X-CSRF-Token", adminCsrfToken)
                .content(objectMapper.writeValueAsString(
                        new PasswordChangeRequest((String) body.get("temporaryPassword"), "NewSecurePass1!"))))
                .andExpect(status().isOk());
        adminUserId = jdbc.queryForObject("SELECT id FROM users WHERE username = 'portal_admin'",
                new MapSqlParameterSource(), UUID.class);
    }

    @AfterEach
    void tearDown() {
        for (String table : List.of("mcp_access_grants", "mcp_service_access", "mcp_tools", "mcp_services",
                "api_consumers", "admin_audit_events", "user_sessions", "users")) {
            jdbc.update("DELETE FROM " + table, new MapSqlParameterSource());
        }
    }

    // ------------------------------------------------------------------
    // credential lifecycle
    // ------------------------------------------------------------------

    @Test
    @DisplayName("issue → inspect → rotate → revoke: one key per user, MCP-scoped, grants survive rotation")
    void credentialLifecycle() throws Exception {
        UserSession user = createUser("alice");

        mockMvc.perform(get("/api/v1/me/mcp-credential").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.issued").value(false));

        MvcResult issued = mockMvc
                .perform(post("/api/v1/me/mcp-credential").cookie(user.session(), user.csrf()).header("X-CSRF-Token",
                        user.csrfToken()))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.shownOnce").value(true))
                .andExpect(jsonPath("$.credential.name").value("alice@portal"))
                .andExpect(jsonPath("$.credential.capabilities[0]").value("mcp:call")).andReturn();
        Map<?, ?> issuedBody = objectMapper.readValue(issued.getResponse().getContentAsString(), Map.class);
        String firstKey = (String) issuedBody.get("apiKey");
        String credentialId = ((Map<?, ?>) issuedBody.get("credential")).get("consumerId").toString();
        assertThat(firstKey).startsWith("mqk_api_");

        // It is a real consumer key, scoped to the MCP channel only: the billing
        // channel rejects it.
        mockMvc.perform(get("/api/v1/billing/summary").header("X-API-Key", firstKey)).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("CONSUMER_SCOPE_DENIED"));

        // Inspect: metadata only, and the key material never comes back.
        mockMvc.perform(get("/api/v1/me/mcp-credential").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.issued").value(true)).andExpect(jsonPath("$.apiKey").doesNotExist())
                .andExpect(jsonPath("$.keyPrefix").isNotEmpty());

        // A second issuance is refused — rotation is the way to get a new key.
        mockMvc.perform(post("/api/v1/me/mcp-credential").cookie(user.session(), user.csrf()).header("X-CSRF-Token",
                user.csrfToken())).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MCP_CREDENTIAL_ALREADY_ISSUED"));

        // Rotate in place: same consumer row (so any ACL grants survive), new key
        // material.
        String digestBefore = jdbc.queryForObject("SELECT encode(key_digest, 'hex') FROM api_consumers WHERE id = :id",
                new MapSqlParameterSource("id", UUID.fromString(credentialId)), String.class);
        MvcResult rotated = mockMvc.perform(post("/api/v1/me/mcp-credential/rotate").cookie(user.session(), user.csrf())
                .header("X-CSRF-Token", user.csrfToken())).andExpect(status().isOk()).andReturn();
        String secondKey = (String) objectMapper.readValue(rotated.getResponse().getContentAsString(), Map.class)
                .get("apiKey");
        assertThat(secondKey).isNotEqualTo(firstKey);
        String digestAfter = jdbc.queryForObject("SELECT encode(key_digest, 'hex') FROM api_consumers WHERE id = :id",
                new MapSqlParameterSource("id", UUID.fromString(credentialId)), String.class);
        assertThat(digestAfter).isNotEqualTo(digestBefore);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM api_consumers WHERE owner_user_id IS NOT NULL",
                new MapSqlParameterSource(), Long.class)).isEqualTo(1L);

        // Revoke: disabled and idempotent; rotating again brings it back ACTIVE.
        mockMvc.perform(post("/api/v1/me/mcp-credential/revoke").cookie(user.session(), user.csrf())
                .header("X-CSRF-Token", user.csrfToken())).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DISABLED"));
        mockMvc.perform(post("/api/v1/me/mcp-credential/revoke").cookie(user.session(), user.csrf())
                .header("X-CSRF-Token", user.csrfToken())).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DISABLED"));
        mockMvc.perform(post("/api/v1/me/mcp-credential/rotate").cookie(user.session(), user.csrf())
                .header("X-CSRF-Token", user.csrfToken())).andExpect(status().isOk())
                .andExpect(jsonPath("$.credential.status").value("ACTIVE"));

        // Rotating before ever issuing is a clear 404, not a silent create.
        UserSession bob = createUser("bob");
        mockMvc.perform(post("/api/v1/me/mcp-credential/rotate").cookie(bob.session(), bob.csrf())
                .header("X-CSRF-Token", bob.csrfToken())).andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("MCP_CREDENTIAL_NOT_ISSUED"));

        // The rotation is audited against the user as the actor.
        Long rotations = jdbc.queryForObject(
                "SELECT count(*) FROM admin_audit_events WHERE action = 'CONSUMER_KEY_ROTATE' AND actor_id = :actor",
                new MapSqlParameterSource("actor", user.userId()), Long.class);
        assertThat(rotations).isEqualTo(2L);
    }

    // ------------------------------------------------------------------
    // discovery follows the data plane's ACL
    // ------------------------------------------------------------------

    @Test
    @DisplayName("discovery lists exactly what the credential may call: server list, tool override, disabled tool")
    void discoveryFollowsAcl() throws Exception {
        UUID serviceId = insertService("slurm-mcp");
        UUID toolA = insertTool(serviceId, "list_partitions");
        UUID toolB = insertTool(serviceId, "submit_job");
        UserSession user = createUser("carol");
        UserSession other = createUser("dave");

        // No credential yet: nothing to evaluate, and the hint says what to do.
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.credential.issued").value(false))
                .andExpect(jsonPath("$.services.length()").value(0)).andExpect(jsonPath("$.hint").isNotEmpty());

        mockMvc.perform(post("/api/v1/me/mcp-credential").cookie(user.session(), user.csrf()).header("X-CSRF-Token",
                user.csrfToken())).andExpect(status().isCreated());
        // 'other' needs a consumer of their own to appear in an ALLOW list (grants have
        // an FK to api_consumers).
        mockMvc.perform(post("/api/v1/me/mcp-credential").cookie(other.session(), other.csrf()).header("X-CSRF-Token",
                other.csrfToken())).andExpect(status().isCreated());
        UUID carolConsumer = consumerOf("carol");
        UUID daveConsumer = consumerOf("dave");

        // Server mode NONE (open): the service and both enabled tools show up.
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.credential.issued").value(true))
                .andExpect(jsonPath("$.services[0].name").value("slurm-mcp"))
                .andExpect(jsonPath("$.services[0].mcpUrl")
                        .value(org.hamcrest.Matchers.containsString("/mcpservers/slurm-mcp/mcp")))
                .andExpect(jsonPath("$.services[0].tools.length()").value(2));

        // Server ALLOW listing someone else → the service must disappear from the
        // user's list.
        setServerMode(serviceId, "ALLOW", List.of(daveConsumer));
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.services.length()").value(0)).andExpect(jsonPath("$.hint").isNotEmpty());

        // …and reappear once the list names the caller's own consumer.
        setServerMode(serviceId, "ALLOW", List.of(carolConsumer));
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.services.length()").value(1))
                .andExpect(jsonPath("$.services[0].tools.length()").value(2));

        // Tool-level overrides only exist while the server is open (mode NONE, #316
        // semantics):
        // narrow toolA to someone else → it vanishes for carol, toolB (no override)
        // stays.
        setServerMode(serviceId, "NONE", List.of());
        setToolGrants(serviceId, toolA, "ALLOW", List.of(daveConsumer));
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.services[0].tools.length()").value(1))
                .andExpect(jsonPath("$.services[0].tools[0].toolName").value("submit_job"));

        // A disabled tool is not callable, so it must not be listed either.
        mockMvc.perform(post("/api/v1/admin/mcp-services/" + serviceId + "/tools/" + toolB + "/status")
                .param("status", "DISABLED").cookie(adminSession, adminCsrf).header("X-CSRF-Token", adminCsrfToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(user.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.services.length()").value(1))
                .andExpect(jsonPath("$.services[0].tools.length()").value(0));
    }

    // ------------------------------------------------------------------
    // isolation
    // ------------------------------------------------------------------

    @Test
    @DisplayName("one user's credential is invisible to another: no shared keys, no cross-user listing")
    void credentialsArePerUser() throws Exception {
        UUID serviceId = insertService("slurm-mcp");
        UUID tool = insertTool(serviceId, "list_partitions");
        UserSession alice = createUser("alice");
        mockMvc.perform(post("/api/v1/me/mcp-credential").cookie(alice.session(), alice.csrf()).header("X-CSRF-Token",
                alice.csrfToken())).andExpect(status().isCreated());
        setServerMode(serviceId, "ALLOW", List.of(consumerOf("alice")));

        UserSession bob = createUser("bob");
        mockMvc.perform(get("/api/v1/me/mcp-credential").cookie(bob.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.issued").value(false));
        // Bob has no credential, so alice's grant cannot leak into his list.
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(bob.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.services.length()").value(0));

        MvcResult bobIssued = mockMvc.perform(post("/api/v1/me/mcp-credential").cookie(bob.session(), bob.csrf())
                .header("X-CSRF-Token", bob.csrfToken())).andExpect(status().isCreated()).andReturn();
        String bobKey = (String) objectMapper.readValue(bobIssued.getResponse().getContentAsString(), Map.class)
                .get("apiKey");
        String aliceKey = jdbc.queryForObject("SELECT key_prefix FROM api_consumers WHERE owner_user_id = :owner",
                new MapSqlParameterSource("owner", alice.userId()), String.class);
        assertThat(bobKey).doesNotContain(aliceKey);
        // Still nothing for bob: the server list names alice's consumer only.
        mockMvc.perform(get("/api/v1/me/mcp-services").cookie(bob.session())).andExpect(status().isOk())
                .andExpect(jsonPath("$.services.length()").value(0));

        // The credential is bound to exactly one user.
        assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM api_consumers WHERE owner_user_id = :owner AND name = 'alice@portal'",
                new MapSqlParameterSource("owner", alice.userId()), Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(DISTINCT owner_user_id) FROM api_consumers",
                new MapSqlParameterSource(), Long.class)).isEqualTo(2L);
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private record UserSession(Cookie session, Cookie csrf, String csrfToken, UUID userId) {
    }

    /** Creates a USER through the admin API and returns a usable session. */
    private UserSession createUser(String username) throws Exception {
        MvcResult created = mockMvc
                .perform(post("/api/v1/admin/users").contentType(MediaType.APPLICATION_JSON)
                        .cookie(adminSession, adminCsrf).header("X-CSRF-Token", adminCsrfToken)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", username, "displayName", username, "role", "USER"))))
                .andExpect(status().isOk()).andReturn();
        Map<?, ?> createdBody = objectMapper.readValue(created.getResponse().getContentAsString(), Map.class);
        String temp = (String) createdBody.get("temporaryPassword");
        UUID userId = UUID.fromString(((Map<?, ?>) createdBody.get("user")).get("id").toString());

        MvcResult login = mockMvc
                .perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("username", username, "password", temp))))
                .andExpect(status().isOk()).andReturn();
        Cookie session = cookie(login, "MIQROKEY_SESSION");
        Cookie csrf = cookie(login, "MIQROKEY_CSRF");
        String csrfToken = csrf == null ? "" : csrf.getValue();
        // Forced password change clears the PASSWORD_CHANGE_REQUIRED gate on /me/*.
        mockMvc.perform(post("/api/v1/auth/password").contentType(MediaType.APPLICATION_JSON).cookie(session, csrf)
                .header("X-CSRF-Token", csrfToken)
                .content(objectMapper.writeValueAsString(new PasswordChangeRequest(temp, "UserSecurePass1!"))))
                .andExpect(status().isOk());
        return new UserSession(session, csrf, csrfToken, userId);
    }

    private UUID consumerOf(String username) {
        return jdbc.queryForObject("SELECT id FROM api_consumers WHERE name = :name",
                new MapSqlParameterSource("name", username + "@portal"), UUID.class);
    }

    private UUID insertService(String name) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO mcp_services (id, tenant_id, name, endpoint, created_by)
                VALUES (:id, :tenantId, :name, 'https://mcp.example.com/mcp', :createdBy)
                """, new MapSqlParameterSource("id", id).addValue("tenantId", TENANT).addValue("name", name)
                .addValue("createdBy", adminUserId));
        return id;
    }

    private UUID insertTool(UUID serviceId, String toolName) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO mcp_tools (id, tenant_id, mcp_service_id, tool_name, method, path, status, created_by)
                VALUES (:id, :tenantId, :serviceId, :toolName, 'POST', '/mcp', 'ENABLED', :createdBy)
                """, new MapSqlParameterSource("id", id).addValue("tenantId", TENANT).addValue("serviceId", serviceId)
                .addValue("toolName", toolName).addValue("createdBy", adminUserId));
        return id;
    }

    private void setServerMode(UUID serviceId, String mode, List<UUID> consumerIds) throws Exception {
        mockMvc.perform(put("/api/v1/admin/mcp-services/" + serviceId + "/access/mode")
                .contentType(MediaType.APPLICATION_JSON).cookie(adminSession, adminCsrf)
                .header("X-CSRF-Token", adminCsrfToken).content(objectMapper.writeValueAsString(Map.of("mode", mode))))
                .andExpect(status().isOk());
        if (!consumerIds.isEmpty()) {
            mockMvc.perform(put("/api/v1/admin/mcp-services/" + serviceId + "/access/grants")
                    .contentType(MediaType.APPLICATION_JSON).cookie(adminSession, adminCsrf)
                    .header("X-CSRF-Token", adminCsrfToken)
                    .content(objectMapper.writeValueAsString(
                            Map.of("mode", mode, "consumerIds", consumerIds.stream().map(UUID::toString).toList()))))
                    .andExpect(status().isOk());
        }
    }

    private void setToolGrants(UUID serviceId, UUID toolId, String mode, List<UUID> consumerIds) throws Exception {
        mockMvc.perform(
                put("/api/v1/admin/mcp-services/" + serviceId + "/access/grants")
                        .contentType(MediaType.APPLICATION_JSON).cookie(adminSession, adminCsrf)
                        .header("X-CSRF-Token", adminCsrfToken)
                        .content(objectMapper.writeValueAsString(Map.of("toolId", toolId.toString(), "mode", mode,
                                "consumerIds", consumerIds.stream().map(UUID::toString).toList()))))
                .andExpect(status().isOk());
    }

    private static Cookie cookie(MvcResult r, String name) {
        if (r.getResponse().getCookies() == null) {
            return null;
        }
        for (Cookie c : r.getResponse().getCookies()) {
            if (name.equals(c.getName())) {
                return c;
            }
        }
        return null;
    }
}
