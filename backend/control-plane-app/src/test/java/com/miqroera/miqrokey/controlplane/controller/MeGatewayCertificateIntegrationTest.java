package com.miqroera.miqrokey.controlplane.controller;

import tools.jackson.databind.ObjectMapper;
import com.miqroera.miqrokey.controlplane.AbstractControlPlaneIntegrationTest;
import com.miqroera.miqrokey.controlplane.controller.AdminProviderApiIntegrationTest.BootstrapHelper;
import com.miqroera.miqrokey.controlplane.dto.BootstrapRequest;
import com.miqroera.miqrokey.controlplane.dto.PasswordChangeRequest;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * #36: the portal hands the logged-in user the gateway certificate, so a
 * self-signed deployment can be trusted locally without anyone having to know a
 * server-side path.
 *
 * <p>
 * The "no certificate configured" branch lives in
 * {@code GatewayCertificateServiceTest} (a property-driven unit test); this
 * class covers the wire shape and the session requirement.
 * </p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Tag("integration")
@DisplayName("Gateway certificate export integration tests (PostgreSQL)")
class MeGatewayCertificateIntegrationTest {

    static {
        AbstractControlPlaneIntegrationTest.POSTGRES.getJdbcUrl();
    }

    /** The certificate the portal itself serves, in a self-signed deployment. */
    private static final String CERT_PATH = resolveCertPath();

    private static String resolveCertPath() {
        try {
            return new ClassPathResource("certificates/self-signed.pem").getFile().getAbsolutePath();
        } catch (IOException e) {
            throw new IllegalStateException("test certificate fixture is missing", e);
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        AbstractControlPlaneIntegrationTest.configureProperties(registry);
        registry.add("miqrokey.bootstrap-secret-file", () -> BootstrapHelper.secretFile().toAbsolutePath().toString());
        registry.add("miqrokey.gateway-tls.cert-file", () -> CERT_PATH);
    }

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    NamedParameterJdbcTemplate jdbc;

    private Cookie session;

    @BeforeEach
    void setUp() throws Exception {
        for (String table : List.of("admin_audit_events", "user_sessions", "users")) {
            jdbc.update("DELETE FROM " + table, new MapSqlParameterSource());
        }
        MvcResult boot = mockMvc
                .perform(post("/api/v1/auth/bootstrap").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new BootstrapRequest(BootstrapHelper.secret(), "portal_admin", "Admin"))))
                .andExpect(status().isCreated()).andReturn();
        session = cookie(boot, "MIQROKEY_SESSION");
        Cookie csrf = cookie(boot, "MIQROKEY_CSRF");
        Map<?, ?> body = objectMapper.readValue(boot.getResponse().getContentAsString(), Map.class);
        mockMvc.perform(post("/api/v1/auth/password").contentType(MediaType.APPLICATION_JSON).cookie(session, csrf)
                .header("X-CSRF-Token", csrf.getValue())
                .content(objectMapper.writeValueAsString(
                        new PasswordChangeRequest((String) body.get("temporaryPassword"), "NewSecurePass1!"))))
                .andExpect(status().isOk());
    }

    private static Cookie cookie(MvcResult result, String name) {
        Cookie[] cookies = result.getResponse().getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie;
            }
        }
        return null;
    }

    @Test
    @DisplayName("requires a portal session")
    void requiresSession() throws Exception {
        mockMvc.perform(get("/api/v1/me/gateway-certificate")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("serves the certificate, flagged self-signed, with nothing but public material")
    void servesSelfSignedCertificate() throws Exception {
        mockMvc.perform(get("/api/v1/me/gateway-certificate").cookie(session)).andExpect(status().isOk())
                .andExpect(jsonPath("$.available").value(true)).andExpect(jsonPath("$.selfSigned").value(true))
                .andExpect(jsonPath("$.subject").value("CN=miqrogate-test-selfsigned"))
                .andExpect(jsonPath("$.fileName").value("miqrogate-ca.pem"))
                .andExpect(jsonPath("$.fingerprintSha256").isNotEmpty())
                .andExpect(jsonPath("$.pem").value(org.hamcrest.Matchers.startsWith("-----BEGIN CERTIFICATE-----")))
                // 只下发证书：任何形式的私钥都不该出现在响应里
                .andExpect(jsonPath("$.pem")
                        .value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("PRIVATE KEY"))));
    }
}
