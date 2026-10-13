package com.miqroera.miqrokey.controlplane.security;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The portal IP allowlist and the paths that sit outside its semantics.
 *
 * <p>
 * The exemption predicate decides on the same lookup path the router uses, so
 * these cases drive real request paths. The bare {@code /api/v1/billing} is the
 * interesting one: the billing channel is API-key/JWT authenticated and reached
 * by external systems that are by definition not in the portal allowlist, so a
 * miss here does not fail open — it blocks the channel. That is the opposite
 * cost from the admin gate's miss, which is why both directions are asserted
 * below.
 * </p>
 */
@DisplayName("AdminIpAllowlistFilter exemptions")
class AdminIpAllowlistFilterTest {

    /** Not in the allowlist below — every request in this test looks external. */
    private static final String EXTERNAL = "203.0.113.5";

    @Test
    @DisplayName("the bare /api/v1/billing path is exempt, like its children")
    void bareBillingPathIsExempt() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filterWithAllowlist().doFilterInternal(request("/api/v1/billing", EXTERNAL), response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isNotEqualTo(403);
    }

    @Test
    @DisplayName("a billing sub-path is exempt")
    void billingSubPathIsExempt() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filterWithAllowlist().doFilterInternal(request("/api/v1/billing/summary", EXTERNAL), response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isNotEqualTo(403);
    }

    @Test
    @DisplayName("the one-time bootstrap endpoint is exempt")
    void bootstrapIsExempt() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filterWithAllowlist().doFilterInternal(request("/api/v1/auth/bootstrap", EXTERNAL), response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isNotEqualTo(403);
    }

    @Test
    @DisplayName("a non-exempt path from outside the allowlist is refused with IP_NOT_ALLOWED")
    void nonExemptPathIsRefused() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filterWithAllowlist().doFilterInternal(request("/api/v1/admin/users", EXTERNAL), response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("IP_NOT_ALLOWED");
    }

    @Test
    @DisplayName("an allowlisted address passes")
    void allowlistedAddressPasses() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filterWithAllowlist().doFilterInternal(request("/api/v1/admin/users", "10.1.2.3"), response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isNotEqualTo(403);
    }

    // ------------------------------------------------------------------

    private static AdminIpAllowlistFilter filterWithAllowlist() {
        return new AdminIpAllowlistFilter(List.of(IpCidrMatcher.parse("10.0.0.0/8")), List.of());
    }

    private static MockHttpServletRequest request(String path, String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRequestURI(path);
        request.setRemoteAddr(remoteAddr);
        return request;
    }
}
