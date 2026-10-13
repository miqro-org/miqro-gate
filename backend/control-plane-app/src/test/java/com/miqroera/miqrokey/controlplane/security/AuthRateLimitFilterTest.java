package com.miqroera.miqrokey.controlplane.security;

import com.miqroera.miqrokey.controlplane.config.AuthRateLimitProperties;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * The auth-endpoint rate limit (ADR-0029 decision 2): what it counts, what it
 * must not count, and that the bucket follows the resolved address rather than
 * anything the caller can vary.
 */
@DisplayName("AuthRateLimitFilter")
class AuthRateLimitFilterTest {

    private static final String CREDENTIAL_PATH = "/api/v1/auth/login";
    private static final String EXTERNAL = "203.0.113.5";

    @Test
    @DisplayName("requests up to the limit reach the chain")
    void requestsUpToTheLimitPass() throws Exception {
        AuthRateLimitFilter filter = filter(3, Duration.ofMinutes(5), true);
        FilterChain chain = mock(FilterChain.class);

        for (int i = 0; i < 3; i++) {
            filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, null), new MockHttpServletResponse(), chain);
        }

        verify(chain, times(3)).doFilter(any(), any());
    }

    @Test
    @DisplayName("the request past the limit is refused with 429 and Retry-After")
    void theRequestPastTheLimitIsRefused() throws Exception {
        AuthRateLimitFilter filter = filter(2, Duration.ofMinutes(5), true);
        FilterChain chain = mock(FilterChain.class);
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, null), new MockHttpServletResponse(), chain);
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, null), new MockHttpServletResponse(), chain);

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, null), response, chain);

        verify(chain, times(2)).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isNotNull();
        assertThat(response.getContentAsString()).contains("rate_limited");
    }

    @Test
    @DisplayName("reads and other endpoints are never counted")
    void readsAreNotCounted() throws Exception {
        AuthRateLimitFilter filter = filter(1, Duration.ofMinutes(5), true);
        FilterChain chain = mock(FilterChain.class);

        // A session's ordinary reads, repeated past the limit, must be untouched.
        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest get = new MockHttpServletRequest("GET", "/api/v1/auth/me");
            get.setRequestURI("/api/v1/auth/me");
            get.setRemoteAddr(EXTERNAL);
            filter.doFilterInternal(get, new MockHttpServletResponse(), chain);
        }
        // And a POST elsewhere is none of this filter's business either.
        filter.doFilterInternal(post("/api/v1/admin/mcp-services", EXTERNAL, null), new MockHttpServletResponse(),
                chain);

        verify(chain, times(6)).doFilter(any(), any());
    }

    @Test
    @DisplayName("a forged X-Forwarded-For does not buy a fresh bucket")
    void forgedForwardedForDoesNotResetTheBucket() throws Exception {
        // No trusted proxies configured, so the header is never honored: varying it
        // must not move the caller out of the bucket it is already in.
        AuthRateLimitFilter filter = filter(2, Duration.ofMinutes(5), true);
        FilterChain chain = mock(FilterChain.class);
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, "198.51.100.7"), new MockHttpServletResponse(), chain);
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, "198.51.100.8"), new MockHttpServletResponse(), chain);

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, "198.51.100.9"), response, chain);

        assertThat(response.getStatus()).isEqualTo(429);
    }

    @Test
    @DisplayName("the window rolls over and the count starts again")
    void windowRollsOver() throws Exception {
        AuthRateLimitFilter filter = filter(1, Duration.ofMillis(150), true);
        FilterChain chain = mock(FilterChain.class);
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, null), new MockHttpServletResponse(), chain);

        Thread.sleep(300);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, null), response, chain);

        assertThat(response.getStatus()).isNotEqualTo(429);
        verify(chain, times(2)).doFilter(any(), any());
    }

    @Test
    @DisplayName("disabled means no counting at all")
    void disabledFilterPassesEverything() throws Exception {
        AuthRateLimitFilter filter = filter(1, Duration.ofMinutes(5), false);
        FilterChain chain = mock(FilterChain.class);

        for (int i = 0; i < 5; i++) {
            filter.doFilterInternal(post(CREDENTIAL_PATH, EXTERNAL, null), new MockHttpServletResponse(), chain);
        }

        verify(chain, times(5)).doFilter(any(), any());
    }

    // ------------------------------------------------------------------

    private static AuthRateLimitFilter filter(int maxRequests, Duration window, boolean enabled) {
        return new AuthRateLimitFilter(new AuthRateLimitProperties(enabled, maxRequests, window), List.of());
    }

    private static MockHttpServletRequest post(String path, String remoteAddr, String forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setRequestURI(path);
        request.setRemoteAddr(remoteAddr);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
        }
        return request;
    }
}
