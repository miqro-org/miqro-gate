package com.miqroera.miqrokey.controlplane.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The shared client-address resolution (#445). Both the IP allowlist and the
 * auth-endpoint rate limit decide on this value, so its rules — especially that
 * a caller cannot influence the outcome — are pinned here rather than through
 * either consumer.
 */
@DisplayName("ClientAddressResolver")
class ClientAddressResolverTest {

    private static final String TRUSTED_PROXY = "10.0.0.1";
    private static final String CLIENT = "203.0.113.9";

    private static ClientAddressResolver resolverTrusting(String cidr) {
        return new ClientAddressResolver(List.of(IpCidrMatcher.parse(cidr)));
    }

    @Test
    @DisplayName("an untrusted peer is the answer, header or not")
    void untrustedPeerWins() {
        MockHttpServletRequest request = requestFrom(CLIENT, "198.51.100.7");

        assertThat(resolverTrusting("10.0.0.0/8").resolve(request)).isEqualTo(CLIENT);
    }

    @Test
    @DisplayName("a trusted proxy reveals the client behind it")
    void trustedProxyRevealsTheClient() {
        MockHttpServletRequest request = requestFrom(TRUSTED_PROXY, CLIENT + ", " + TRUSTED_PROXY);

        assertThat(resolverTrusting("10.0.0.0/8").resolve(request)).isEqualTo(CLIENT);
    }

    @Test
    @DisplayName("a forged entry prepended by the client is ignored — the walk starts from the right")
    void forgedLeftmostEntryIsIgnored() {
        // Append-style proxy: the real client lands last, whatever the caller sent.
        MockHttpServletRequest request = requestFrom(TRUSTED_PROXY, "198.51.100.7, " + CLIENT);

        assertThat(resolverTrusting("10.0.0.0/8").resolve(request)).isEqualTo(CLIENT);
    }

    @Test
    @DisplayName("a chain of nothing but our own proxies falls back to the peer")
    void allTrustedChainFallsBackToThePeer() {
        MockHttpServletRequest request = requestFrom(TRUSTED_PROXY, "10.0.0.2, 10.0.0.3");

        assertThat(resolverTrusting("10.0.0.0/8").resolve(request)).isEqualTo(TRUSTED_PROXY);
    }

    @Test
    @DisplayName("a blank header from a trusted proxy falls back to the peer")
    void blankHeaderFallsBackToThePeer() {
        MockHttpServletRequest request = requestFrom(TRUSTED_PROXY, "   ");

        assertThat(resolverTrusting("10.0.0.0/8").resolve(request)).isEqualTo(TRUSTED_PROXY);
    }

    private static MockHttpServletRequest requestFrom(String peer, String forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr(peer);
        request.addHeader("X-Forwarded-For", forwardedFor);
        return request;
    }
}
