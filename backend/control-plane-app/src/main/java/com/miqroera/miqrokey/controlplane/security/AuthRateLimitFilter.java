package com.miqroera.miqrokey.controlplane.security;

import com.miqroera.miqrokey.controlplane.config.AuthRateLimitProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-source rate limit on the credential-guessing surface (ADR-0029 decision
 * 2).
 *
 * <p>
 * Account lockout alone bounds guessing per <em>username</em>, and it is the
 * attacker who decides when to spend those failures; this bounds what one
 * source can spend overall. Both are needed, because neither covers the other's
 * case.
 * </p>
 *
 * <p>
 * Deliberately narrow. Only POSTs to the endpoints that accept a credential are
 * counted — a session's ordinary reads must not be throttled, and the inference
 * data plane is out of scope entirely (ADR-0026). The address comes from
 * {@link ClientAddressResolver}, the same resolution the IP allowlist uses: if
 * the two disagreed about who is calling, an address the allowlist permits
 * could be a different address than the one counted here.
 * </p>
 *
 * <p>
 * State is per instance and in memory. A multi-instance deployment therefore
 * multiplies the effective limit by the instance count — acceptable for a
 * control plane that runs one, and honest about it rather than implying a
 * shared budget this does not keep.
 * </p>
 */
public class AuthRateLimitFilter extends OncePerRequestFilter {

    /** The endpoints that take a credential, i.e. where guessing pays off. */
    private static final Set<String> CREDENTIAL_PATHS = Set.of("/api/v1/auth/login", "/api/v1/auth/register",
            "/api/v1/auth/bootstrap", "/api/v1/auth/password");

    /** Bucket for requests whose source address cannot be determined. */
    private static final String UNKNOWN_SOURCE = "unknown";

    /**
     * Past this many distinct sources, expired windows are dropped on the next
     * request. Keeps the map bounded without a scheduler, and the entries are tiny.
     */
    private static final int SWEEP_THRESHOLD = 10_000;

    private final AuthRateLimitProperties properties;
    private final ClientAddressResolver clientAddresses;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public AuthRateLimitFilter(AuthRateLimitProperties properties, List<IpCidrMatcher> trustedProxies) {
        this.properties = properties;
        this.clientAddresses = new ClientAddressResolver(trustedProxies);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!properties.enabled() || !isCredentialAttempt(request)) {
            chain.doFilter(request, response);
            return;
        }

        String source = clientAddresses.resolve(request);
        Decision decision = count(source == null || source.isBlank() ? UNKNOWN_SOURCE : source);
        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }

        response.setStatus(429);
        response.setContentType("application/problem+json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Retry-After", Long.toString(decision.retryAfterSeconds()));
        response.getWriter().write(ProblemJson.of(429, "Too Many Requests", "rate_limited", null, requestId(request)));
    }

    private static boolean isCredentialAttempt(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        // The same normalized path the router matched on (#723) — a semicolon or
        // encoded separator must not make a counted request look uncounted.
        return CREDENTIAL_PATHS.contains(RequestPaths.lookupPath(request));
    }

    private Decision count(String source) {
        long now = System.currentTimeMillis();
        long windowMillis = properties.window().toMillis();
        if (windows.size() > SWEEP_THRESHOLD) {
            windows.entrySet().removeIf(entry -> now - entry.getValue().start >= windowMillis);
        }
        Window window = windows.compute(source, (key, existing) -> {
            if (existing == null || now - existing.start >= windowMillis) {
                return new Window(now);
            }
            existing.count++;
            return existing;
        });
        long millisLeft = window.start + windowMillis - now;
        long retryAfterSeconds = millisLeft <= 0 ? 1 : (millisLeft + 999) / 1000;
        return new Decision(window.count <= properties.maxRequests(), retryAfterSeconds);
    }

    private static String requestId(HttpServletRequest request) {
        String header = request.getHeader("X-Request-Id");
        String value = header != null && !header.isBlank() ? header : UUID.randomUUID().toString();
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** Outcome of one counted request. */
    private record Decision(boolean allowed, long retryAfterSeconds) {
    }

    /** A fixed window's start and the number of requests counted inside it. */
    private static final class Window {

        private final long start;
        private int count = 1;

        Window(long start) {
            this.start = start;
        }
    }
}
