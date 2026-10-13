package com.miqroera.miqrokey.controlplane.security;

import com.miqroera.miqrokey.domain.model.User;
import com.miqroera.miqrokey.domain.model.UserRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The deny-by-default gate on the admin surface, exercised at the path segment
 * boundary.
 *
 * <p>
 * The gate decides on {@code RequestPaths.lookupPath}, so these cases drive
 * real request paths through it. The bare {@code /api/v1/admin} is the
 * interesting one: it is a path the gate must cover even though no production
 * controller serves it today — the controllers that declare
 * {@code @RequestMapping
 * ("/api/v1/admin")} inherit it, so a method added without a sub-path lands
 * there, and an admin endpoint that the gate misses is reachable by any
 * authenticated user.
 * </p>
 */
@DisplayName("RoleInterceptor admin path gate")
class RoleInterceptorTest {

    private static final String ADMIN_ROOT = "/api/v1/admin";

    @Test
    @DisplayName("USER is denied on the bare /api/v1/admin path")
    void userDeniedOnBareAdminRoot() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean allowed = interceptor(UserRole.USER).preHandle(request(ADMIN_ROOT), response, new Object());

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("FORBIDDEN");
    }

    @Test
    @DisplayName("unauthenticated caller is denied on the bare /api/v1/admin path")
    void anonymousDeniedOnBareAdminRoot() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        UserContext context = new UserContext();

        boolean allowed = new RoleInterceptor(context).preHandle(request(ADMIN_ROOT), response, new Object());

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("SYSTEM_ADMIN passes on the bare /api/v1/admin path")
    void adminAllowedOnBareAdminRoot() throws Exception {
        assertThat(interceptor(UserRole.SYSTEM_ADMIN).preHandle(request(ADMIN_ROOT), new MockHttpServletResponse(),
                new Object())).isTrue();
    }

    @Test
    @DisplayName("USER is denied on an admin sub-path")
    void userDeniedOnAdminSubPath() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean allowed = interceptor(UserRole.USER).preHandle(request(ADMIN_ROOT + "/users"), response, new Object());

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    @DisplayName("the machine-credential surface /api/v1/admin-api is not swept into the session gate")
    void openAdminSurfaceIsNotGatedByRoleInterceptor() throws Exception {
        // /api/v1/admin-api/** is authenticated by AdminApiKeyAuthFilter (ADR-0015);
        // the segment after "admin" differs, so the session gate must not claim it.
        assertThat(interceptor(UserRole.USER).preHandle(request("/api/v1/admin-api/usage/summary"),
                new MockHttpServletResponse(), new Object())).isTrue();
    }

    // ------------------------------------------------------------------

    private static RoleInterceptor interceptor(UserRole role) {
        UserContext context = new UserContext();
        User user = mock(User.class);
        when(user.role()).thenReturn(role);
        context.setUser(user);
        return new RoleInterceptor(context);
    }

    private static MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRequestURI(path);
        return request;
    }
}
