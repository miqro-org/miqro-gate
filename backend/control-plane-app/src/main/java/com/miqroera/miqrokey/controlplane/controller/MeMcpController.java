package com.miqroera.miqrokey.controlplane.controller;

import com.miqroera.miqrokey.controlplane.security.UserContext;
import com.miqroera.miqrokey.controlplane.service.MeMcpService;
import com.miqroera.miqrokey.domain.model.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Self-service MCP onboarding for the logged-in user (ADR-0028 option A):
 * discovery of the services/tools their credential may call, plus the
 * credential itself (issue / inspect / rotate / revoke). Session-authenticated
 * like every other {@code /me} surface — an API consumer key cannot reach it.
 *
 * <p>
 * Paths follow the ADR and issue #30: {@code /api/v1/me/mcp-services} for
 * discovery, {@code /api/v1/me/mcp-credential} for the credential lifecycle.
 * </p>
 */
@RestController
public class MeMcpController {

    private final MeMcpService meMcpService;
    private final UserContext userContext;

    public MeMcpController(MeMcpService meMcpService, UserContext userContext) {
        this.meMcpService = meMcpService;
        this.userContext = userContext;
    }

    /** Services and tools the caller's credential is allowed to call. */
    @GetMapping("/api/v1/me/mcp-services")
    public MeMcpService.ServicesView services() {
        return meMcpService.services(user());
    }

    /** Credential metadata ({@code issued=false} when the user has none yet). */
    @GetMapping("/api/v1/me/mcp-credential")
    public MeMcpService.McpCredentialView credential() {
        return meMcpService.credential(user());
    }

    /** First issuance; the key is returned here and nowhere else. */
    @PostMapping("/api/v1/me/mcp-credential")
    public ResponseEntity<MeMcpService.IssuedCredential> issue(HttpServletRequest httpReq) {
        return ResponseEntity.status(HttpStatus.CREATED).body(meMcpService.issue(user(), requestId(httpReq)));
    }

    /** Replaces the key in place; the consumer row (and its grants) is kept. */
    @PostMapping("/api/v1/me/mcp-credential/rotate")
    public MeMcpService.IssuedCredential rotate(HttpServletRequest httpReq) {
        return meMcpService.rotate(user(), requestId(httpReq));
    }

    /** Disables the credential; idempotent. */
    @PostMapping("/api/v1/me/mcp-credential/revoke")
    public MeMcpService.McpCredentialView revoke(HttpServletRequest httpReq) {
        return meMcpService.revoke(user(), requestId(httpReq));
    }

    private User user() {
        return userContext.getUser();
    }

    private static String requestId(HttpServletRequest request) {
        String header = request.getHeader("X-Request-Id");
        return header != null && !header.isBlank() ? header : UUID.randomUUID().toString();
    }
}
