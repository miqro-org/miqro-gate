package com.miqroera.miqrokey.controlplane.controller;

import com.miqroera.miqrokey.controlplane.dto.McpServiceAccessView;
import com.miqroera.miqrokey.controlplane.dto.MeMcpCredentialIssueView;
import com.miqroera.miqrokey.controlplane.dto.MeMcpCredentialView;
import com.miqroera.miqrokey.controlplane.security.UserContext;
import com.miqroera.miqrokey.controlplane.service.ApiException;
import com.miqroera.miqrokey.controlplane.service.UserMcpCredentialService;
import com.miqroera.miqrokey.domain.model.ApiConsumer;
import com.miqroera.miqrokey.domain.model.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Self-service MCP access (ADR-0030, issue #1): what the caller's own
 * credential may call, and that credential itself.
 *
 * <p>
 * Every read is scoped to the caller's own consumer — an unauthorised service
 * is never named, and there is no path here that takes someone else's identity.
 * The credential is an ordinary API consumer under the hood, so revocation,
 * expiry and per-consumer audit already apply to it.
 * </p>
 */
@RestController
@RequestMapping("/api/v1/me")
public class MeMcpServiceController {

    private final UserMcpCredentialService credentialService;
    private final UserContext userContext;

    public MeMcpServiceController(UserMcpCredentialService credentialService, UserContext userContext) {
        this.credentialService = credentialService;
        this.userContext = userContext;
    }

    /**
     * The ONLINE MCP services the caller's credential may call, with the gateway
     * addresses to reach them. Decided by the gateway's own access rule, so the
     * list and the data plane cannot disagree.
     */
    @GetMapping("/mcp-services")
    public List<McpServiceAccessView> visibleServices() {
        User user = userContext.getUser();
        return credentialService.visibleServices(user.tenantId(), user.id());
    }

    /** Metadata of the caller's credential; never the key itself. */
    @GetMapping("/mcp-credential")
    public MeMcpCredentialView credential() {
        User user = userContext.getUser();
        return credentialService.current(user.tenantId(), user.id()).map(MeMcpServiceController::toView)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "MCP_CREDENTIAL_NOT_ISSUED", "尚未签发 MCP 凭据。"));
    }

    /**
     * Issues the caller's credential on first use and is idempotent afterwards: the
     * plaintext key appears only in the response that creates it, so a repeat call
     * returns the same metadata with {@code apiKey} null rather than minting
     * another.
     */
    @PostMapping("/mcp-credential")
    public ResponseEntity<MeMcpCredentialIssueView> issue(HttpServletRequest httpReq) {
        User user = userContext.getUser();
        UserMcpCredentialService.IssuedCredential issued = credentialService.issueOrGet(user.tenantId(), user.id(),
                user.username(), requestId(httpReq));
        return ResponseEntity.ok(new MeMcpCredentialIssueView(toView(issued.consumer()), issued.apiKey()));
    }

    private static MeMcpCredentialView toView(ApiConsumer consumer) {
        return new MeMcpCredentialView(consumer.id(), consumer.name(), consumer.keyPrefix(), consumer.status(),
                consumer.capabilities() == null ? null : List.copyOf(consumer.capabilities()), consumer.createdAt(),
                consumer.expiresAt());
    }

    private static String requestId(HttpServletRequest request) {
        String header = request.getHeader("X-Request-Id");
        return header != null && !header.isBlank() ? header : UUID.randomUUID().toString();
    }
}
