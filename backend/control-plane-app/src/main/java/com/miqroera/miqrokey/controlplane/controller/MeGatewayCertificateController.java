package com.miqroera.miqrokey.controlplane.controller;

import com.miqroera.miqrokey.controlplane.service.GatewayCertificateService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Hands the logged-in user the gateway's TLS certificate (#36).
 *
 * <p>
 * Session-authenticated like every other {@code /me} surface. The certificate
 * is public information — it is presented to every client that connects — so
 * the only reason this sits behind a session is that the portal page it serves
 * is behind one too; nothing here is a secret.
 * </p>
 */
@RestController
public class MeGatewayCertificateController {

    private final GatewayCertificateService gatewayCertificateService;

    public MeGatewayCertificateController(GatewayCertificateService gatewayCertificateService) {
        this.gatewayCertificateService = gatewayCertificateService;
    }

    /**
     * {@code available=false} when the deployment did not point
     * {@code miqrokey.gateway-tls.cert-file} at a readable certificate; the page
     * then simply offers nothing rather than showing a broken action.
     */
    @GetMapping("/api/v1/me/gateway-certificate")
    public GatewayCertificateService.GatewayCertificateView certificate() {
        return gatewayCertificateService.view();
    }
}
