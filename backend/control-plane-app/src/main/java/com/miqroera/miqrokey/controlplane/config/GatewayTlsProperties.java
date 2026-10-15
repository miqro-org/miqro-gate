package com.miqroera.miqrokey.controlplane.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Gateway TLS settings used by the certificate export (#36).
 *
 * <p>
 * Self-signed deployments (local / on-prem) make every client trust the gateway
 * certificate before it can open the MCP data plane — and until now the portal
 * told users to do that without offering them the file. Pointing this at the
 * certificate the portal already serves lets the portal hand it out.
 * </p>
 */
@ConfigurationProperties(prefix = "miqrokey.gateway-tls")
public class GatewayTlsProperties {

    /**
     * Path to the gateway's TLS certificate (PEM). Empty/unset disables the export
     * — the portal then keeps its generic "trust the CA" wording and offers nothing
     * to download. Only ever the certificate: the private key must not be mounted
     * where this application can read it.
     */
    private String certFile;

    public String getCertFile() {
        return certFile;
    }

    public void setCertFile(String certFile) {
        this.certFile = certFile;
    }
}
