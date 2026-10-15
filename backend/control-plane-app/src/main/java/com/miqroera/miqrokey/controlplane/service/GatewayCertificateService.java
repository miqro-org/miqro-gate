package com.miqroera.miqrokey.controlplane.service;

import com.miqroera.miqrokey.controlplane.config.GatewayTlsProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Serves the gateway's own TLS certificate to the portal (#36).
 *
 * <p>
 * Self-signed deployments require every client to trust that certificate before
 * it can reach the MCP data plane; the portal used to say so without offering
 * the file. This reads the certificate the portal already serves (configured
 * via {@code miqrokey.gateway-tls.cert-file}) and reports whether it is
 * self-signed, so the page can hand it out — and can stay quiet on deployments
 * with a publicly trusted certificate, where there is nothing to do.
 * </p>
 *
 * <p>
 * Only the certificate is ever read: a deployment that also mounted the private
 * key would still not expose it here. Anything unreadable or unparseable is
 * reported as "unavailable" rather than failing the page — an operator who has
 * not configured the path should still be able to use the portal.
 * </p>
 */
@Service
public class GatewayCertificateService {

    private static final Logger LOG = LoggerFactory.getLogger(GatewayCertificateService.class);

    /**
     * Download name; clients feed this straight to NODE_EXTRA_CA_CERTS & friends.
     */
    static final String FILE_NAME = "miqrogate-ca.pem";

    private final GatewayTlsProperties properties;

    public GatewayCertificateService(GatewayTlsProperties properties) {
        this.properties = properties;
    }

    /**
     * The certificate to hand out, or {@link GatewayCertificateView#unavailable()}.
     */
    public GatewayCertificateView view() {
        String path = properties.getCertFile();
        if (path == null || path.isBlank()) {
            return GatewayCertificateView.unavailable();
        }
        byte[] pem;
        try {
            pem = Files.readAllBytes(Path.of(path));
        } catch (IOException | RuntimeException e) {
            // Not an error worth a stack trace: an unconfigured/missing cert just
            // means the portal keeps its generic wording.
            LOG.info("aigw.certificate.unavailable path={} reason={}", path, e.toString());
            return GatewayCertificateView.unavailable();
        }
        X509Certificate cert;
        try {
            cert = firstCertificate(pem);
        } catch (CertificateException e) {
            LOG.warn("aigw.certificate.unparseable path={}: {}", path, e.getMessage());
            return GatewayCertificateView.unavailable();
        }
        String subject = cert.getSubjectX500Principal().getName();
        String issuer = cert.getIssuerX500Principal().getName();
        return new GatewayCertificateView(true, new String(pem, StandardCharsets.UTF_8), subject.equals(issuer),
                subject, issuer, fingerprint(cert), cert.getNotAfter().toInstant().toString(), FILE_NAME);
    }

    private static X509Certificate firstCertificate(byte[] pem) throws CertificateException {
        // A fullchain file may carry intermediates after the leaf; the leaf — the
        // one the clients actually see — is what decides "self-signed or not".
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    private static String fingerprint(X509Certificate cert) throws IllegalStateException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            String hex = HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
            return hex.toUpperCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new IllegalStateException("cannot fingerprint gateway certificate", e);
        }
    }

    /**
     * @param available
     *            false when no certificate could be read; every other field is then
     *            null
     * @param pem
     *            the certificate in PEM form, as mounted
     * @param selfSigned
     *            issuer equals subject — the case where clients must be told to
     *            trust it
     * @param fingerprintSha256
     *            colon-separated, upper case (matches what `openssl x509
     *            -fingerprint -sha256` prints)
     */
    public record GatewayCertificateView(boolean available, String pem, boolean selfSigned, String subject,
            String issuer, String fingerprintSha256, String notAfter, String fileName) {

        static GatewayCertificateView unavailable() {
            return new GatewayCertificateView(false, null, false, null, null, null, null, null);
        }
    }
}
