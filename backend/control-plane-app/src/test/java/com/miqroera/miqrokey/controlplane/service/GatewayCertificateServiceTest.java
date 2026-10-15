package com.miqroera.miqrokey.controlplane.service;

import com.miqroera.miqrokey.controlplane.config.GatewayTlsProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * #36: the portal hands users the gateway certificate — and, just as important,
 * stays quiet when there is nothing to hand out (publicly trusted certificate,
 * or no certificate mounted at all).
 */
class GatewayCertificateServiceTest {

    private static final String SELF_SIGNED = "/certificates/self-signed.pem";
    private static final String CA_SIGNED = "/certificates/ca-signed.pem";

    /** openssl x509 -in self-signed.pem -noout -fingerprint -sha256 */
    private static final String SELF_SIGNED_FINGERPRINT = "60:BC:00:F9:8D:75:0A:18:98:90:CA:60:B8:9D:1D:94:"
            + "9B:2E:50:61:BE:28:78:A0:66:65:57:73:6B:21:28:C7";

    private static GatewayCertificateService serviceFor(String certFile) {
        GatewayTlsProperties properties = new GatewayTlsProperties();
        properties.setCertFile(certFile);
        return new GatewayCertificateService(properties);
    }

    private static String materialize(@TempDir Path dir, String resource) throws IOException {
        Path target = dir.resolve(resource.substring(resource.lastIndexOf('/') + 1));
        try (InputStream in = GatewayCertificateServiceTest.class.getResourceAsStream(resource)) {
            Files.copy(in, target);
        }
        return target.toAbsolutePath().toString();
    }

    @Test
    @DisplayName("a self-signed certificate is exported — and flagged as self-signed")
    void exportsSelfSignedCertificate(@TempDir Path dir) throws Exception {
        GatewayCertificateService.GatewayCertificateView view = serviceFor(materialize(dir, SELF_SIGNED)).view();

        assertThat(view.available()).isTrue();
        assertThat(view.selfSigned()).isTrue();
        assertThat(view.pem()).startsWith("-----BEGIN CERTIFICATE-----").contains("-----END CERTIFICATE-----");
        assertThat(view.subject()).isEqualTo("CN=miqrogate-test-selfsigned");
        assertThat(view.issuer()).isEqualTo(view.subject());
        // The fingerprint is the one `openssl x509 -fingerprint -sha256` prints, so
        // an operator can compare what the portal shows with what they see locally.
        assertThat(view.fingerprintSha256()).isEqualTo(SELF_SIGNED_FINGERPRINT);
        assertThat(view.notAfter()).isEqualTo("2046-10-10T04:04:34Z");
        assertThat(view.fileName()).isEqualTo(GatewayCertificateService.FILE_NAME);
    }

    @Test
    @DisplayName("a CA-signed certificate is still readable but is NOT flagged self-signed")
    void reportsTrustedCertificate(@TempDir Path dir) throws Exception {
        GatewayCertificateService.GatewayCertificateView view = serviceFor(materialize(dir, CA_SIGNED)).view();

        assertThat(view.available()).isTrue();
        // The page hides the download on this answer: with a publicly trusted
        // certificate there is nothing for the user to do.
        assertThat(view.selfSigned()).isFalse();
        assertThat(view.issuer()).isEqualTo("CN=miqrogate-test-ca");
        assertThat(view.subject()).isNotEqualTo(view.issuer());
    }

    @Test
    @DisplayName("no configured path → unavailable, and the portal stays usable")
    void unconfiguredIsUnavailable() {
        GatewayCertificateService.GatewayCertificateView view = serviceFor(null).view();

        assertThat(view.available()).isFalse();
        assertThat(view.pem()).isNull();
        assertThat(view.selfSigned()).isFalse();
    }

    @Test
    @DisplayName("a missing or unreadable file → unavailable, never an error")
    void missingFileIsUnavailable(@TempDir Path dir) {
        GatewayCertificateService.GatewayCertificateView view = serviceFor(dir.resolve("nope.pem").toString()).view();

        assertThat(view.available()).isFalse();
        assertThat(view.pem()).isNull();
    }

    @Test
    @DisplayName("a file that is not a certificate → unavailable, never an error")
    void garbageFileIsUnavailable(@TempDir Path dir) throws Exception {
        Path notACert = dir.resolve("readme.pem");
        Files.writeString(notACert, "this is not a certificate\n");

        GatewayCertificateService.GatewayCertificateView view = serviceFor(notACert.toString()).view();

        assertThat(view.available()).isFalse();
    }
}
