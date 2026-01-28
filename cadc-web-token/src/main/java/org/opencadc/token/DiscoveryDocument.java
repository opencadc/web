package org.opencadc.token;

import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.reg.client.CachingFile;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;
import org.apache.log4j.Logger;
import org.json.JSONObject;

/**
 * Represents an OpenID Connect Discovery Document, which provides endpoints and other configuration information about
 * an OpenID Connect Provider (OP).
 */
public class DiscoveryDocument {
    private static final Logger LOGGER = Logger.getLogger(DiscoveryDocument.class.getName());
    private static final String CONFIG_CACHE_DIR = "opencadc-oidc-cache";
    private static final String AUTH_ENDPOINT_KEY = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_KEY = "token_endpoint";

    static final String WELL_KNOWN_ENDPOINT = "/.well-known/openid-configuration";
    private final CachingFile cachingFile;

    /**
     * Construct a DiscoveryDocument from the given discovery document URL. Used for testing.
     *
     * @param discoveryDocumentURL The URL of the discovery document.
     * @throws IOException If there is an error determining the domain name of the URL.
     */
    DiscoveryDocument(final URL discoveryDocumentURL) throws IOException {
        Objects.requireNonNull(discoveryDocumentURL, "discoveryDocumentURL from issuer cannot be null");
        final String domainName = NetUtil.getDomainName(discoveryDocumentURL);
        this.cachingFile = new CachingFile(
                DiscoveryDocument.getBaseCacheDirectory(domainName).toFile(), discoveryDocumentURL);
    }

    private JSONObject getDiscoveryDocumentFileContent() throws IOException {
        return new JSONObject(this.cachingFile.getContent());
    }

    /**
     * Instantiate a DiscoveryDocument from the given issuer URL.
     *
     * @param issuerURL The issuer URL.
     * @return DiscoveryDocument instance.
     */
    static DiscoveryDocument fromIssuer(final URL issuerURL) {
        try {
            final URL discoveryDocumentURL =
                    new URL(issuerURL.toExternalForm() + DiscoveryDocument.WELL_KNOWN_ENDPOINT);
            return new DiscoveryDocument(discoveryDocumentURL);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to create DiscoveryDocument from issuer URL: " + issuerURL, e);
        }
    }

    /**
     * Get the Authorization Endpoint URL from the Discovery Document.
     *
     * @return URL of the Authorization Endpoint.
     * @throws IOException If the document cannot be read.
     */
    URL getAuthorizationEndpoint() throws IOException {
        final String urlString = this.getDiscoveryDocumentFileContent().getString(DiscoveryDocument.AUTH_ENDPOINT_KEY);
        return new URL(urlString);
    }

    /**
     * Get the Token Endpoint URL from the Discovery Document.
     *
     * @return URL of the Token Endpoint.
     * @throws IOException If the document cannot be read.
     */
    URL getTokenEndpoint() throws IOException {
        final String urlString = this.getDiscoveryDocumentFileContent().getString(DiscoveryDocument.TOKEN_ENDPOINT_KEY);
        return new URL(urlString);
    }

    private static Path getBaseCacheDirectory(final String issuerDomainName) {
        final String tmpDir = System.getProperty("java.io.tmpdir");
        if (tmpDir == null) {
            throw new RuntimeException("No tmp system dir defined.");
        }

        final Path path = Paths.get(tmpDir, DiscoveryDocument.CONFIG_CACHE_DIR, issuerDomainName);
        LOGGER.debug("Base cache dir: " + path);
        return path;
    }
}
