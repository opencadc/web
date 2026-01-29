package org.opencadc.token;

import ca.nrc.cadc.reg.client.CachingFile;
import ca.nrc.cadc.util.FileUtil;
import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import org.json.JSONTokener;
import org.junit.Assert;
import org.junit.Test;

public class DiscoveryDocumentTest {
    @Test
    public void testDiscoveryDocument() throws Exception {
        final File discoveryDocumentFile =
                FileUtil.getFileFromResource("discovery-document.json", DiscoveryDocumentTest.class);
        final StringBuilder jsonContent = new StringBuilder();
        try (final FileInputStream dis = new FileInputStream(discoveryDocumentFile)) {
            jsonContent.append(new JSONTokener(dis).nextValue());
        }

        final CachingFile cachingFile =
                new CachingFile(
                        discoveryDocumentFile,
                        URI.create("https://example.org/.well-known/openid-configuration")
                                .toURL()) {
                    @Override
                    public String getContent() {
                        return jsonContent.toString();
                    }
                };

        final DiscoveryDocument discoveryDocument = new DiscoveryDocument(cachingFile);
        Assert.assertEquals(
                "Wrong Auth.",
                "https://example.org/authorize",
                discoveryDocument.getAuthorizationEndpoint().toString());
        Assert.assertEquals(
                "Wrong Token.",
                "https://example.org/token",
                discoveryDocument.getTokenEndpoint().toString());
    }
}
