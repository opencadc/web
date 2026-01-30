/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *
 ************************************************************************
 */

package org.opencadc.token;

import static org.junit.Assert.*;

import ca.nrc.cadc.auth.NotAuthenticatedException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import org.junit.Test;

public class ClientTest {
    static DiscoveryDocument getDiscoveryDocument() throws IOException {
        final URL issuerURL = new URL("https://example.org/issuer");
        return DiscoveryDocument.fromIssuer(issuerURL);
    }

    @Test
    public void needsRefresh() {
        final long goodExpiryTime = System.currentTimeMillis() - 50000L;
        final Assets goodAssets = new Assets("access", "refresh", goodExpiryTime);

        assertFalse("Should not need refresh.", Client.needsRefresh(goodAssets));

        final long expiredExpiryTime = System.currentTimeMillis() - 61000L;
        final Assets expiredAssets = new Assets("access", "refresh", expiredExpiryTime);

        assertTrue("Should not need refresh.", Client.needsRefresh(expiredAssets));
    }

    @Test
    public void setAndGet() throws Exception {
        final Client testSubject = new Client(
                ClientTest.getDiscoveryDocument(),
                "clientID",
                "clientSecret",
                new URL("https://example.org/myapp/redirect"),
                new URL("https://example.org/myapp/callback"),
                new String[] {"openid"},
                new TestTokenStore());

        // Emulate the JSON coming from the OpenID Connect Provider.
        final JSONObject testTokenSet = new JSONObject();
        testTokenSet.put(Assets.ACCESS_TOKEN_KEY, "myaccesstoken");
        testTokenSet.put(Assets.REFRESH_TOKEN_KEY, "myrefreshtoken");
        testTokenSet.put(Assets.EXPIRES_IN_KEY, Integer.toString(3600));

        final byte[] cookieValue = testSubject.setAccessToken(testTokenSet);

        final String accessToken = testSubject.getAccessToken(new String(cookieValue, StandardCharsets.ISO_8859_1));

        assertEquals("Wrong accessToken", "myaccesstoken", accessToken);
    }

    @Test
    public void getAuthorizationCode() throws Exception {
        final Client testSubject = new Client(
                ClientTest.getDiscoveryDocument(),
                "clientID",
                "clientSecret",
                new URL("https://example.org/myapp/redirect"),
                new URL("https://example.org/myapp/callback"),
                new String[] {"openid"},
                new TestTokenStore());

        final URI testURI = URI.create("https://example.com/myapp/redirect?code=mycode");
        final AuthorizationCode authorizationCode = testSubject.getAuthorizationCode(testURI);
        assertEquals("Wrong code", "mycode", authorizationCode.getValue());
    }

    @Test
    public void getAuthorizationCodeErrors() throws Exception {
        final Client testSubject = new Client(
                ClientTest.getDiscoveryDocument(),
                "clientID",
                "clientSecret",
                new URL("https://example.org/myapp/redirect"),
                new URL("https://example.org/myapp/callback"),
                new String[] {"openid"},
                new TestTokenStore());

        try {
            final URI testURI = URI.create("https://example.com/myapp/redirect?code=mycode&state=mystate");
            testSubject.getAuthorizationCode(testURI);
            fail("Should throw IllegalStateException");
        } catch (IllegalStateException illegalStateException) {
            assertEquals(
                    "Wrong message.",
                    "Response state expected, but none provided to compare to by caller.",
                    illegalStateException.getMessage());
        }

        try {
            final URI testURI = URI.create("https://example.com/myapp/redirect?code=mycode");
            testSubject.getAuthorizationCode(testURI, new State("mystate"));
            fail("Should throw IllegalStateException");
        } catch (IllegalStateException illegalStateException) {
            assertEquals(
                    "Wrong message",
                    "Caller state expected, but none provided to compare to by response.",
                    illegalStateException.getMessage());
        }

        try {
            final URI testURI = URI.create("https://example.com/myapp/redirect?code=mycode&state=mystateone");
            testSubject.getAuthorizationCode(testURI, new State("mystatetwo"));
            fail("Should throw NotAuthenticatedException");
        } catch (NotAuthenticatedException notAuthenticatedException) {
            assertEquals(
                    "Wrong message",
                    "Caller state does not match request state!  Possible tampering.",
                    notAuthenticatedException.getMessage());
        }
    }
}
