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

import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.net.HttpGet;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.util.StringUtil;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Objects;


/**
 * A configured Client necessary to connect to an OpenID Connect Provider from a CADC/CANFAR application.
 */
public class Client {
    private static final Logger LOGGER = Logger.getLogger(Client.class);

    private static final String WELL_KNOWN_ENDPOINT = "/.well-known/openid-configuration";
    private static final String AUTH_ENDPOINT_KEY = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_KEY = "token_endpoint";


    private final String clientID;
    private final String clientSecret;
    private final URL callbackURL;
    private final URL redirectURL;
    private final String[] scope;
    private final TokenStore tokenStore;


    /**
     * Full constructor.  Mostly used for testing, but feel free to use an alternate TokenStore implementation.
     *
     * @param clientID     The ID (Not the name) of the configured Client registered at the provider.
     * @param clientSecret The secret associated with the Client ID for authorization to the provider.
     * @param callbackURL  Where to send the user after successful login and successful redirect to callback.
     * @param redirectURL  The Callback URL to redirect the user to after successful login.
     * @param scope        The array of Scope values to send.
     * @param tokenStore   The TokenStore cache.
     */
    public Client(String clientID, String clientSecret, URL callbackURL, URL redirectURL, String[] scope,
                  TokenStore tokenStore) {
        this.clientID = clientID;
        this.clientSecret = clientSecret;
        this.callbackURL = callbackURL;
        this.redirectURL = redirectURL;
        this.scope = scope;
        this.tokenStore = tokenStore;
    }

    /**
     * Full (mostly) constructor.
     *
     * @param clientID           The ID (Not the name) of the configured Client registered at the provider.
     * @param clientSecret       The secret associated with the Client ID for authorization to the provider.
     * @param callbackURL        Where to send the user after successful login and successful redirect to callback.
     * @param redirectURL        The Callback URL to redirect the user to after successful login.
     * @param scope              The array of Scope values to send.
     * @param tokenStoreCacheURL The URL to the default cache implementation.
     */
    public Client(String clientID, String clientSecret, URL callbackURL, URL redirectURL, String[] scope,
                  String tokenStoreCacheURL) {
        this(clientID, clientSecret, callbackURL, redirectURL, scope, new RedisTokenStore(tokenStoreCacheURL));
    }

    /**
     * Obtain the URL that the user will be redirected to after successful login and redirect_uri.
     *
     * @return The URL of the end callback.
     */
    public URL getCallbackURL() {
        return callbackURL;
    }

    /**
     * Obtain the URL that the user will be redirected to after successful login by the OpenID Connect provider.
     *
     * @return The URL of the end redirect.
     */
    public URL getRedirectURL() {
        return redirectURL;
    }

    /**
     * Obtain the login endpoint without the optional State string.
     *
     * @return URI to redirect the user to.  Never null.
     * @throws IOException If any URLs cannot be used.
     */
    public URL getAuthorizationURL() throws IOException {
        return getAuthorizationURL("");
    }

    /**
     * Obtain the login endpoint, but provide the optional State string to be stored by the caller.
     *
     * @param stateString The state value to check later (optional).
     * @return URI to redirect the user to.  Never null.
     * @throws IOException If any URLs cannot be used.
     */
    public URL getAuthorizationURL(final String stateString) throws IOException {
        // The authorization endpoint of the server
        final URI authorizationEndpoint = URI.create(Client.getAuthorizationEndpoint().toExternalForm());

        // The client identifier provisioned by the server
        final ClientID clientID = new ClientID(this.clientID);

        // The requested scope values for the token
        final Scope scope = new Scope(this.scope);

        // The client callback URI, typically pre-registered with the server
        final URI callback = URI.create(this.redirectURL.toExternalForm());

        final AuthorizationRequest.Builder requestBuilder =
                new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), clientID)
                        .scope(scope)
                        .redirectionURI(callback)
                        .endpointURI(authorizationEndpoint);

        if (StringUtil.hasText(stateString)) {
            requestBuilder.state(new State(stateString));
        }

        final AuthorizationRequest request = requestBuilder.build();
        return request.toURI().toURL();
    }

    /**
     * Decrypt the given cookie value to obtain the key, then look it up in the cache to return the access token.
     *
     * @param encryptedCookieValue The encrypted cookie value from the caller.
     * @return String access token.
     * @throws Exception If the Assets with the given key don't exist, or the cookie cannot be decrypted.
     */
    public String getAccessToken(final String encryptedCookieValue) throws Exception {
        final String assetsKey = getAssetsKey(encryptedCookieValue);
        final Assets storedAssets = this.tokenStore.get(assetsKey);
        final Assets assets;

        if (Client.needsRefresh(storedAssets)) {
            final Assets refreshedAssets = refresh(storedAssets);
            this.tokenStore.put(assetsKey, refreshedAssets);
            assets = refreshedAssets;
        } else {
            assets = storedAssets;
        }

        return assets.getAccessToken();
    }

    /**
     * Obtain an access token from the token endpoint for the current configuration, obtaining necessary elements
     * from the provided response URI from the authorization endpoint.  This will not use the optional State.
     *
     * @param responseURI The response URI from the authorization's login.
     * @return The encrypted Assets key.  Never null.
     * @throws IOException If any URLs cannot be used.
     */
    public byte[] setAccessToken(final URI responseURI) throws Exception {
        final AuthorizationCode code = getAuthorizationCode(responseURI);
        return setAccessToken(code);
    }

    /**
     * Obtain an access token from the token endpoint for the current configuration, obtaining necessary elements
     * from the provided response URI from the authorization endpoint.
     *
     * @param responseURI The response URI from the authorization's login.
     * @param state       The optional state value to be used to compare against later.
     * @return The encrypted Assets key.  Never null.
     * @throws IOException If any URLs cannot be used.
     */
    public byte[] setAccessToken(final URI responseURI, final String state) throws Exception {
        final AuthorizationCode code = getAuthorizationCode(responseURI, new State(state));
        return setAccessToken(code);
    }

    byte[] setAccessToken(final AuthorizationCode authorizationCode) throws Exception {
        final URI callback = URI.create(this.redirectURL.toExternalForm());
        final AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationCode, callback);

        // The credentials to authenticate the client at the token endpoint
        final ClientID clientID = new ClientID(this.clientID);
        final Secret clientSecret = new Secret(this.clientSecret);
        final ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        final URI tokenEndpoint = URI.create(Client.getTokenEndpoint().toExternalForm());
        final TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);
        final TokenResponse tokenResponse;

        try {
            tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (ParseException parseException) {
            throw new IllegalArgumentException("Invalid or missing response parameters from token endpoint: "
                                               + parseException.getMessage(), parseException);
        }

        if (!tokenResponse.indicatesSuccess()) {
            // We got an error response...
            handleTokenErrorResponse(tokenResponse.toErrorResponse());
        }

        final AccessTokenResponse tokenSuccessResponse = tokenResponse.toSuccessResponse();
        return setAccessToken(new JSONObject(tokenSuccessResponse.toJSONObject().toJSONString()));
    }

    byte[] setAccessToken(final JSONObject tokenSet) throws Exception {
        final Assets assets = new Assets(tokenSet);
        return encryptAssetsKey(this.tokenStore.put(assets));
    }

    /**
     * Encrypt the given assets key to be used in a cookie and sent to the browser.
     *
     * @param assetsKey The key to encrypt and put into a cookie.
     * @return byte array of encrypted value, never null.
     * @throws Exception If the encryption fails.
     */
    byte[] encryptAssetsKey(final String assetsKey) throws Exception {
        final CookieEncrypt cookieEncrypt = new CookieEncrypt();
        final EncryptedCookie encryptionEncryptedCookie = cookieEncrypt.encrypt(assetsKey);
        return encryptionEncryptedCookie.marshall();
    }

    /**
     * Perform a refresh of the given Assets and return the new version.
     *
     * @param assets The (possibly expired) assets to be refreshed using its refresh token.
     * @return The refreshed Assets object.
     * @throws Exception For any HTTP errors, or in obtaining the Token Endpoint URL.
     */
    Assets refresh(final Assets assets) throws Exception {
        final RefreshToken refreshToken = new RefreshToken(assets.getRefreshToken());
        final RefreshTokenGrant refreshTokenGrant = new RefreshTokenGrant(refreshToken);

        // The credentials to authenticate the client at the token endpoint
        final ClientID clientID = new ClientID(this.clientID);
        final Secret clientSecret = new Secret(this.clientSecret);
        final ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        final URI tokenEndpoint = URI.create(Client.getTokenEndpoint().toExternalForm());
        final TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, refreshTokenGrant);
        final TokenResponse tokenResponse;

        try {
            tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (ParseException parseException) {
            throw new IllegalArgumentException("Invalid or missing response parameters from token endpoint: "
                                               + parseException.getMessage(), parseException);
        }

        if (!tokenResponse.indicatesSuccess()) {
            handleTokenErrorResponse(tokenResponse.toErrorResponse());
        }

        final AccessTokenResponse tokenSuccessResponse = tokenResponse.toSuccessResponse();

        return new Assets(new JSONObject(tokenSuccessResponse.toJSONObject().toJSONString()));
    }

    String getAssetsKey(final String encryptedCookieValue) throws Exception {
        final EncryptedCookie encryptedEncryptedCookie = new EncryptedCookie(encryptedCookieValue);
        final CookieDecrypt cookieDecrypt = new CookieDecrypt();
        return cookieDecrypt.getAssetsKey(encryptedEncryptedCookie);
    }

    /**
     * Obtain an authorization code without the optional state provided.
     *
     * @param responseURI The response URI from the authorization's login.
     * @return AuthorizationCode instance, never null.
     */
    AuthorizationCode getAuthorizationCode(final URI responseURI) {
        return getAuthorizationCode(responseURI, null);
    }

    /**
     * Obtain an authorization code and provide the optional state.
     *
     * @param responseURI The response URI from the authorization's login.
     * @param state       The state value to compare against to the response.
     * @return AuthorizationCode instance, never null.
     */
    AuthorizationCode getAuthorizationCode(final URI responseURI, final State state) {
        // Parse the authorisation response from the callback URI
        final AuthorizationResponse response;

        try {
            response = AuthorizationResponse.parse(responseURI);
        } catch (ParseException parseException) {
            throw new IllegalArgumentException("Invalid or missing response parameters from authorization endpoint: "
                                               + parseException.getMessage(), parseException);
        }

        // Check the returned state parameter, must match the original.
        final State responseState = response.getState();
        if (responseState == null && state != null) {
            throw new IllegalStateException("Caller state expected, but none provided to compare to by response.");
        } else if (responseState != null && state == null) {
            throw new IllegalStateException("Response state expected, but none provided to compare to by caller.");
        } else if (responseState != null && !state.equals(responseState)) {
            throw new NotAuthenticatedException("Caller state does not match request state!  Possible tampering.");
        } else if (!response.indicatesSuccess()) {
            // The request was denied or some error occurred
            final AuthorizationErrorResponse errorResponse = response.toErrorResponse();
            throw new IllegalArgumentException("Invalid response from authorization server: " + errorResponse);
        }

        final AuthorizationSuccessResponse successResponse = response.toSuccessResponse();

        // Retrieve the authorisation code, to be used later to exchange the code for
        // an access token at the token endpoint of the server
        return successResponse.getAuthorizationCode();
    }

    void handleTokenErrorResponse(final TokenErrorResponse tokenErrorResponse) {
        final ErrorObject tokenErrorObject = tokenErrorResponse.getErrorObject();
        if (tokenErrorObject.getHTTPStatusCode() == 401) {
            throw new NotAuthenticatedException("Refresh token expired.  Please re-authenticate.");
        } else {
            throw new IllegalArgumentException("Invalid response from token server: "
                                               + tokenErrorResponse.toJSONObject());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Client that = (Client) o;
        return Objects.equals(clientID, that.clientID) && Objects.equals(callbackURL, that.callbackURL)
               && Objects.equals(redirectURL, that.redirectURL) && Arrays.equals(scope, that.scope);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(clientID, callbackURL, redirectURL);
        result = 31 * result + Arrays.hashCode(scope);
        return result;
    }

    /**
     * Generate a new 16-character state value for the caller.  The caller will need to store this and retrieve it
     * later to compare.
     *
     * @return String random state value.
     */
    public static String generateState() {
        return RandomStringUtils.randomAlphanumeric(16);
    }

    /**
     * Obtain whether the given Assets is expired, or about to expire.
     *
     * @param assets The Assets to check.
     * @return  True if about to expire or is expired.  False otherwise.
     */
    public static boolean needsRefresh(final Assets assets) {
        return assets.isAccessTokenExpired();
    }

    /**
     * Obtain the Issuer base URL.
     *
     * @return URL of the Issuer.  Never null.
     * @throws IOException                   For a poorly formed URL.
     * @throws UnsupportedOperationException If the configured Issuer URL is not an HTTPS URL.
     */
    public static URL getIssuer() throws IOException {
        final LocalAuthority localAuthority = new LocalAuthority();
        final URI openIDIssuerURI = localAuthority.getServiceURI(Standards.SECURITY_METHOD_OPENID.toASCIIString());
        if (!"https".equals(openIDIssuerURI.getScheme())) {
            throw new UnsupportedOperationException("OpenID Provider not configured.");
        } else {
            return openIDIssuerURI.toURL();
        }
    }

    /**
     * Pull the Authorization Endpoint URL from the Well Known JSON document.
     *
     * @return URL of the Authorization Endpoint for authentication.  Never null.
     * @throws IOException For a poorly formed URL.
     */
    public static URL getAuthorizationEndpoint() throws IOException {
        final JSONObject jsonObject = Client.getWellKnownJSON();
        final String authEndpointString = jsonObject.getString(Client.AUTH_ENDPOINT_KEY);
        return new URL(authEndpointString);
    }

    /**
     * Pull the Token Endpoint URL from the Well Known JSON document.
     *
     * @return URL of the Token Endpoint for access and refresh tokens.  Never null.
     * @throws IOException For a poorly formed URL.
     */
    public static URL getTokenEndpoint() throws IOException {
        final JSONObject jsonObject = Client.getWellKnownJSON();
        final String tokenEndpointString = jsonObject.getString(Client.TOKEN_ENDPOINT_KEY);
        return new URL(tokenEndpointString);
    }

    /**
     * Obtain the .well-known endpoint JSON document.
     * TODO: Cache this?
     *
     * @return The JSON Object of the response data.
     * @throws MalformedURLException If URLs cannot be created as expected.
     */
    private static JSONObject getWellKnownJSON() throws IOException {
        final URL oidcIssuer = Client.getIssuer();
        final URL configurationURL = new URL(oidcIssuer.toExternalForm() + Client.WELL_KNOWN_ENDPOINT);
        final Writer writer = new StringWriter();
        final HttpGet httpGet = new HttpGet(configurationURL, inputStream -> {
            final Reader inputReader = new BufferedReader(new InputStreamReader(inputStream));
            final char[] buffer = new char[8192];
            int charsRead;
            while ((charsRead = inputReader.read(buffer)) >= 0) {
                writer.write(buffer, 0, charsRead);
            }
            writer.flush();
        });

        httpGet.run();

        return new JSONObject(writer.toString());
    }
}
