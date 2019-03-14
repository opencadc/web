package ca.nrc.cadc.accesscontrol;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.security.AccessControlException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;


/**
 * Client to access a registered AC Web Service.
 */
public class AccessControlClient {
    private static final String CADC_TOKEN_HEADER_KEY = "X-CADC-DelegationToken";
    private static final String CADC_PASSWORD_FIELD = "password";
    private final RegistryClient registryClient;
    private final URI groupManagementServiceURI;


    public AccessControlClient(final URI serviceURI)
        throws IllegalArgumentException {
        this(serviceURI, new RegistryClient());
    }

    AccessControlClient(URI serviceURI, RegistryClient registryClient) {
        this.registryClient = registryClient;
        this.groupManagementServiceURI = serviceURI;
    }


    /**
     * Obtain the Login URL.
     *
     * @return URL for login
     */
    private URL lookupLoginURL() {
        return this.registryClient
                   .getServiceURL(this.groupManagementServiceURI,
                                  Standards.UMS_LOGIN_01, AuthMethod.ANON);
    }

    public String login(final String username, char[] password) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Map<String, Object> payload = new HashMap<>();

        payload.put("username", username);
        payload.put("password", new String(password));

        final int statusCode = post(lookupLoginURL(), payload, out);
        switch (statusCode) {
            case 200: {
                return out.toString();
            }

            case 401: {
                throw new AccessControlException("Login denied");
            }

            default: {
                throw new IllegalArgumentException(
                    String.format("Unable to login '%s'.\nServer error code: %d.",
                                  username, statusCode));
            }
        }
    }

    private URL lookupPasswordResetURL() {
        return this.registryClient.getServiceURL(
            this.groupManagementServiceURI,
            Standards.UMS_RESETPASS_01, AuthMethod.TOKEN);
    }

    /**
     * Reset the password for the currently authenticated user.
     *
     * @param newPassword The new password value.
     */
    public void resetPassword(final char[] newPassword, final char[] token) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Map<String, Object> payload = new HashMap<>();
        payload.put(CADC_PASSWORD_FIELD, new String(newPassword));

        final Map<String, String> headers = new HashMap<>();
        headers.put(CADC_TOKEN_HEADER_KEY, new String(token));

        final int statusCode = post(lookupPasswordResetURL(), payload, headers, out);
        switch (statusCode) {
            case 200: {
                break;
            }

            case 403:
            case 401: {
                throw new AccessControlException("Login denied");
            }

            default: {
                throw new IllegalArgumentException(
                    String.format("Unable to reset password.\nServer error code: %d.", statusCode));
            }
        }
    }

    /**
     * Submit login data to the service.
     *
     * @param url     The URL endpoint.
     * @param payload The payload information.
     * @param out     The response stream.
     * @return Response status code.
     */
    int post(final URL url, final Map<String, Object> payload, final OutputStream out) {
        final Map<String, String> headers = Collections.emptyMap();
        return post(url, payload, headers, out);
    }

    /**
     * Submit login data to the service with extra headers
     *
     * @param url     The URL endpoint.
     * @param payload The payload information.
     * @param headers Extra headers set to the request.
     * @param out     The response stream.
     * @return Response status code.
     */
    int post(final URL url, final Map<String, Object> payload, final Map<String, String> headers,
             final OutputStream out) {
        final HttpPost post = new HttpPost(url, payload, out);
        for (final Map.Entry<String, String> entry : headers.entrySet()) {
            post.setRequestProperty(entry.getKey(), entry.getValue());
        }

        post.run();
        return post.getResponseCode();
    }

    public String getCurrentHttpPrincipalUsername(Subject subject) {
        final AuthMethod authMethod = AuthenticationUtil.getAuthMethod(subject);
        String username;

        if ((authMethod != null) && (authMethod != AuthMethod.ANON)) {
            final Set curPrincipals = subject.getPrincipals(HttpPrincipal.class);
            HttpPrincipal[] principalArray =
                new HttpPrincipal[curPrincipals.size()];
            username = ((HttpPrincipal[]) curPrincipals
                                              .toArray(principalArray))[0].getName();
        } else {
            username = null;
        }

        return username;
    }
}
