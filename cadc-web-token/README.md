# OpenCADC Web Token library (0.1.0)

- [Usage](#usage)
- [OpenID Connect](#openid-connect)
  - [Login](#login)
- [BFF Pattern](#bff-pattern)
  - [After Successful Login](#after-successful-login)
  - [Authenticated Requests](#authenticated-requests)
    - [Flow](#general-steps)

## Usage

The `org.opencadc.token.Client` and `org.opencadc.token.Assets` classes are the publicly available
APIs.  The `org.opencadc.token.Assets` class is never actually instantiated (although it could be), but
rather used to deliver token values.

### Login (Authorization)

Your application's Login endpoint (Servlet example):
```java
import org.opencadc.token.Client;

public class LoginServlet extends HttpServlet {
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        final Client webTokenClient = new Client("clientID", "clientSecret",
                                                 new URL("https://example.org/myapp/redirect"),
                                                 new URL("https://example.org/myapp/callback"),
                                                 new String[] {
                                                         "openid", "profile"
                                                 }, "redis://mycache:6739");
        // Send the user to the login
        response.sendRedirect(webTokenClient.getAuthorizationURL().toExternalForm());
    }
}
```

### OpenID Connect Callback (`redirect_uri`)

After a successful login, users are redirected to your application's `redirect_uri` endpoint (`https://example.org/myapp/redirect` above).
As this library uses the Authorization Code flow, a `code` query parameter will be included in the request to the callback.
Your endpoint handling should use the client's `setAccessToken()` method, which will:

1. Parse the `code` from the request URI
2. Use the `code` to request a Token from the Token Endpoint
3. Store the token set (access, refresh, and expiry time) into cache
4. Return the encrypted key to the cache entry, with the necessary items to decrypt later, encoded in Base64
5. Set that value into a cookie with `Secure` and `Http-Only` with a `Path` of `/`, with a name starting with `_Host-`.

```java
import org.opencadc.token.Client;

public class OpenIDConnectRedirectCallbackServlet extends HttpServlet {
    
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        final Client webTokenClient = new Client("clientID", "clientSecret",
                                                 new URL("https://example.org/myapp/redirect"),
                                                 new URL("https://example.org/myapp/callback"),
                                                 new String[] {
                                                         "openid", "profile"
                                                 }, "redis://mycache:6739");
        
        // Parse the `code` parameter, and request a token.
        final byte[] encryptedKey = webTokenClient.setAccessToken(request.getRequestURI());
        
        // The encryptedKey will be the cookie value.
        final Cookie cookie = new Cookie("_Host-auth-myapp", new String(encryptedKey, StandardCharsets.ISO_8859_1));
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
        
        response.sendRedirect(webTokenClient.getCallbackURL().toExternalForm());
    }
}
```

### Access Token Usage

Access Tokens are obtained from the token and delivered as an encrypted value to be used in a cookie.

```java
public class ApplicationProtectedResourceServlet extends HttpServlet {
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        final Client webTokenClient = new Client("clientID", "clientSecret",
                                                 new URL("https://example.org/myapp/redirect"),
                                                 new URL("https://example.org/myapp/callback"),
                                                 new String[] {
                                                         "openid", "profile"
                                                 }, "redis://mycache:6739");
        // Send the user to the login
        final Cookie firstPartyCookie =
                Arrays.stream(req.getCookies())
                      .filter(cookie -> "_Host-auth-myapp".equals(cookie.getName()))
                      .findFirst()
                      .orElse(null);

        if (firstPartyCookie != null) {
            // Also handles refresh automatically, if available.
            final String accessToken = webTokenClient.getAccessToken(firstPartyCookie.getValue());
            
            // Use the new accessToken in an GET call, or create a Subject with the token principal.
            
            final Subject subject = new Subject();
            subject.getPrincipals().add(new AuthorizationTokenPrincipal(AuthenticationUtil.AUTHORIZATION_HEADER,
                                                                        AuthenticationUtil.CHALLENGE_TYPE_BEARER
                                                                        + " " + accessToken));
            subject.getPublicCredentials().add(
                    new AuthorizationToken(AuthenticationUtil.CHALLENGE_TYPE_BEARER, accessToken,
                                           Collections.singletonList(
                                                   URI.create(request.getRequestURI()).getHost())));
            subject.getPublicCredentials().add(AuthMethod.TOKEN);
            
            // Create the Subject, then use it to make authenticated calls.
            Subject.doAs(subject, ...);
        }
    }
}
```

## OpenID Connect

Browser based applications use the Authorization Code flow to authenticate users to the OpenId Provider (OIdP).  A good example of how that works is shown at [Medium.com](https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660#c027), with `openid` included in the `scope` parameter.

Once that flow succeeds, the OpenID Connect Client (the application) will have an Access Token (and Refresh Token) to use to make authenticated calls on behalf of the user to an API, such as Cavern or Skaha.

As this flow is inefficient to use each time a request is made, the Access Token and Refresh Tokens are stored for the user, and retrieved when an authenticated call is necessary.  Access Tokens cannot be securely stored in the browser however, so a secure way of doing it is to implement the [Backend For Frontend (BFF)](#bff-pattern) pattern.

### Login

Login is supplied by the OpenID Connect Provider, and the endpoint can be looked up using the JSON document at the `.well-known/openid-configuration` endpoint, and looking up the `authorization_endpoint` key.  To start the Authorization Code flow, redirect the user to the `authorization_endpoint` with the following `properties`:

| Property | Value                                             |
| -------  |---------------------------------------------------|
| `scope`  | `openid profile offline_access`                   |
| `redirect_uri` | `https://example.com/myapplication/oidc-callback` |
| `response_type` | `code`                                            |
| `client_id` | `myclient_identifier`                             |


**Example**:

*https[]()://example-oidc.com/authorize?client_id=asfaslkfjlkj3-asdfdsdflkj&scope=openid%20profile%20offline_access&response_type=code&redirect_uri=https%3A%2F%2Fexample.com%2Fmyapplication%2Foidc-callback*


If successful, this will call the URL at `redirect_uri` with a `code` parameter, containing a very short lived string value:

*https[]()://example.com/myapplication/oidc-callback?code=sdfue887hdyr*

The `redirect_uri` endpoint can then pull the `code` query parameter, and use the `token_endpoint` from the `.well-known/openid-configuration` endpoint to exchange that `code` for tokens.  In order to do that, the client must authenticate with the same `client_id` used in the Login, as well as the `client_secret`, and POST the values.  The `client_secret` is typically generated by the client on registration.  Code below
is taken from the `Client` class and happens internally.

**Example**:
```java
final String codeFromCallbackURI = request.getParameter("code");
final ClientID clientID = new ClientID(this.clientID);
final Secret clientSecret = new Secret(this.clientSecret);
final AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(codeFromCallbackURI);

// Basic Authentication to obtain a Token from the IAM service.
final ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

final URI tokenEndpoint = URI.create(Client.getTokenEndpoint().toExternalForm());
final TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

// Send the request for the token...
final TokenResponse tokenResponse = sendTokenRequest(tokenRequest);
final AccessTokenResponse tokenSuccessResponse = tokenResponse.toSuccessResponse();

// We now have the Assets (Access Token, Refresh Token, and Expiry Time of Access Token)
final Assets assets = new Assets(new JSONObject(tokenSuccessResponse.toJSONObject().toJSONString()));
```

Document returned from the `TokenRequest`:
```json
{
  "access_token": "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
  "expires_in": 3600,
  "refresh_token": "IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk",

  "id_token": "asklIILLdnsf9sdjsdfhkjhjh" // Not actually used, but there if needed.
}
```

The application now has what it needs to make authenticated calls to the API(s).  Let's look at how they're stored and used with the [BFF Pattern](#bff-pattern).

## BFF Pattern

The UI applications use the Backend For Frontend (BFF) pattern to securely store tokens in a server-side cache, and can only be retrieved with an encrypted, HTTP-Only, and Secure, first-party cookie from the browser.  First-party cookies are obtained from a direct visit to the site, such as from a redirect, rather than from a request made from the page using JavaScript (third-party).  As browsers tighten security on cookies, this helps to future proof it.

All OpenID Connect (OIDC) interaction is handled by the [Nimbus OAuth2 Java Library](https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/src/master/).

### After Successful Login

The JSON document with a token set represents the Assets.  These Assets are stored in a Redis cache on the server, and a key is issued to retrieve them.  Each application has its own Token Cache.  The Assets are made up of the `access_token`, `refresh_token`, and the `expires_in` values.

That returned Assets key is SHA-256 encrypted, and set in the browser in a secure cookie.  That cookie is only good for this application, and cannot be read by JavaScript (`http-only`).

### Authenticated Requests

That encrypted cookie can now be used with the application to make authenticated requests.  The browser will send the cookie with each request, and follow the path as laid out in the diagram.

![BFF Pattern](./BFF.png)

#### General Steps

1. User makes a request for a resource from a browser application
2. If there is no first-party cookie, then proceed as though anonymous.  If the resource is protected, then a 401 or 403 status code is returned.
   1. For the Science Portal, this means denying access with a modal login box as authentication is required.
   2. For the Storage UI, this means producing a button to optionally authenticate, as public browsing is allowed for Public items.
3. Decrypt the cookie if present, then use the key to look up the Assets in the Redis cache.
4. Use the Access Token from the Assets as a Bearer token in the request header to the API.

If the Access Token is valid (and the user is granted access to the resource), then the resource is returned.  The system will check the `expires_in` value to determine if the Access Token will soon expire, and if so, will request a refresh.

1. If no Refresh Token is present in the Assets, the user needs to re-authenticate.
2. If a Refresh Token is present in the Assets, then request a new Access Token from the token endpoint.
3. If the Refresh Token is expired (i.e. 401 is returned from the OIdP), then the user needs to re-authenticate.
4. Use the refreshed Access Token and return the resource to the user.
