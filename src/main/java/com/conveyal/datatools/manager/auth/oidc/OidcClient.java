package com.conveyal.datatools.manager.auth.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.List;

/** OIDC discovery, authorization code exchange, and ID token validation. */
final class OidcClient {
    private static final int CONNECT_TIMEOUT = 5_000;
    private static final int READ_TIMEOUT = 10_000;
    private final Issuer issuer;
    private final ClientID clientId;
    private final URI redirectUri;
    private final OIDCProviderMetadata metadata;
    private final ClientAuthentication clientAuthentication;
    private final IDTokenValidator validator;

    OidcClient(URI issuerUri, String clientId, String clientSecret, URI redirectUri)
        throws GeneralException, IOException {
        requireWebUri(issuerUri);
        if (issuerUri.getRawQuery() != null) throw new IllegalArgumentException("OIDC issuer must not have a query.");
        this.issuer = new Issuer(issuerUri.toString());
        this.clientId = new ClientID(clientId);
        this.redirectUri = redirectUri;
        metadata = OIDCProviderMetadata.resolve(issuer, null, OidcClient::configureRequest);
        requireWebUri(metadata.getAuthorizationEndpointURI());
        requireWebUri(metadata.getTokenEndpointURI());
        requireWebUri(metadata.getJWKSetURI());
        if (metadata.getIDTokenJWSAlgs() == null || !metadata.getIDTokenJWSAlgs().contains(JWSAlgorithm.RS256)) {
            throw new IllegalArgumentException("The provider must support RS256 ID tokens.");
        }
        if (metadata.getCodeChallengeMethods() != null
            && !metadata.getCodeChallengeMethods().contains(CodeChallengeMethod.S256)) {
            throw new IllegalArgumentException("The provider must support S256 PKCE.");
        }
        List<ClientAuthenticationMethod> methods = metadata.getTokenEndpointAuthMethods();
        if (methods == null || methods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            clientAuthentication = new ClientSecretBasic(this.clientId, new Secret(clientSecret));
        } else if (methods.contains(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
            clientAuthentication = new ClientSecretPost(this.clientId, new Secret(clientSecret));
        } else {
            throw new IllegalArgumentException("The provider must support client_secret_basic or client_secret_post.");
        }
        var keys = new DefaultResourceRetriever(CONNECT_TIMEOUT, READ_TIMEOUT, 256 * 1024) {
            @Override
            protected HttpURLConnection openHTTPConnection(URL url) throws IOException {
                HttpURLConnection connection = super.openHTTPConnection(url);
                connection.setInstanceFollowRedirects(false);
                return connection;
            }
        };
        validator = new IDTokenValidator(issuer, this.clientId, JWSAlgorithm.RS256, metadata.getJWKSetURI().toURL(), keys);
    }

    URI authorize(String state, String nonce, String verifier) {
        return new AuthenticationRequest.Builder(ResponseType.CODE, new Scope("openid", "profile", "email"),
            clientId, redirectUri)
            .endpointURI(metadata.getAuthorizationEndpointURI())
            .responseMode(ResponseMode.QUERY)
            .state(new State(state))
            .nonce(new Nonce(nonce))
            .codeChallenge(new CodeVerifier(verifier), CodeChallengeMethod.S256)
            .build().toURI();
    }

    boolean matchesResponseIssuer(String responseIssuer) {
        return responseIssuer == null ? !metadata.supportsAuthorizationResponseIssuerParam()
            : issuer.getValue().equals(responseIssuer);
    }

    IDTokenClaimsSet exchange(String code, String nonce, String verifier)
        throws IOException, GeneralException, BadJOSEException, JOSEException {
        var grant = new AuthorizationCodeGrant(new AuthorizationCode(code), redirectUri, new CodeVerifier(verifier));
        HTTPRequest request = new TokenRequest.Builder(metadata.getTokenEndpointURI(), clientAuthentication, grant)
            .build().toHTTPRequest();
        configureRequest(request);
        TokenResponse response = OIDCTokenResponseParser.parse(request.send());
        if (!(response instanceof OIDCTokenResponse)) throw new GeneralException("Provider rejected the code exchange.");
        return validator.validate(((OIDCTokenResponse) response).getOIDCTokens().getIDToken(), new Nonce(nonce));
    }

    private static void configureRequest(HTTPRequest request) {
        request.setConnectTimeout(CONNECT_TIMEOUT);
        request.setReadTimeout(READ_TIMEOUT);
        request.setFollowRedirects(false);
    }

    /** Permit HTTP only for explicitly configured loopback development endpoints. */
    static void requireWebUri(URI uri) {
        if (uri == null || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Invalid OIDC URL.");
        }
        String host = uri.getHost();
        boolean loopback = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "[::1]".equals(host);
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !("http".equalsIgnoreCase(uri.getScheme()) && loopback)) {
            throw new IllegalArgumentException("OIDC requires HTTPS outside loopback.");
        }
    }
}
