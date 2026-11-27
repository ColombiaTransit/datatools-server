package com.conveyal.datatools.manager.auth.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcClientTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CLIENT_ID = "datatools";
    private static final String NONCE = "test-nonce";
    private static final String VERIFIER = new CodeVerifier().getValue();
    private static final URI REDIRECT = URI.create("https://datatools.example/api/auth/oidc/callback");
    private static RSAKey signingKey;
    private final AtomicReference<String> idToken = new AtomicReference<>();
    private final AtomicReference<String> tokenAuthorization = new AtomicReference<>();
    private final AtomicReference<Map<String, List<String>>> tokenParameters = new AtomicReference<>();
    private HttpServer provider;
    private String issuer;
    private OidcClient client;

    @BeforeAll
    static void createSigningKey() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("provider-key").generate();
    }

    @BeforeEach
    void startProvider() throws Exception {
        provider = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        issuer = "http://127.0.0.1:" + provider.getAddress().getPort() + "/realm";
        provider.createContext("/realm/.well-known/openid-configuration", request -> {
            var metadata = new LinkedHashMap<String, Object>();
            metadata.put("issuer", issuer);
            metadata.put("authorization_endpoint", issuer + "/authorize");
            metadata.put("token_endpoint", issuer + "/token");
            metadata.put("jwks_uri", issuer + "/jwks");
            metadata.put("response_types_supported", List.of("code"));
            metadata.put("subject_types_supported", List.of("public"));
            metadata.put("id_token_signing_alg_values_supported", List.of("RS256"));
            metadata.put("code_challenge_methods_supported", List.of("S256"));
            metadata.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic"));
            metadata.put("authorization_response_iss_parameter_supported", true);
            json(request, MAPPER.writeValueAsString(metadata));
        });
        provider.createContext("/realm/jwks", request -> json(request, new JWKSet(signingKey.toPublicJWK()).toString()));
        provider.createContext("/realm/token", request -> {
            tokenAuthorization.set(request.getRequestHeaders().getFirst("Authorization"));
            tokenParameters.set(URLUtils.parseParameters(new String(request.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8)));
            json(request, MAPPER.createObjectNode().put("token_type", "Bearer").put("access_token", "unused-test-token")
                .put("id_token", idToken.get()).toString());
        });
        provider.start();
        client = new OidcClient(URI.create(issuer), CLIENT_ID, "test-client-secret", REDIRECT);
    }

    @AfterEach
    void stopProvider() {
        if (provider != null) provider.stop(0);
    }

    @Test
    void exchangesAuthorizationCodeWithPkceAndVerifiesSignedIdToken() throws Exception {
        URI authorize = client.authorize("test-state", NONCE, VERIFIER);
        var query = URLUtils.parseParameters(authorize.getRawQuery());
        assertEquals("/realm/authorize", authorize.getPath());
        assertEquals(List.of("test-state"), query.get("state"));
        assertEquals(List.of(NONCE), query.get("nonce"));
        assertEquals(List.of("S256"), query.get("code_challenge_method"));
        assertEquals(List.of(CodeChallenge.compute(CodeChallengeMethod.S256, new CodeVerifier(VERIFIER)).getValue()),
            query.get("code_challenge"));
        assertFalse(query.containsKey("code_verifier"));

        issueIdToken(issuer, CLIENT_ID, NONCE, Instant.now().plusSeconds(120));
        var claims = client.exchange("test-code", NONCE, VERIFIER);
        assertEquals("provider-user", claims.getSubject().getValue());
        assertEquals("user@example.test", claims.getStringClaim("email"));
        assertTrue(tokenAuthorization.get().startsWith("Basic "));
        assertEquals(List.of("test-code"), tokenParameters.get().get("code"));
        assertEquals(List.of(VERIFIER), tokenParameters.get().get("code_verifier"));
        assertEquals(List.of(REDIRECT.toString()), tokenParameters.get().get("redirect_uri"));
    }

    @Test
    void rejectsAnIdTokenWithAnIncorrectNonce() throws Exception {
        issueIdToken(issuer, CLIENT_ID, "incorrect-nonce", Instant.now().plusSeconds(120));
        assertThrows(BadJOSEException.class, () -> client.exchange("test-code", NONCE, VERIFIER));
    }

    @Test
    void rejectsAnIdTokenForADifferentClient() throws Exception {
        issueIdToken(issuer, "other-client", NONCE, Instant.now().plusSeconds(120));
        assertThrows(BadJOSEException.class, () -> client.exchange("test-code", NONCE, VERIFIER));
    }

    @Test
    void rejectsAnIdTokenFromADifferentIssuer() throws Exception {
        issueIdToken(issuer + "-wrong", CLIENT_ID, NONCE, Instant.now().plusSeconds(120));
        assertThrows(BadJOSEException.class, () -> client.exchange("test-code", NONCE, VERIFIER));
    }

    @Test
    void rejectsAnExpiredIdToken() throws Exception {
        issueIdToken(issuer, CLIENT_ID, NONCE, Instant.now().minusSeconds(600));
        assertThrows(BadJOSEException.class, () -> client.exchange("test-code", NONCE, VERIFIER));
    }

    @Test
    void rejectsAnIdTokenSignedWithAnUntrustedKey() throws Exception {
        issueIdToken(issuer, CLIENT_ID, NONCE, Instant.now().plusSeconds(120),
            new RSAKeyGenerator(2048).keyID(signingKey.getKeyID()).generate());
        assertThrows(BadJOSEException.class, () -> client.exchange("test-code", NONCE, VERIFIER));
    }

    @Test
    void checksTheCallbackIssuerWhenAdvertised() {
        assertTrue(client.matchesResponseIssuer(issuer));
        assertFalse(client.matchesResponseIssuer(issuer + "-wrong"));
        assertFalse(client.matchesResponseIssuer(null));
    }

    @Test
    void restrictsPublicOriginToHttpsOrLoopbackAndNormalizesDefaultPort() {
        assertEquals(URI.create("https://datatools.example"),
            OidcController.publicOrigin(URI.create("https://DATATOOLS.example:443/")));
        assertEquals(URI.create("http://localhost:9966"),
            OidcController.publicOrigin(URI.create("http://localhost:9966/")));
        assertThrows(IllegalArgumentException.class,
            () -> OidcController.publicOrigin(URI.create("http://datatools.example")));
        assertThrows(IllegalArgumentException.class,
            () -> OidcController.publicOrigin(URI.create("https://datatools.example/extra")));
    }

    private void issueIdToken(String issuer, String audience, String nonce, Instant expiresAt) throws Exception {
        issueIdToken(issuer, audience, nonce, expiresAt, signingKey);
    }

    private void issueIdToken(String issuer, String audience, String nonce, Instant expiresAt, RSAKey key)
        throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
            new JWTClaimsSet.Builder().issuer(issuer).audience(audience).subject("provider-user")
                .issueTime(Date.from(Instant.now().minusSeconds(900))).expirationTime(Date.from(expiresAt))
                .claim("nonce", nonce).claim("email", "user@example.test").build());
        jwt.sign(new RSASSASigner(key));
        idToken.set(jwt.serialize());
    }

    private static void json(HttpExchange request, String value) throws IOException {
        byte[] content = value.getBytes(StandardCharsets.UTF_8);
        request.getResponseHeaders().set("Content-Type", "application/json");
        request.sendResponseHeaders(200, content.length);
        try (var response = request.getResponseBody()) {
            response.write(content);
        }
    }
}
