package com.conveyal.datatools.manager.auth.oidc;

import com.conveyal.datatools.manager.persistence.Persistence;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.bson.Document;
import spark.Request;
import spark.Response;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Locale;

import static com.conveyal.datatools.manager.DataManager.getConfigPropertyAsText;
import static spark.Spark.before;
import static spark.Spark.get;
import static spark.Spark.post;

/** Opt-in OIDC endpoints for establishing and inspecting a Datatools session. */
public final class OidcController {
    public static final String PREFIX = "/api/auth/oidc/";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final OidcClient client;
    private final OidcStore store;
    private final URI origin;
    private final String browserCookie;
    private final String sessionCookie;
    private final boolean secure;

    private OidcController(OidcClient client, OidcStore store, URI origin) {
        this.client = client;
        this.store = store;
        this.origin = origin;
        secure = "https".equals(origin.getScheme());
        String prefix = secure ? "__Host-" : "";
        browserCookie = prefix + "datatools-oidc-login";
        sessionCookie = prefix + "datatools-oidc-session";
    }

    public static void registerIfEnabled() throws IOException {
        if (!Boolean.parseBoolean(setting("OIDC_ENABLED"))) return;
        URI origin = publicOrigin(URI.create(getConfigPropertyAsText("application.public_url", "")));
        String issuer = require("OIDC_ISSUER", setting("OIDC_ISSUER"));
        String clientId = require("OIDC_CLIENT_ID", setting("OIDC_CLIENT_ID"));
        String secret = require("OIDC_CLIENT_SECRET", System.getenv("OIDC_CLIENT_SECRET"));
        OidcClient client;
        try {
            client = new OidcClient(URI.create(issuer), clientId, secret, origin.resolve(PREFIX + "callback"));
        } catch (GeneralException | IOException e) {
            throw new IOException("OIDC discovery failed. Check OIDC_ISSUER and provider connectivity.");
        }
        OidcStore store = new OidcStore(Persistence.getMongoDatabase(), issuer, clientId);
        OidcController controller = new OidcController(client, store, origin);
        before(PREFIX + "*", (request, response) -> {
            response.header("Cache-Control", "no-store");
            response.header("Referrer-Policy", "no-referrer");
        });
        get(PREFIX + "login", controller::login);
        get(PREFIX + "callback", controller::callback);
        get(PREFIX + "session", controller::session);
        post(PREFIX + "logout", controller::logout);
    }

    private String login(Request request, Response response) {
        String state = randomToken();
        String browser = randomToken();
        String nonce = new Nonce(32).getValue();
        String verifier = new CodeVerifier().getValue();
        store.saveLogin(state, browser, nonce, verifier);
        setCookie(response, browserCookie, browser, OidcStore.LOGIN_LIFETIME);
        response.redirect(client.authorize(state, nonce, verifier).toString());
        return "";
    }

    private String callback(Request request, Response response) {
        String state = parameter(request, "state");
        String browser = request.cookie(browserCookie);
        if (!isToken(state) || !isToken(browser)) return error(response, 400, "Invalid or expired OIDC login.");
        Document login = store.consumeLogin(state, browser);
        if (login == null) return error(response, 400, "Invalid or expired OIDC login.");
        setCookie(response, browserCookie, "", Duration.ZERO);
        String code = parameter(request, "code");
        String issuer = parameter(request, "iss");
        if (request.queryParams().contains("error") || code == null || code.isBlank() || code.length() > 4_096
            || (issuer == null && request.queryParams().contains("iss")) || !client.matchesResponseIssuer(issuer)) {
            return error(response, 400, "OIDC login was declined or the response was invalid.");
        }
        IDTokenClaimsSet claims;
        try {
            claims = client.exchange(code, login.getString("nonce"), login.getString("verifier"));
        } catch (IOException | GeneralException | BadJOSEException | JOSEException e) {
            return error(response, 401, "OIDC login could not be verified.");
        }
        String identity = store.upsertIdentity(claims);
        String priorSession = request.cookie(sessionCookie);
        if (isToken(priorSession)) store.removeSession(priorSession);
        String session = randomToken();
        store.createSession(session, identity);
        setCookie(response, sessionCookie, session, OidcStore.SESSION_LIFETIME);
        response.redirect(origin.resolve("/").toString(), 303);
        return "";
    }

    private String session(Request request, Response response) {
        ObjectNode result = MAPPER.createObjectNode().put("authenticated", false);
        response.type("application/json");
        String token = request.cookie(sessionCookie);
        Document session = isToken(token) ? store.getSession(token) : null;
        if (session == null) return result.toString();
        Document identity = store.getIdentity(session.getString("identity"));
        if (identity == null) return result.toString();
        result.put("authenticated", true);
        result.put("expiresAt", session.getDate("expiresAt").toInstant().toString());
        result.putObject("user")
            .put("id", identity.getString("_id"))
            .put("name", identity.getString("name"))
            .put("email", identity.getString("email"))
            .put("emailVerified", Boolean.TRUE.equals(identity.getBoolean("emailVerified")));
        return result.toString();
    }

    private String logout(Request request, Response response) {
        if (!origin.toString().equals(request.headers("Origin"))) {
            return error(response, 403, "OIDC logout requires a same-origin request.");
        }
        String token = request.cookie(sessionCookie);
        if (isToken(token)) store.removeSession(token);
        setCookie(response, sessionCookie, "", Duration.ZERO);
        response.status(204);
        return "";
    }

    private void setCookie(Response response, String name, String value, Duration age) {
        response.raw().addHeader("Set-Cookie", name + "=" + value + "; Path=/; Max-Age=" + age.toSeconds()
            + "; HttpOnly; SameSite=Lax" + (secure ? "; Secure" : ""));
    }

    private static String parameter(Request request, String name) {
        String[] values = request.queryParamsValues(name);
        return values != null && values.length == 1 ? values[0] : null;
    }

    private static String error(Response response, int status, String message) {
        response.status(status);
        response.type("application/json");
        return MAPPER.createObjectNode().put("message", message).toString();
    }

    private static String randomToken() {
        return new State(32).getValue();
    }

    private static boolean isToken(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{43}");
    }

    private static String setting(String key) {
        String value = System.getenv(key);
        return value == null ? getConfigPropertyAsText(key, "") : value;
    }

    private static String require(String key, String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(key + " is required for OIDC.");
        return value;
    }

    static URI publicOrigin(URI url) {
        OidcClient.requireWebUri(url);
        if (url.getRawQuery() != null || !(url.getRawPath().isEmpty() || "/".equals(url.getRawPath()))) {
            throw new IllegalArgumentException("application.public_url must be an origin when OIDC is enabled.");
        }
        String scheme = url.getScheme().toLowerCase(Locale.ROOT);
        String host = url.getHost().toLowerCase(Locale.ROOT);
        int port = url.getPort();
        boolean defaultPort = port == -1 || ("https".equals(scheme) ? port == 443 : port == 80);
        return URI.create(scheme + "://" + host + (defaultPort ? "" : ":" + port));
    }
}
