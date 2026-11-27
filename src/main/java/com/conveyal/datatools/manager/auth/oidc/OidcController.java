package com.conveyal.datatools.manager.auth.oidc;

import com.conveyal.datatools.manager.auth.Auth0UserProfile;
import com.conveyal.datatools.manager.persistence.Persistence;
import com.fasterxml.jackson.core.JsonProcessingException;
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
import java.util.List;
import java.util.Locale;

import static com.conveyal.datatools.manager.DataManager.getConfigPropertyAsText;
import static spark.Spark.before;
import static spark.Spark.get;
import static spark.Spark.halt;
import static spark.Spark.post;
import static spark.Spark.put;

/** Opt-in OIDC endpoints for establishing and inspecting a Datatools session. */
public final class OidcController {
    public static final String PREFIX = "/api/auth/oidc/";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int USER_PAGE_SIZE = 100;
    private final OidcClient client;
    private final OidcStore store;
    private final URI origin;
    private final String bootstrapSubject;
    private final String browserCookie;
    private final String sessionCookie;
    private final boolean secure;

    private OidcController(OidcClient client, OidcStore store, URI origin, String bootstrapSubject) {
        this.client = client;
        this.store = store;
        this.origin = origin;
        this.bootstrapSubject = bootstrapSubject;
        secure = "https".equals(origin.getScheme());
        String prefix = secure ? "__Host-" : "";
        browserCookie = prefix + "datatools-oidc-login";
        sessionCookie = prefix + "datatools-oidc-session";
    }

    public static boolean isEnabled() {
        return Boolean.parseBoolean(setting("OIDC_ENABLED"));
    }

    public static OidcController registerIfEnabled() throws IOException {
        if (!isEnabled()) return null;
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
        OidcController controller = new OidcController(client, store, origin, setting("OIDC_ADMIN_SUBJECT"));
        before(PREFIX + "*", (request, response) -> {
            response.header("Cache-Control", "no-store");
            response.header("Referrer-Policy", "no-referrer");
        });
        get(PREFIX + "login", controller::login);
        get(PREFIX + "callback", controller::callback);
        get(PREFIX + "session", controller::session);
        post(PREFIX + "logout", controller::logout);
        get(PREFIX + "users", controller::listUsers);
        get(PREFIX + "users/:id/grants", controller::getGrants);
        put(PREFIX + "users/:id/grants", controller::replaceGrants);
        return controller;
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
        Document session = readSession(request);
        if (session == null) return result.toString();
        Document identity = store.getIdentity(session.getString("identity"));
        if (identity == null) return result.toString();
        result.put("authenticated", true);
        result.put("expiresAt", session.getDate("expiresAt").toInstant().toString());
        result.set("user", userSummary(identity).put("subject", identity.getString("subject")));
        result.putObject("permissions")
            .put("applicationAdmin", OidcPermissions.profile(identity, bootstrapSubject).canAdministerApplication())
            .set("grants", MAPPER.valueToTree(OidcPermissions.grants(identity)));
        return result.toString();
    }

    private String listUsers(Request request, Response response) {
        requireAdministrator(request, response);
        List<Document> users = store.listIdentities(parameter(request, "after"), USER_PAGE_SIZE + 1);
        ObjectNode result = MAPPER.createObjectNode();
        var entries = result.putArray("users");
        users.stream().limit(USER_PAGE_SIZE).map(OidcController::userSummary).forEach(entries::add);
        if (users.size() > USER_PAGE_SIZE) result.put("next", users.get(USER_PAGE_SIZE - 1).getString("_id"));
        response.type("application/json");
        return result.toString();
    }

    private String getGrants(Request request, Response response) {
        requireAdministrator(request, response);
        Document identity = store.getIdentity(request.params(":id"));
        if (identity == null) return error(response, 404, "OIDC user not found.");
        response.type("application/json");
        return grantsResponse(OidcPermissions.grants(identity));
    }

    private String replaceGrants(Request request, Response response) {
        if (!isSameOrigin(request)) return error(response, 403, "Changing OIDC grants requires a same-origin request.");
        requireAdministrator(request, response);
        String body = request.body();
        if (body.length() > 65_536) return error(response, 413, "OIDC grants request is too large.");
        List<Document> grants;
        try {
            grants = OidcPermissions.parseGrants(MAPPER.readTree(body),
                projectId -> Persistence.projects.getById(projectId) != null,
                (projectId, feedId) -> {
                    var feed = Persistence.feedSources.getById(feedId);
                    return feed != null && projectId.equals(feed.projectId);
                });
        } catch (JsonProcessingException e) {
            return error(response, 400, "Invalid grants JSON.");
        } catch (IllegalArgumentException e) {
            return error(response, 400, e.getMessage());
        }
        if (!store.replaceGrants(request.params(":id"), grants)) return error(response, 404, "OIDC user not found.");
        response.type("application/json");
        return grantsResponse(grants);
    }

    private void requireAdministrator(Request request, Response response) {
        Document session = readSession(request);
        Document identity = session == null ? null : store.getIdentity(session.getString("identity"));
        if (identity == null) halt(401, error(response, 401, "An OIDC session is required."));
        if (!OidcPermissions.profile(identity, bootstrapSubject).canAdministerApplication()) {
            halt(403, error(response, 403, "Datatools administrator permission is required."));
        }
    }

    /** Authenticate using current local grants, including changes since login. */
    public void checkUser(Request request, Response response) {
        if (requiresSameOrigin(request.requestMethod(), request.pathInfo())
            && !matchesOrigin(origin, request.headers("Origin"), request.headers("Referer"))) {
            halt(403, error(response, 403, "This request requires the Datatools origin."));
        }
        Document session = readSession(request);
        Document identity = session == null ? null : store.getIdentity(session.getString("identity"));
        if (identity == null) halt(401, error(response, 401, "An OIDC session is required."));
        request.attribute("user", OidcPermissions.profile(identity, bootstrapSubject));
        request.attribute("oidcAuthenticated", true);
    }

    public static boolean isAuthenticatedRequest(Request request) {
        return Boolean.TRUE.equals(request.attribute("oidcAuthenticated"));
    }

    public static Auth0UserProfile anonymousProfile() {
        return OidcPermissions.profile(new Document(), "");
    }

    static boolean requiresSameOrigin(String method, String path) {
        // Some legacy GET endpoints start jobs or issue download tokens.
        if ("GET".equals(method)) {
            return path.matches("(?i).*/secure/(project/[^/]+/(download|downloadtoken|thirdPartySync/[^/]+)"
                + "|snapshot/[^/]+/(download|downloadtoken)|feedversion/[^/]+/downloadtoken)/?");
        }
        return !("HEAD".equals(method) || "OPTIONS".equals(method));
    }

    static boolean matchesOrigin(URI expected, String originHeader, String referer) {
        if (originHeader != null) return expected.toString().equals(originHeader);
        if (referer == null) return false;
        try {
            URI page = URI.create(referer);
            if (page.getHost() == null || page.getRawUserInfo() != null) return false;
            return expected.equals(publicOrigin(URI.create(page.getScheme() + "://" + page.getRawAuthority())));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private Document readSession(Request request) {
        String token = request.cookie(sessionCookie);
        return isToken(token) ? store.getSession(token) : null;
    }

    private static ObjectNode userSummary(Document identity) {
        return MAPPER.createObjectNode()
            .put("id", identity.getString("_id"))
            .put("name", identity.getString("name"))
            .put("email", identity.getString("email"))
            .put("emailVerified", Boolean.TRUE.equals(identity.getBoolean("emailVerified")));
    }

    private static String grantsResponse(List<Document> grants) {
        ObjectNode result = MAPPER.createObjectNode();
        result.set("grants", MAPPER.valueToTree(grants));
        return result.toString();
    }

    private boolean isSameOrigin(Request request) {
        return origin.toString().equals(request.headers("Origin"));
    }

    private String logout(Request request, Response response) {
        if (!isSameOrigin(request)) {
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
