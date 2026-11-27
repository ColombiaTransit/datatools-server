package com.conveyal.datatools.manager.auth.oidc;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.UpdateOptions;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.bson.Document;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.mongodb.client.model.Filters.and;
import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Filters.gt;
import static com.mongodb.client.model.Updates.combine;
import static com.mongodb.client.model.Updates.set;
import static com.mongodb.client.model.Updates.setOnInsert;

/** Persists OIDC login transactions, sessions and provider identities in MongoDB. */
final class OidcStore {
    static final Duration LOGIN_LIFETIME = Duration.ofMinutes(5);
    static final Duration SESSION_LIFETIME = Duration.ofHours(8);
    private static final String EXPIRY = "expiresAt";
    private final MongoCollection<Document> logins;
    private final MongoCollection<Document> sessions;
    private final MongoCollection<Document> identities;
    private final String issuer;
    private final String clientId;

    OidcStore(MongoDatabase database, String issuer, String clientId) {
        this.issuer = issuer;
        this.clientId = clientId;
        logins = database.getCollection("oidcLoginAttempts");
        sessions = database.getCollection("oidcSessions");
        identities = database.getCollection("oidcIdentities");
        logins.createIndex(Indexes.ascending(EXPIRY), new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
        sessions.createIndex(Indexes.ascending(EXPIRY), new IndexOptions().expireAfter(0L, TimeUnit.SECONDS));
    }

    void saveLogin(String state, String browser, String nonce, String verifier) {
        logins.insertOne(new Document("_id", sessionKey(state)).append("browser", digest(browser))
            .append("nonce", nonce).append("verifier", verifier).append(EXPIRY, expiresIn(LOGIN_LIFETIME)));
    }

    Document consumeLogin(String state, String browser) {
        return logins.findOneAndDelete(and(eq("_id", sessionKey(state)), eq("browser", digest(browser)),
            gt(EXPIRY, new Date())));
    }

    String upsertIdentity(IDTokenClaimsSet claims) {
        String subject = claims.getSubject().getValue();
        String id = "oidc:" + digest(issuer + "\n" + subject);
        identities.updateOne(eq("_id", id), combine(
            setOnInsert("issuer", issuer),
            setOnInsert("subject", subject),
            set("name", claims.getStringClaim("name")),
            set("email", claims.getStringClaim("email")),
            set("emailVerified", Boolean.TRUE.equals(claims.getBooleanClaim("email_verified")))
        ), new UpdateOptions().upsert(true));
        return id;
    }

    void createSession(String session, String identity) {
        sessions.insertOne(new Document("_id", sessionKey(session)).append("identity", identity)
            .append(EXPIRY, expiresIn(SESSION_LIFETIME)));
    }

    Document getSession(String session) {
        return sessions.find(and(eq("_id", sessionKey(session)), gt(EXPIRY, new Date()))).first();
    }

    Document getIdentity(String id) {
        return identities.find(and(eq("_id", id), eq("issuer", issuer))).first();
    }

    List<Document> listIdentities(String after, int limit) {
        var filter = after == null ? eq("issuer", issuer) : and(eq("issuer", issuer), gt("_id", after));
        return identities.find(filter).sort(Sorts.ascending("_id")).limit(limit).into(new ArrayList<>());
    }

    boolean replaceGrants(String identity, List<Document> grants) {
        return identities.updateOne(and(eq("_id", identity), eq("issuer", issuer)), set("grants", grants))
            .getMatchedCount() == 1;
    }

    void removeSession(String session) {
        sessions.deleteOne(eq("_id", sessionKey(session)));
    }

    private String sessionKey(String token) {
        return digest(issuer + "\n" + clientId + "\n" + token);
    }

    private static Date expiresIn(Duration lifetime) {
        return Date.from(Instant.now().plus(lifetime));
    }

    private static String digest(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable.", e);
        }
    }
}
