package com.conveyal.datatools.manager.auth.oidc;

import com.conveyal.datatools.manager.models.FeedSource;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bson.Document;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcPermissionsTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PROJECT = "project";
    private static final String OTHER_PROJECT = "other-project";

    @Test
    void deniesAccessToNewIdentities() {
        var profile = OidcPermissions.profile(identity("new-user"), "");
        assertFalse(profile.canAdministerApplication());
        assertFalse(profile.hasProject(PROJECT, null));
        assertFalse(profile.canViewFeed(feed(PROJECT, "feed")));
        assertFalse(profile.canEditGTFS(feed(PROJECT, "feed")));
    }

    @Test
    void bootstrapsAdministrationBySubjectOnly() {
        assertTrue(OidcPermissions.profile(identity("initial-admin"), "initial-admin").canAdministerApplication());
        assertFalse(OidcPermissions.profile(identity("different-user"), "initial-admin").canAdministerApplication());
        assertFalse(OidcPermissions.profile(identity("initial-admin"), "admin@example.test").canAdministerApplication());
    }

    @Test
    void keepsProjectViewAndIndividualFeedEditsSeparate() {
        var profile = OidcPermissions.profile(identity("editor",
            grant(PROJECT, "viewer", null), grant(PROJECT, "editor", "editable")), "");
        assertTrue(profile.hasProject(PROJECT, null));
        assertTrue(profile.canViewFeed(feed(PROJECT, "read-only")));
        assertFalse(profile.canEditGTFS(feed(PROJECT, "read-only")));
        assertTrue(profile.canEditGTFS(feed(PROJECT, "editable")));
        assertFalse(profile.canManageFeed(feed(PROJECT, "editable")));
        assertFalse(profile.canViewFeed(feed(OTHER_PROJECT, "editable")));
    }

    @Test
    void limitsApprovalAndManagementToTheAssignedFeeds() {
        var profile = OidcPermissions.profile(identity("manager",
            grant(PROJECT, "feed-manager", "managed"), grant(PROJECT, "approver", "approved")), "");
        assertTrue(profile.canManageFeed(feed(PROJECT, "managed")));
        assertFalse(profile.canEditGTFS(feed(PROJECT, "managed")));
        assertFalse(profile.canManageFeed(feed(PROJECT, "approved")));
        assertTrue(profile.canApproveGTFS(null, PROJECT, "approved"));
        assertFalse(profile.canApproveGTFS(null, PROJECT, "managed"));
    }

    @Test
    void grantsProjectAdminsAccessToTheirProjectOnly() {
        var profile = OidcPermissions.profile(identity("project-admin", grant(PROJECT, "project-admin", null)), "");
        assertTrue(profile.canAdministerProject(feed(PROJECT, "any-feed")));
        assertTrue(profile.canManageFeed(feed(PROJECT, "any-feed")));
        assertFalse(profile.canAdministerApplication());
        assertFalse(profile.canAdministerProject(feed(OTHER_PROJECT, "any-feed")));
    }

    @Test
    void checksFeedOwnershipAndRejectsEscalatingOrUnknownGrants() throws Exception {
        assertThrows(IllegalArgumentException.class,
            () -> parse("{\"projectId\":\"project\",\"role\":\"editor\",\"feedId\":\"foreign\"}"));
        assertThrows(IllegalArgumentException.class,
            () -> parse("{\"projectId\":\"unknown\",\"role\":\"viewer\"}"));
        assertThrows(IllegalArgumentException.class,
            () -> parse("{\"projectId\":\"project\",\"role\":\"editor\",\"feedId\":\"*\"}"));
        assertThrows(IllegalArgumentException.class,
            () -> parse("{\"projectId\":\"project\",\"role\":\"project-admin\",\"feedId\":\"editable\"}"));
        assertThrows(IllegalArgumentException.class,
            () -> parse("{\"projectId\":\"project\",\"role\":\"administer-application\"}"));
        assertEquals(List.of(grant(PROJECT, "editor", "editable")),
            parse("{\"projectId\":\"project\",\"role\":\"editor\",\"feedId\":\"editable\"}"));
        assertTrue(parse("").isEmpty());
    }

    private static List<Document> parse(String grant) throws Exception {
        return OidcPermissions.parseGrants(MAPPER.readTree("{\"grants\":[" + grant + "]}"),
            PROJECT::equals, (projectId, feedId) -> PROJECT.equals(projectId) && "editable".equals(feedId));
    }

    private static Document identity(String subject, Document... grants) {
        return new Document("_id", "oidc:" + subject).append("subject", subject)
            .append("email", "admin@example.test").append("grants", List.of(grants));
    }

    private static Document grant(String project, String role, String feed) {
        return new Document("projectId", project).append("role", role).append("feedId", feed);
    }

    private static FeedSource feed(String project, String id) {
        var feed = new FeedSource() {
            @Override public String organizationId() {
                return null;
            }
        };
        feed.projectId = project;
        feed.id = id;
        return feed;
    }
}
