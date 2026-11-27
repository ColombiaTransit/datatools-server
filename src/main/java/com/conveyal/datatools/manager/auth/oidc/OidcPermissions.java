package com.conveyal.datatools.manager.auth.oidc;

import com.conveyal.datatools.manager.auth.Auth0UserProfile;
import com.conveyal.datatools.manager.auth.Auth0UserProfile.DatatoolsInfo;
import com.conveyal.datatools.manager.auth.Auth0UserProfile.Organization;
import com.conveyal.datatools.manager.auth.Auth0UserProfile.Permission;
import com.conveyal.datatools.manager.auth.Auth0UserProfile.Project;
import com.conveyal.datatools.manager.auth.Auth0UserProfile.Subscription;
import com.fasterxml.jackson.databind.JsonNode;
import org.bson.Document;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

/** Local OIDC project and feed assignments, translated to Datatools permissions. */
final class OidcPermissions {
    private static final Map<String, List<String>> ROLES = Map.of(
        "viewer", List.of("view-feed"),
        "editor", List.of("view-feed", "edit-gtfs"),
        "feed-manager", List.of("view-feed", "manage-feed"),
        "approver", List.of("view-feed", "approve-gtfs"),
        "project-admin", List.of("administer-project")
    );

    private OidcPermissions() {}

    static List<Document> parseGrants(JsonNode body, Predicate<String> projectExists,
                                      BiPredicate<String, String> feedBelongsToProject) {
        if (body == null || !body.isObject() || !body.path("grants").isArray()) {
            throw new IllegalArgumentException("Supply a grants array.");
        }
        JsonNode grants = body.path("grants");
        if (grants.size() > 200) throw new IllegalArgumentException("Supply at most 200 grants.");
        Set<Document> unique = new LinkedHashSet<>();
        for (JsonNode grant : grants) {
            String projectId = identifier(grant.path("projectId"), "projectId");
            String role = identifier(grant.path("role"), "role");
            JsonNode feed = grant.get("feedId");
            String feedId = feed == null || feed.isNull() ? null : identifier(feed, "feedId");
            if (!ROLES.containsKey(role)) throw new IllegalArgumentException("Unknown Datatools role.");
            if (feedId != null && "project-admin".equals(role)) {
                throw new IllegalArgumentException("Project administrator grants apply to the entire project.");
            }
            if (!projectExists.test(projectId)) throw new IllegalArgumentException("Grant references an unknown project.");
            if (feedId != null && !feedBelongsToProject.test(projectId, feedId)) {
                throw new IllegalArgumentException("Grant references a feed outside its project.");
            }
            unique.add(new Document("projectId", projectId).append("role", role).append("feedId", feedId));
        }
        return new ArrayList<>(unique);
    }

    static List<Document> grants(Document identity) {
        return identity.getList("grants", Document.class, List.of());
    }

    static Auth0UserProfile profile(Document identity, String bootstrapSubject) {
        boolean administrator = !bootstrapSubject.isBlank() && bootstrapSubject.equals(identity.getString("subject"));
        Permission[] global = administrator
            ? new Permission[]{new Permission("administer-application", null)}
            : new Permission[0];
        Map<String, Map<String, Set<String>>> permissions = new LinkedHashMap<>();
        for (Document grant : grants(identity)) {
            Map<String, Set<String>> project = permissions.computeIfAbsent(grant.getString("projectId"),
                ignored -> new LinkedHashMap<>());
            String feed = grant.getString("feedId");
            for (String permission : ROLES.get(grant.getString("role"))) {
                project.computeIfAbsent(permission, ignored -> new LinkedHashSet<>()).add(feed == null ? "*" : feed);
            }
        }
        Project[] projects = permissions.entrySet().stream().map(project -> new Project(project.getKey(),
            project.getValue().entrySet().stream()
                .map(permission -> new Permission(permission.getKey(), permission.getValue().toArray(new String[0])))
                .toArray(Permission[]::new),
            new String[0])).toArray(Project[]::new);
        var info = new DatatoolsInfo("oidc", projects, global, new Organization[0], new Subscription[0]);
        return Auth0UserProfile.fromLocalPermissions(identity.getString("email"), identity.getString("_id"), info);
    }

    private static String identifier(JsonNode node, String field) {
        if (!node.isTextual() || node.textValue().isBlank() || node.textValue().length() > 160 || "*".equals(node.textValue())) {
            throw new IllegalArgumentException("Invalid " + field + ".");
        }
        return node.textValue();
    }
}
