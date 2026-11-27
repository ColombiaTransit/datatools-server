package com.conveyal.datatools.manager.auth.oidc;

import com.conveyal.datatools.manager.auth.Auth0UserProfile;
import com.conveyal.datatools.manager.models.FeedSource;
import com.conveyal.datatools.manager.persistence.Persistence;
import graphql.language.Argument;
import graphql.language.Field;
import graphql.language.Node;
import graphql.language.OperationDefinition;
import graphql.language.StringValue;
import graphql.language.VariableDefinition;
import graphql.language.VariableReference;
import graphql.parser.Parser;
import spark.Request;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static com.conveyal.datatools.common.utils.SparkUtils.logMessageAndHalt;
import static com.mongodb.client.model.Filters.eq;

/** Feed access checks for editor requests and the GTFS query endpoint. */
public final class OidcApiPermissions {
    private OidcApiPermissions() {}

    public static void checkEditor(Request request) {
        String feedId = request.queryParams("feedId");
        FeedSource feed = feedId == null || feedId.isBlank() ? null : Persistence.feedSources.getById(feedId);
        if (feed == null) {
            logMessageAndHalt(request, 400, "Must provide valid feedId parameter.");
            return;
        }
        Auth0UserProfile user = request.attribute("user");
        boolean read = "GET".equals(request.requestMethod()) || "HEAD".equals(request.requestMethod());
        if (!(read ? user.canViewFeed(feed) : user.canEditGTFS(feed))) {
            logMessageAndHalt(request, 403, "User is not authorized for this feed.");
        }
    }

    public static boolean canReadNamespace(Auth0UserProfile user, String namespace) {
        var version = Persistence.feedVersions.getOneFiltered(eq("namespace", namespace));
        if (version != null) {
            var feed = version.parentFeedSource();
            return feed != null && ((feed.isPublic && namespace.equals(feed.publishedVersionId)) || user.canViewFeed(feed));
        }
        var snapshot = Persistence.snapshots.getOneFiltered(eq("namespace", namespace));
        if (snapshot != null) {
            var feed = Persistence.feedSources.getById(snapshot.feedSourceId);
            return feed != null && user.canViewFeed(feed);
        }
        var feed = Persistence.feedSources.getOneFiltered(eq("editorNamespace", namespace));
        return feed != null && user.canViewFeed(feed);
    }

    /** Collect all explicit namespaces, including overrides on nested fields and inside fragments. */
    public static Set<String> namespaces(String query, Map<String, Object> variables) {
        var document = new Parser().parseDocument(query);
        var operations = document.getDefinitionsOfType(OperationDefinition.class);
        if (operations.size() != 1 || operations.get(0).getOperation() != OperationDefinition.Operation.QUERY) {
            throw new IllegalArgumentException("Supply one GraphQL query operation.");
        }
        var values = new HashMap<String, Object>();
        for (VariableDefinition variable : operations.get(0).getVariableDefinitions()) {
            if (variable.getDefaultValue() instanceof StringValue) {
                values.put(variable.getName(), ((StringValue) variable.getDefaultValue()).getValue());
            }
        }
        values.putAll(variables);

        var result = new LinkedHashSet<String>();
        var pending = new ArrayDeque<Node<?>>();
        pending.add(document);
        while (!pending.isEmpty()) {
            Node<?> node = pending.removeFirst();
            for (Node<?> child : node.getChildren()) pending.addLast(child);
            if (!(node instanceof Field)) continue;
            var field = (Field) node;
            Argument namespace = field.getArguments().stream()
                .filter(arg -> "namespace".equals(arg.getName())).findFirst().orElse(null);
            if (namespace == null) {
                if ("feed".equals(field.getName())) throw new IllegalArgumentException("A feed namespace is required.");
                continue;
            }
            var value = namespace.getValue();
            Object resolved = value instanceof StringValue ? ((StringValue) value).getValue()
                : value instanceof VariableReference ? values.get(((VariableReference) value).getName()) : null;
            if (!(resolved instanceof String) || ((String) resolved).isBlank()) {
                throw new IllegalArgumentException("A feed namespace must be a non-empty string.");
            }
            result.add((String) resolved);
        }
        return result;
    }
}
