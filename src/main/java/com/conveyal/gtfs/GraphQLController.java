package com.conveyal.gtfs;

import com.conveyal.datatools.manager.auth.Auth0UserProfile;
import com.conveyal.datatools.manager.auth.oidc.OidcApiPermissions;
import com.conveyal.gtfs.graphql.GTFSGraphQL;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import graphql.ExecutionInput;
import graphql.ExecutionResult;
import graphql.introspection.IntrospectionQuery;
import graphql.parser.InvalidSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Request;
import spark.Response;

import javax.sql.DataSource;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.conveyal.datatools.common.utils.SparkUtils.logMessageAndHalt;
import static spark.Spark.get;
import static spark.Spark.post;

/**
 * This Spark Controller contains methods to provide HTTP responses to GraphQL queries, including a query for the
 * GraphQL schema.
 */
public class GraphQLController {
    private static final Logger LOG = LoggerFactory.getLogger(GraphQLController.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    private static boolean checkFeedAccess;

    /**
     * A Spark Controller that responds to a GraphQL query in HTTP GET query parameters.
     */
    public static Map<String, Object> getGraphQL (Request request, Response response) {
        JsonNode varsJson = null;
        try {
            String variables = request.queryParams("variables");
            if (variables != null) varsJson = mapper.readTree(variables);
        } catch (IOException e) {
            LOG.warn("Error processing variables", e);
            logMessageAndHalt(request, 400, "Malformed JSON");
        }
        String queryJson = request.queryParams("query");
        return doQuery(varsJson, queryJson, request);
    }

    /**
     * A Spark Controller that responds to a GraphQL query in an HTTP POST body.
     */
    public static Map<String, Object> postGraphQL (Request req, Response response) {
        JsonNode node = null;
        try {
            node = mapper.readTree(req.body());
        } catch (IOException e) {
            LOG.warn("Error processing POST body JSON", e);
            logMessageAndHalt(req, 400, "Malformed JSON");
        }
        if (node == null || !node.path("query").isTextual()) {
            logMessageAndHalt(req, 400, "A GraphQL query string is required.");
            return null;
        }
        JsonNode vars = node.get("variables");
        String query = node.get("query").asText();
        return doQuery(vars, query, req);
    }

    /**
     * Execute a GraphQL query and return result that fully complies with the GraphQL specification.
     */
    private static Map<String, Object> doQuery (JsonNode varsJson, String queryJson, Request request) {
        long startTime = System.currentTimeMillis();
        if (varsJson == null && queryJson == null) {
            return getSchema(null, null);
        }
        if (queryJson == null || (varsJson != null && !varsJson.isNull() && !varsJson.isObject()
            && !varsJson.toString().equals("\"{}\""))) {
            logMessageAndHalt(request, 400, "Supply a GraphQL query and optional variables object.");
            return null;
        }
        // The graphiql app sends over this unparseable string while doing an introspection query.  Therefore this code
        // checks for it and sends an empty map in that case.
        Map<String, Object> variables = varsJson == null || varsJson.isNull() || varsJson.toString().equals("\"{}\"")
            ? new HashMap<>()
            : mapper.convertValue(varsJson, Map.class);
        if (checkFeedAccess) {
            Set<String> namespaces;
            try {
                namespaces = OidcApiPermissions.namespaces(queryJson, variables);
            } catch (IllegalArgumentException | InvalidSyntaxException e) {
                logMessageAndHalt(request, 400, "Invalid GTFS GraphQL query or feed namespace.");
                return null;
            }
            Auth0UserProfile user = request.attribute("user");
            if (namespaces.stream().anyMatch(namespace -> !OidcApiPermissions.canReadNamespace(user, namespace))) {
                logMessageAndHalt(request, 403, "User is not authorized for a requested feed.");
            }
        }
        ExecutionInput executionInput = ExecutionInput.newExecutionInput()
                .query(queryJson)
                .variables(variables)
                .build();
        ExecutionResult result = GTFSGraphQL.getGraphQl().execute(executionInput);
        long endTime = System.currentTimeMillis();
        LOG.info("Query took {} msec", endTime - startTime);
        return result.toSpecification();
    }


    /**
     * A Spark Controller that returns the GraphQL schema.
     */
    static Map<String, Object> getSchema(Request req, Response res) {
        return GTFSGraphQL.getGraphQl().execute(IntrospectionQuery.INTROSPECTION_QUERY).toSpecification();
    }


    /**
     * Register Spark HTTP endpoints. API prefix should begin and end with "/", e.g. "/api/".
     */
    public static void initialize (DataSource dataSource, String apiPrefix) {
        initialize(dataSource, apiPrefix, false);
    }

    public static void initialize (DataSource dataSource, String apiPrefix, boolean enforceFeedAccess) {
        LOG.info("Initialized GTFS GraphQL API at localhost:port{}", apiPrefix);
        if (dataSource == null) {
            throw new RuntimeException("Cannot initialize GraphQL endpoints. Data source must not be null.");
        }
        GTFSGraphQL.initialize(dataSource);
        checkFeedAccess = enforceFeedAccess;
        get(apiPrefix + "graphql", GraphQLController::getGraphQL, mapper::writeValueAsString);
        post(apiPrefix + "graphql", GraphQLController::postGraphQL, mapper::writeValueAsString);
        get(apiPrefix + "graphql/schema", GraphQLController::getSchema, mapper::writeValueAsString);
        post(apiPrefix + "graphql/schema", GraphQLController::getSchema, mapper::writeValueAsString);
    }
}
