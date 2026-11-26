package com.conveyal.datatools.editor.controllers.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import spark.Request;
import spark.Response;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static com.conveyal.datatools.common.utils.SparkUtils.formatJSON;
import static com.conveyal.datatools.manager.DataManager.getConfigPropertyAsText;
import static spark.Spark.post;

/** Routes street edits through a server-configured GraphHopper instance. */
public final class GraphHopperController {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    private static final String MOTORWAY_MODEL =
        "{\"priority\":[{\"if\":\"road_class == MOTORWAY\",\"multiply_by\":0.1}]}";
    private static final int MAX_POINTS = 100;

    private GraphHopperController() {}

    public static void register(String editorApiPrefix) {
        String url = setting("GRAPHHOPPER_URL", "");
        if (url.isBlank()) return;
        String base = url.strip().replaceAll("/+$", "");
        URI routeUri;
        try {
            routeUri = URI.create(base.endsWith("/route") ? base : base + "/route");
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid GRAPHHOPPER_URL.");
        }
        if (routeUri.getHost() == null || routeUri.getUserInfo() != null || routeUri.getQuery() != null
            || routeUri.getFragment() != null || !("https".equals(routeUri.getScheme())
            || "http".equals(routeUri.getScheme()))) {
            throw new IllegalArgumentException("GRAPHHOPPER_URL must be an HTTP(S) base or route URL.");
        }
        String accessId = setting("CF_ACCESS_CLIENT_ID", "");
        String accessSecret = setting("CF_ACCESS_CLIENT_SECRET", "");
        if (accessId.isBlank() != accessSecret.isBlank() || (!accessId.isBlank() && !"https".equals(routeUri.getScheme()))) {
            throw new IllegalArgumentException("GraphHopper Cloudflare Access requires both credentials and HTTPS.");
        }
        String userAgent = setting("GRAPHHOPPER_USER_AGENT", "ColombiaTransit-Datatools");
        post(editorApiPrefix + "secure/graphhopper/route",
            (request, response) -> route(request, response, routeUri, userAgent, accessId, accessSecret));
    }

    private static String setting(String key, String defaultValue) {
        String environmentValue = System.getenv(key);
        return environmentValue == null ? getConfigPropertyAsText(key, defaultValue) : environmentValue;
    }

    private static String route(Request request, Response response, URI routeUri,
                                String userAgent, String accessId, String accessSecret) {
        ObjectNode payload;
        String body = request.body();
        if (body.length() > 16_384) return error(response, 413, "GraphHopper routing request is too large.");
        try {
            payload = routingPayload(MAPPER.readTree(body));
        } catch (JsonProcessingException | IllegalArgumentException e) {
            return error(response, 400, "Supply 2 to 100 valid longitude/latitude pairs and an optional avoidMotorways boolean.");
        }

        HttpRequest.Builder upstream = HttpRequest.newBuilder(routeUri)
            .timeout(Duration.ofSeconds(25))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("User-Agent", userAgent)
            .POST(HttpRequest.BodyPublishers.ofString(payload.toString()));
        if (!accessId.isBlank()) {
            upstream.header("CF-Access-Client-Id", accessId);
            upstream.header("CF-Access-Client-Secret", accessSecret);
        }
        try {
            HttpResponse<String> result = CLIENT.send(upstream.build(), HttpResponse.BodyHandlers.ofString());
            if (result.statusCode() == 400) return error(response, 400, "GraphHopper could not route these points.");
            if (result.statusCode() != 200) {
                return error(response, 502, "Private GraphHopper is unavailable.");
            }
            JsonNode resultJson = MAPPER.readTree(result.body());
            if (resultJson == null || !resultJson.path("paths").isArray()) {
                return error(response, 502, "Private GraphHopper returned an invalid routing response.");
            }
            return result.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return error(response, 502, "Private GraphHopper request was interrupted.");
        } catch (IOException e) {
            return error(response, 502, "Private GraphHopper is unavailable.");
        }
    }

    static ObjectNode routingPayload(JsonNode input) throws JsonProcessingException {
        if (input == null || !input.isObject()) throw new IllegalArgumentException();
        JsonNode points = input.path("points");
        JsonNode avoidMotorways = input.path("avoidMotorways");
        if (!points.isArray() || points.size() < 2 || points.size() > MAX_POINTS
            || (!avoidMotorways.isMissingNode() && !avoidMotorways.isBoolean())) {
            throw new IllegalArgumentException();
        }
        for (JsonNode point : points) {
            if (!point.isArray() || point.size() != 2 || !validCoordinate(point.get(0), 180)
                || !validCoordinate(point.get(1), 90)) {
                throw new IllegalArgumentException();
            }
        }
        ObjectNode payload = MAPPER.createObjectNode()
            .put("profile", "bus")
            .put("locale", "en")
            .put("points_encoded", true)
            .put("instructions", true)
            .put("elevation", false);
        payload.set("points", points);
        if (avoidMotorways.asBoolean()) {
            payload.put("ch.disable", true);
            payload.set("custom_model", MAPPER.readTree(MOTORWAY_MODEL));
        }
        return payload;
    }

    private static boolean validCoordinate(JsonNode value, int limit) {
        return value.isNumber() && Math.abs(value.doubleValue()) <= limit;
    }

    private static String error(Response response, int status, String message) {
        response.status(status);
        return formatJSON(message, status, null);
    }
}
