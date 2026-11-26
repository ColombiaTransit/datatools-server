package com.conveyal.datatools.editor.controllers.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphHopperControllerTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void usesBusProfileAndOnlyAcceptsSupportedOptions() throws Exception {
        JsonNode input = MAPPER.readTree(
            "{\"profile\":\"car\",\"points\":[[-75.8787,8.7509],[-75.5253,10.4236]],\"custom_model\":{}}");
        JsonNode payload = GraphHopperController.routingPayload(input);
        assertEquals("bus", payload.path("profile").asText());
        assertEquals(input.path("points"), payload.path("points"));
        assertTrue(payload.path("points_encoded").asBoolean());
        assertTrue(payload.path("instructions").asBoolean());
        assertFalse(payload.has("custom_model"));
        assertFalse(payload.has("ch.disable"));
    }

    @Test
    void appliesMotorwayPreferenceWithFlexibleRouting() throws Exception {
        JsonNode input = MAPPER.readTree(
            "{\"points\":[[-75.8787,8.7509],[-75.5253,10.4236]],\"avoidMotorways\":true}");
        JsonNode payload = GraphHopperController.routingPayload(input);
        assertTrue(payload.path("ch.disable").asBoolean());
        assertEquals(0.1, payload.path("custom_model").path("priority").get(0).path("multiply_by").asDouble());
    }

    @Test
    void rejectsInvalidCoordinates() throws Exception {
        JsonNode input = MAPPER.readTree("{\"points\":[[-75.8787,8.7509],[-75.5253,91]]}");
        assertThrows(IllegalArgumentException.class, () -> GraphHopperController.routingPayload(input));
    }
}
