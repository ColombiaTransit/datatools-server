package com.conveyal.datatools.manager.auth.oidc;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcApiPermissionsTest {
    @Test
    void collectsNamespacesFromVariablesAliasesAndNestedFragments() {
        String query = "query($ns: String) { selected: feed(namespace: $ns) { ...locations } }"
            + " fragment locations on feed { location_groups(namespace: \"other\") { location_group_id } }";
        assertEquals(Set.of("selected", "other"), OidcApiPermissions.namespaces(query, Map.of("ns", "selected")));
    }

    @Test
    void resolvesDefaultNamespaceAndHonorsExplicitOverrides() {
        String query = "query($ns: String = \"default\") { feed(namespace: $ns) { namespace } }";
        assertEquals(Set.of("default"), OidcApiPermissions.namespaces(query, Map.of()));
        assertEquals(Set.of("override"), OidcApiPermissions.namespaces(query, Map.of("ns", "override")));
    }

    @Test
    void rejectsMissingNamespacesAndAmbiguousOperations() {
        assertThrows(IllegalArgumentException.class,
            () -> OidcApiPermissions.namespaces("{ feed { namespace } }", Map.of()));
        assertThrows(IllegalArgumentException.class,
            () -> OidcApiPermissions.namespaces("query($ns: String) { feed(namespace: $ns) { namespace } }", Map.of()));
        assertThrows(IllegalArgumentException.class, () -> OidcApiPermissions.namespaces(
            "query One { __typename } query Two { __typename }", Map.of()));
    }

    @Test
    void requiresAnExactOriginForWritesAndLegacyGetActions() {
        URI origin = URI.create("https://data.example");
        assertTrue(OidcController.requiresSameOrigin("POST", "/api/editor/secure/graphhopper/route"));
        assertTrue(OidcController.requiresSameOrigin("GET", "/api/editor/secure/snapshot/123/downloadtoken"));
        assertFalse(OidcController.requiresSameOrigin("GET", "/api/manager/secure/project"));
        assertTrue(OidcController.matchesOrigin(origin, "https://data.example", null));
        assertTrue(OidcController.matchesOrigin(origin, null, "https://data.example:443/project/23"));
        assertFalse(OidcController.matchesOrigin(origin, "null", "https://data.example/project/23"));
        assertFalse(OidcController.matchesOrigin(origin, null, "https://data.example.other.test/project/23"));
        assertFalse(OidcController.matchesOrigin(origin, null, null));
    }
}
