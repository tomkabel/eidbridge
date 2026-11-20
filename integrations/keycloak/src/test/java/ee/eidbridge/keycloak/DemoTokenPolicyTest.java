// SPDX-License-Identifier: MIT OR Apache-2.0
package ee.eidbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class DemoTokenPolicyTest {

    private static final String PROD = "https://id.example.com";

    private static Map<String, Object> claims(Object... kv) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    @Test
    void productionTokenAccepted() {
        assertNull(DemoTokenPolicy.reject(claims("acr", "http://eidas.europa.eu/LoA/high", "eid_method", "smartid"), PROD, false));
    }

    @Test
    void emptyAndNullClaimsAccepted() {
        assertNull(DemoTokenPolicy.reject(null, PROD, false));
        assertNull(DemoTokenPolicy.reject(Map.of(), null, false));
    }

    @Test
    void acrDemoRejected() {
        assertEquals("acr is demo", DemoTokenPolicy.reject(claims("acr", "demo"), PROD, false));
    }

    @Test
    void eidEnvDemoRejected() {
        assertEquals("eid_env is demo", DemoTokenPolicy.reject(claims("eid_env", "demo"), PROD, false));
    }

    @Test
    void issuerSuffixDemoRejected() {
        assertNotNull(DemoTokenPolicy.reject(claims(), "http://localhost:18080/demo", false));
        assertNotNull(DemoTokenPolicy.reject(claims(), "https://id.example.com/demo/", false));
        assertNotNull(DemoTokenPolicy.reject(claims("iss", "https://id.example.com/demo"), null, false));
    }

    @Test
    void caseInsensitiveDemoValues() {
        assertNotNull(DemoTokenPolicy.reject(claims("acr", "DEMO"), PROD, false));
        assertNotNull(DemoTokenPolicy.reject(claims("eid_env", " Demo "), PROD, false));
    }

    @Test
    void similarButNotDemoAccepted() {
        assertNull(DemoTokenPolicy.reject(claims("acr", "demonstration", "eid_env", "prod"), "https://id.example.com/demos", false));
        assertNull(DemoTokenPolicy.reject(claims(), "https://demo.example.com", false));
        assertNull(DemoTokenPolicy.reject(claims("acr", 5, "eid_env", true), PROD, false));
    }

    @Test
    void allowDemoAcceptsEverything() {
        assertNull(DemoTokenPolicy.reject(claims("acr", "demo", "eid_env", "demo"), "http://localhost:18080/demo", true));
    }
}
