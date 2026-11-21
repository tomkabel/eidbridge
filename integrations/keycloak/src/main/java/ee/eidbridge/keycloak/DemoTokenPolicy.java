// SPDX-License-Identifier: MIT OR Apache-2.0
package ee.eidbridge.keycloak;

import java.util.Map;

/**
 * Decides whether an ID token must be refused because it comes from the bridge's demo mode.
 *
 * <p>A demo token is recognised by any one of: {@code acr} equal to {@code demo}, {@code eid_env}
 * equal to {@code demo}, or an {@code iss} ending in {@code /demo}. A pure function so that it can
 * be unit tested without Keycloak.
 */
public final class DemoTokenPolicy {

    private DemoTokenPolicy() {}

    /**
     * @param claims ID token claims (may be null)
     * @param issuer the token's {@code iss}; if null, {@code claims.get("iss")} is used
     * @param allowDemo true for demo realms: nothing is rejected
     * @return null when the token is acceptable, otherwise a short reason naming the offending claim
     */
    public static String reject(Map<String, Object> claims, String issuer, boolean allowDemo) {
        if (allowDemo) {
            return null;
        }
        Object acr = claims == null ? null : claims.get("acr");
        if (isDemo(acr)) {
            return "acr is demo";
        }
        Object env = claims == null ? null : claims.get("eid_env");
        if (isDemo(env)) {
            return "eid_env is demo";
        }
        String iss = issuer;
        if (iss == null && claims != null && claims.get("iss") instanceof String s) {
            iss = s;
        }
        if (iss != null && stripTrailingSlashes(iss).endsWith("/demo")) {
            return "issuer ends with /demo";
        }
        return null;
    }

    private static boolean isDemo(Object v) {
        return v instanceof String s && s.trim().equalsIgnoreCase("demo");
    }

    private static String stripTrailingSlashes(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '/') {
            end--;
        }
        return s.substring(0, end);
    }
}
