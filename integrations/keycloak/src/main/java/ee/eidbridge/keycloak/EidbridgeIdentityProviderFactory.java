// SPDX-License-Identifier: MIT OR Apache-2.0
package ee.eidbridge.keycloak;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.util.JsonSerialization;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/** Registers the {@code eidbridge} identity provider type. */
public class EidbridgeIdentityProviderFactory extends OIDCIdentityProviderFactory {

    public static final String PROVIDER_ID = "eidbridge";
    public static final String ALLOW_DEMO = "allowDemo";

    private static final Logger LOG = Logger.getLogger(EidbridgeIdentityProviderFactory.class);
    private static final long DISCOVERY_TTL_MS = 10 * 60 * 1000L;

    private record Discovery(Map<String, String> endpoints, long at) {}

    private static final Map<String, Discovery> DISCOVERY_CACHE = new ConcurrentHashMap<>();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "eidbridge";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                new ProviderConfigProperty("issuer", "Issuer",
                        "The bridge issuer URL. Endpoints are discovered from <issuer>/.well-known/openid-configuration.",
                        ProviderConfigProperty.STRING_TYPE, null),
                new ProviderConfigProperty(ALLOW_DEMO, "Allow demo tokens",
                        "Accept ID tokens from the bridge's demo mode (acr=demo, eid_env=demo, issuer ending in /demo). Off by default; enable only in demo realms.",
                        ProviderConfigProperty.BOOLEAN_TYPE, "false"));
    }

    @Override
    public OIDCIdentityProviderConfig createConfig() {
        return new OIDCIdentityProviderConfig();
    }

    @Override
    public EidbridgeIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        IdentityProviderModel effective = new IdentityProviderModel(model);
        // The copy constructor may share the map; always work on our own.
        Map<String, String> cfg = new java.util.HashMap<>(model.getConfig());
        applyDefaults(cfg);
        discover(session, cfg);
        effective.setConfig(cfg);
        return new EidbridgeIdentityProvider(session, new OIDCIdentityProviderConfig(effective));
    }

    /** Settings the bridge requires are forced; the rest are defaults an operator may override. */
    static void applyDefaults(Map<String, String> cfg) {
        cfg.put("pkceEnabled", "true");
        cfg.put("pkceMethod", "S256");
        cfg.put("validateSignature", "true");
        cfg.put("useJwksUrl", "true");
        cfg.putIfAbsent("syncMode", "IMPORT");
        cfg.putIfAbsent("clientAuthMethod", "client_secret_basic");
        cfg.putIfAbsent("defaultScope", "openid profile");
        cfg.putIfAbsent("backchannelSupported", "false");
        cfg.putIfAbsent(ALLOW_DEMO, "false");
    }

    /** Fills missing endpoints from OIDC discovery of the configured issuer (cached for 10 minutes). */
    private static void discover(KeycloakSession session, Map<String, String> cfg) {
        String issuer = cfg.get("issuer");
        if (issuer == null || issuer.isBlank()) {
            return;
        }
        if (notBlank(cfg.get("authorizationUrl")) && notBlank(cfg.get("tokenUrl")) && notBlank(cfg.get("jwksUrl"))) {
            return;
        }
        Discovery d = DISCOVERY_CACHE.get(issuer);
        if (d == null || System.currentTimeMillis() - d.at() > DISCOVERY_TTL_MS) {
            try {
                String url = issuer.replaceAll("/+$", "") + "/.well-known/openid-configuration";
                JsonNode doc = fetchJson(session, url);
                Map<String, String> found = new java.util.HashMap<>();
                put(found, "authorizationUrl", doc, "authorization_endpoint");
                put(found, "tokenUrl", doc, "token_endpoint");
                put(found, "userInfoUrl", doc, "userinfo_endpoint");
                put(found, "jwksUrl", doc, "jwks_uri");
                put(found, "logoutUrl", doc, "end_session_endpoint");
                d = new Discovery(found, System.currentTimeMillis());
                DISCOVERY_CACHE.put(issuer, d);
            } catch (Exception e) {
                LOG.warnf("eidbridge discovery for %s failed: %s", issuer, e.toString());
                if (d == null) {
                    return;
                }
            }
        }
        d.endpoints().forEach((k, v) -> {
            if (!notBlank(cfg.get(k))) {
                cfg.put(k, v);
            }
        });
    }

    /** GET a JSON document with Keycloak's own HTTP client (honours its proxy and truststore settings). */
    private static JsonNode fetchJson(KeycloakSession session, String url) throws java.io.IOException {
        HttpGet get = new HttpGet(url);
        get.setHeader("Accept", "application/json");
        HttpResponse resp = session.getProvider(HttpClientProvider.class).getHttpClient().execute(get);
        HttpEntity entity = resp.getEntity();
        try {
            int status = resp.getStatusLine().getStatusCode();
            if (status != 200 || entity == null) {
                throw new java.io.IOException("HTTP " + status);
            }
            try (java.io.InputStream in = entity.getContent()) {
                return JsonSerialization.readValue(in, JsonNode.class);
            }
        } finally {
            org.apache.http.util.EntityUtils.consumeQuietly(entity);
        }
    }

    private static void put(Map<String, String> out, String key, JsonNode doc, String field) {
        JsonNode n = doc.get(field);
        if (n != null && n.isTextual() && !n.asText().isEmpty()) {
            out.put(key, n.asText());
        }
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
