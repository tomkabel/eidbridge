// SPDX-License-Identifier: MIT OR Apache-2.0
package ee.eidbridge.keycloak;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;

/**
 * OpenID Connect identity provider for the eidbridge bridge. Behaves like the generic OIDC provider
 * (the brokered user id is the ID token {@code sub}; the authorization request carries state, nonce
 * and, with the factory defaults, a PKCE S256 challenge) and adds two things: demo tokens are
 * refused unless {@code allowDemo} is set, and the eID claims are copied to user attributes.
 */
public class EidbridgeIdentityProvider extends OIDCIdentityProvider {

    /** Brokered user attributes set from the ID token (claim name -> attribute name). */
    static final Map<String, String> ATTRIBUTES =
            Map.of("eid_method", "eid_method", "acr", "eid_acr", "country", "eid_country");

    private final boolean allowDemo;

    public EidbridgeIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
        this.allowDemo = Boolean.parseBoolean(config.getConfig().get(EidbridgeIdentityProviderFactory.ALLOW_DEMO));
    }

    /** Runs after signature, issuer, audience and expiry validation and before any user exists. */
    @Override
    protected JsonWebToken validateToken(String encodedToken, boolean ignoreAudience) {
        JsonWebToken token = super.validateToken(encodedToken, ignoreAudience);
        Map<String, Object> claims = new HashMap<>();
        if (token.getOtherClaims() != null) {
            claims.putAll(token.getOtherClaims());
        }
        if (token instanceof IDToken id && id.getAcr() != null) {
            claims.put("acr", id.getAcr());
        }
        String reason = DemoTokenPolicy.reject(claims, token.getIssuer(), allowDemo);
        if (reason != null) {
            throw new IdentityBrokerException(
                    "eidbridge demo ID token refused (" + reason + "); set allowDemo=true on this identity provider only in a demo realm");
        }
        return token;
    }

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken)
            throws IOException {
        BrokeredIdentityContext identity = super.extractIdentity(tokenResponse, accessToken, idToken);
        Map<String, Object> claims = new HashMap<>();
        if (idToken.getOtherClaims() != null) {
            claims.putAll(idToken.getOtherClaims());
        }
        if (idToken instanceof IDToken id && id.getAcr() != null) {
            claims.put("acr", id.getAcr());
        }
        ATTRIBUTES.forEach((claim, attribute) -> {
            if (claims.get(claim) instanceof String value && !value.isEmpty()) {
                identity.setUserAttribute(attribute, value);
            }
        });
        return identity;
    }
}
