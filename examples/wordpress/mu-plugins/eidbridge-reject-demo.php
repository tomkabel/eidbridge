<?php
/**
 * Plugin Name: eidbridge - reject demo logins in production
 * Description: With EIDBRIDGE_PRODUCTION true, refuses ID tokens issued by an eidbridge demo instance (acr=demo, eid_env=demo, issuer ending in /demo).
 * Version:     1.0.0
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * Must-use plugin (wp-content/mu-plugins/). It hooks the claims of the ID token
 * after "OpenID Connect Generic Client" verified its signature, issuer, audience,
 * expiry and nonce. No eID protocol code lives here.
 */

defined( 'ABSPATH' ) || exit;

function eidbridge_is_demo_claim( $claims ) {
	if ( ! is_array( $claims ) ) {
		return false;
	}
	$iss = isset( $claims['iss'] ) && is_string( $claims['iss'] ) ? rtrim( $claims['iss'], '/' ) : '';
	return ( isset( $claims['acr'] ) && 'demo' === $claims['acr'] )
		|| ( isset( $claims['eid_env'] ) && 'demo' === $claims['eid_env'] )
		|| ( '' !== $iss && '/demo' === substr( $iss, -5 ) );
}

function eidbridge_reject_demo_claim( $claims ) {
	if ( defined( 'EIDBRIDGE_PRODUCTION' ) && EIDBRIDGE_PRODUCTION && eidbridge_is_demo_claim( $claims ) ) {
		return new WP_Error( 'eidbridge-demo-token', 'Demo-mode eID logins are refused on a production site.', array( 'acr' => $claims['acr'] ?? null ) );
	}
	return $claims;
}
// Runs for the authorization-code callback and for refresh-token handling.
add_filter( 'openid-connect-modify-id-token-claim-before-validation', 'eidbridge_reject_demo_claim', 10, 1 );

// Defence in depth: the same test on the user claim (userinfo or ID token).
add_filter(
	'openid-connect-generic-user-login-test',
	function ( $allowed, $user_claim ) {
		if ( defined( 'EIDBRIDGE_PRODUCTION' ) && EIDBRIDGE_PRODUCTION && eidbridge_is_demo_claim( $user_claim ) ) {
			return false;
		}
		return $allowed;
	},
	10,
	2
);
