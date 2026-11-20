<?php
// Configure "OpenID Connect Generic Client" from the bridge discovery document.
$issuer = getenv( 'ISSUER' ) ?: 'http://localhost:18480/demo';
$res    = wp_remote_get( rtrim( $issuer, '/' ) . '/.well-known/openid-configuration' );
if ( is_wp_error( $res ) ) {
	WP_CLI::error( $res->get_error_message() );
}
$d = json_decode( wp_remote_retrieve_body( $res ), true );
if ( ! is_array( $d ) || ( $d['issuer'] ?? '' ) !== $issuer ) {
	WP_CLI::error( 'discovery issuer mismatch: ' . ( $d['issuer'] ?? '(none)' ) );
}
if ( ! in_array( 'S256', $d['code_challenge_methods_supported'] ?? array(), true ) ) {
	WP_CLI::error( 'bridge does not advertise S256' );
}
$settings = array(
	'login_type'               => 'button',
	'client_id'                => 'wordpress',
	'client_secret'            => getenv( 'WP_CLIENT_SECRET' ),
	'scope'                    => 'openid profile',
	'endpoint_login'           => $d['authorization_endpoint'],
	'endpoint_token'           => $d['token_endpoint'],
	'endpoint_userinfo'        => '', // identity comes from the signed ID token only
	'endpoint_jwks'            => $d['jwks_uri'],
	'issuer'                   => $d['issuer'],
	'acr_values'               => '',
	'enable_pkce'              => 1,
	'allow_internal_idp'       => 1, // example only: the demo issuer is http://localhost
	'no_sslverify'             => 0,
	'http_request_timeout'     => 10,
	// The WordPress user is found by the ID token `sub` (stored in user meta
	// openid-connect-generic-subject-identity). identity_key only chooses the
	// user_login of a NEW user; using `sub` avoids name/e-mail based naming.
	'identity_key'             => 'sub',
	'nickname_key'             => 'sub',
	'email_format'             => '{sub}@eid.invalid',
	'displayname_format'       => '',
	'link_existing_users'      => 0,
	'link_unverified_users'    => 0,
	'create_if_does_not_exist' => 1,
	'enforce_privacy'          => 0,
	'redirect_user_back'       => 0,
	'token_refresh_enable'     => 0,
	'enable_logging'           => 1,
	'log_limit'                => 200,
);
update_option( 'openid_connect_generic_settings', $settings );
WP_CLI::success( 'configured for issuer ' . $d['issuer'] );
