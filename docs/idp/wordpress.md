# WordPress: log in through eidbridge

Configuration only. WordPress uses an existing, maintained OpenID Connect client plugin; there is no eID protocol code in WordPress and no custom login plugin. A user clicks "Login with OpenID Connect" on `wp-login.php`, logs in with their eID at the bridge, and returns to WordPress as a user mapped by the ID token `sub`.

e2e: PASSED on 2026-11-20 (`examples/wordpress/run-e2e.sh`, see "Run the example").

## Plugin choice

**OpenID Connect Generic Client** by daggerhart, wordpress.org slug `daggerhart-openid-connect-generic`, license GPL-2.0+.

| Item | Value tested on 2026-11-20 |
|---|---|
| Plugin version | 3.11.5 (header "Requires at least 5.0", "Requires PHP 8.0", "Tested up to 7.1.5") |
| Zip | `https://downloads.wordpress.org/plugin/daggerhart-openid-connect-generic.3.11.5.zip` |
| Zip sha256 | `81a2940e4b7bf85f08310d23bb1671b703bb023f44ae17afeb780ecdc77452dd` |
| WordPress image | `wordpress:7.1.5-php8.4-apache@sha256:9ad529b57c01fd71f161f331f638b83ef50ac7f095095d52bb222b7bc3b4d10b` |
| WP-CLI image | `wordpress:cli-2.12.0-php8.4@sha256:10719513e86fe417166a315cc9421bd9cfedaaaef728ea25af1e20f3d9a09c68` |
| MariaDB image | `mariadb:11.4.13@sha256:a8992b5e5404d11e03c54a31d0c1bdea3fd116d283aa6d1a627551f29045309b` |

Why this plugin: it is what the bridge needs from a relying party, read from the 3.11.5 source:

* PKCE `S256`: setting `enable_pkce` (default on) sends `code_challenge` and `code_challenge_method=S256` and the verifier with the token request.
* `nonce` and `state` on every authorization request; the ID token nonce is compared with the one stored for the state.
* The redirect URI is fixed by the plugin (`https://SITE/wp-admin/admin-ajax.php?action=openid-connect-authorize`, or `https://SITE/openid-connect-authorize` with "alternate redirect URI") and sent exactly.
* ID token signature check against the JWKS (`endpoint_jwks`), plus `iss`, `aud` and `exp` checks. RS256 is what the bridge signs with.
* The WordPress user is found by the ID token `sub`, stored in user meta `openid-connect-generic-subject-identity`.
* Existing users are linked only if you turn on `link_existing_users`; leave it off.

Because all of this is present, the example does not ship its own plugin.

Limits of the plugin, found by reading it and by the e2e run:

* It does not check the RFC 9207 `iss` response parameter that the bridge adds to the callback. The `iss` claim of the signed ID token is checked instead, against the configured issuer.
* It authenticates at the token endpoint with `client_secret_post` only (the secret goes in the form body). Register the client with `"token_endpoint_auth_method": "client_secret_post"`; `client_secret_basic` fails with `invalid_client`.
* It accepts an ID token without a nonce claim. The bridge always includes the nonce, so this does not matter for eidbridge.
* It knows nothing about demo mode. Use the guard below.

## 1. Register WordPress at the bridge

Add a client to the bridge's clients file (`EIDBRIDGE_CLIENTS_FILE`, mode 0600, readable by the bridge user):

```json
[{"client_id": "wordpress",
  "client_secret": "<40+ random characters>",
  "token_endpoint_auth_method": "client_secret_post",
  "redirect_uris": ["https://SITE/wp-admin/admin-ajax.php?action=openid-connect-authorize"],
  "sub_mode": "pairwise"}]
```

The bridge compares the redirect URI exactly, including the query string. With the default `pairwise` mode the `sub` differs per client, so one person has one WordPress user per site that uses a given client.

## 2. Install and configure the plugin

Install version 3.11.5 from the zip above (check the sha256 first) or from the Plugins screen; WP-CLI: `wp plugin install ./daggerhart-openid-connect-generic.3.11.5.zip --activate`. Then Settings, OpenID Connect Client, with values from `<issuer>/.well-known/openid-configuration` (`<issuer>` is the bridge's issuer URL, for production `EIDBRIDGE_ISSUER` without a path):

| Setting | Value |
|---|---|
| Client ID / Client Secret | the client from step 1 (better: `define('OIDC_CLIENT_ID', ...)` and `define('OIDC_CLIENT_SECRET', ...)` in `wp-config.php`) |
| Scope | `openid profile` (the scopes the bridge accepts) |
| Login Endpoint URL | `authorization_endpoint` |
| Token Validation Endpoint URL | `token_endpoint` |
| JWKS Endpoint URL | `jwks_uri` |
| Userinfo Endpoint URL | empty: identity comes from the signed ID token |
| Issuer | `issuer`, exactly as in discovery |
| Enable PKCE (S256) | on (mandatory) |
| Identity Key | `sub` |
| Nickname Key | `sub` |
| Email Formatting | `{sub}@eid.invalid`: the bridge sends no e-mail, and `{email}` would fail user creation |
| Link Existing Users / Link unverified | off |
| Create user if does not exist | on |
| Allow internal IdP | off, except when the bridge is on localhost or a private address (the example turns it on) |

"Identity Key" only chooses the `user_login` of a newly created user. The mapping from login to WordPress user is always the ID token `sub` in user meta, never the e-mail address or a name. Do not enable linking by name or e-mail: the bridge asserts no e-mail and names are not unique.

The example sets these through `wp eval-file examples/wordpress/provision/configure.php`, which reads the discovery document and refuses to continue if `S256` is not advertised.

## 3. Reject demo logins in production

Demo-mode ID tokens carry `acr=demo` and `eid_env=demo`, and come from an issuer ending in `/demo`. A production site must never accept them.

1. Configure the production issuer only. The plugin compares the token `iss` with the configured Issuer, so a demo token (`.../demo`) fails.
2. Define the constant `EIDBRIDGE_PRODUCTION` as `true` in `wp-config.php` and install the must-use plugin `examples/wordpress/mu-plugins/eidbridge-reject-demo.php` into `wp-content/mu-plugins/`. It runs after the plugin has verified the token and refuses claims with `acr=demo`, `eid_env=demo` or an issuer ending in `/demo`.

Tested on 2026-11-20 with the demo bridge: with `EIDBRIDGE_PRODUCTION=true` the login ends on `wp-login.php?login-error=eidbridge-demo-token` ("Demo-mode eID logins are refused on a production site."), `profile.php` redirects to the login page and no user is created. Switched back to `false`, the same user logs in again.

## Run the example

Needs docker (with compose), curl, python3 and ports 18480 to 18482 on localhost.

```sh
cd examples/wordpress
./run-e2e.sh
# behind a TLS-intercepting proxy: EXTRA_CA_FILE=$HOME/.ccr/ca-bundle.crt ./run-e2e.sh
```

The script downloads the plugin zip into `examples/wordpress/.cache/` and verifies the sha256 above, builds the bridge from this repository, starts MariaDB, WordPress and the bridge (all with host networking: bridge `127.0.0.1:18480`, WordPress `http://localhost:18481`, MariaDB `18482`), provisions WordPress with WP-CLI, runs `e2e.py` and removes everything.

`e2e.py` (standard library only) drives the browser path: the WordPress login page link (asserts PKCE S256, nonce, state, exact redirect URI), the bridge login page, the QR flow that the fixture upstream (`EIDBRIDGE_SMARTID_ENV=mock`) approves, and the WordPress callback. It then checks `wp-admin/profile.php` (200 for the user, 302 for an anonymous client), reads the stored `sub` with WP-CLI, logs in again in a fresh browser (same WordPress user), and runs the production-guard check above.

The example is for demo mode only: `http://localhost` issuer, fixture upstream, `allow_internal_idp`, a throw-away database password and a random client secret per run. For a real site use an https issuer and the steps above.
