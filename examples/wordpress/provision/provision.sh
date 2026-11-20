#!/bin/sh
# One-shot provisioning with WP-CLI (runs as uid 33 in the wordpress:cli image).
set -eu
URL=http://localhost:18481
ISSUER=http://localhost:18480/demo

echo "waiting for MariaDB and wp-config.php"
i=0
until [ -f wp-config.php ] && wp db query 'SELECT 1' >/dev/null 2>&1; do
  i=$((i+1)); [ "$i" -gt 90 ] && { echo "database/wp-config not ready" >&2; exit 1; }
  sleep 2
done
echo "waiting for the bridge discovery document"
i=0
until wget -qO /dev/null "$ISSUER/.well-known/openid-configuration"; do
  i=$((i+1)); [ "$i" -gt 60 ] && { echo "bridge not ready" >&2; exit 1; }
  sleep 1
done

if ! wp core is-installed 2>/dev/null; then
  wp core install --url="$URL" --title="eidbridge WordPress example" \
    --admin_user=admin --admin_password="admin-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    --admin_email=admin@example.invalid --skip-email
fi

if ! wp plugin is-installed daggerhart-openid-connect-generic; then
  wp plugin install "$PLUGIN_ZIP"
fi
wp plugin activate daggerhart-openid-connect-generic

# Production guard: reject demo-mode logins (see mu-plugins/eidbridge-reject-demo.php).
mkdir -p wp-content/mu-plugins
cp /mu-plugins-src/eidbridge-reject-demo.php wp-content/mu-plugins/eidbridge-reject-demo.php

# Plugin settings from the bridge's discovery document.
wp eval-file /provision/configure.php

# Demo issuers must not log in when this is true. Start in demo mode.
wp config set EIDBRIDGE_PRODUCTION false --raw
wp option get openid_connect_generic_settings --format=json | sed 's/"client_secret":"[^"]*"/"client_secret":"<redacted>"/'
echo "provisioned"
