#!/bin/sh
# Nextcloud post-installation hook (run once by the container entrypoint right
# after the automatic install). Enables the bind-mounted privacyIDEA app.
#
# --force is used so the app enables even on a Nextcloud newer than the
# max-version declared in appinfo/info.xml, which is what lets this stack test
# the app against the latest Nextcloud release.
set -eu

echo "post-installation hook: enabling the privacyidea app"
php /var/www/html/occ app:enable --force privacyidea

# Dev conveniences (dev stack only): verbose logging so the plugin's debug
# lines show, and no request rate limiter so repeated login/OTP testing doesn't
# trip "too many requests".
php /var/www/html/occ config:system:set loglevel --value 0 --type integer
php /var/www/html/occ config:system:set ratelimit.protection.enabled --value false --type boolean
