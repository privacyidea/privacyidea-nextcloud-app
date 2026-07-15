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
