#!/usr/bin/env bash
# End-to-end smoke test of the app against one Nextcloud version.
#
#   tests/e2e/run.sh [nextcloud-image-tag]        (default: latest)
#
# Starts a throwaway Nextcloud container, installs the app from the working
# tree, points it at mock_privacyidea.py and runs smoke.mjs in headless Chrome.
# Then it checks the Nextcloud log for errors from the app.
#
# Needs docker, git, curl, python3, node 22+ and Chrome or Chromium (CHROME_BIN).
# E2E_PORT (default 8099) and E2E_MOCK_PORT (default 5099) change the ports.
# E2E_MOCK_BIND sets the address that the mock listens on. E2E_APP_DIR tests the
# app from another checkout. E2E_KEEP=1 keeps the Nextcloud container after the
# run, for debugging.
set -euo pipefail

TAG="${1:-latest}"
PORT="${E2E_PORT:-8099}"
MOCK_PORT="${E2E_MOCK_PORT:-5099}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
APP_DIR="${E2E_APP_DIR:-$REPO_ROOT}"
CONTAINER="pi-e2e-nextcloud-$(printf '%s' "$TAG" | tr -c 'a-zA-Z0-9.' '-')"
NC_URL="http://localhost:$PORT"
PI_URL="http://host.docker.internal:$MOCK_PORT"
WORK="$(mktemp -d)"
MOCK_PID=""
MOCK_BIND=""

section() { printf '\n== %s\n' "$*"; }
fail()
{
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		echo "::error title=E2E smoke test::$*"
	else
		echo "ERROR: $*" >&2
	fi
	exit 1
}
occ() { docker exec -u www-data "$CONTAINER" php occ "$@"; }

cleanup()
{
	local status=$?
	if [ "$status" -ne 0 ] && docker inspect "$CONTAINER" >/dev/null 2>&1; then
		section "Nextcloud log, last 40 entries"
		docker exec "$CONTAINER" tail -n 40 /var/www/html/data/nextcloud.log 2>/dev/null \
			| python3 -I "$REPO_ROOT/dev/nclog.py" \
			|| docker logs --tail 40 "$CONTAINER" 2>&1
		section "Mock privacyIDEA log"
		cat "$WORK/mock.log" 2>/dev/null || true
	fi
	if [ -n "$MOCK_PID" ]; then
		kill "$MOCK_PID" 2>/dev/null || true
	fi
	if [ "${E2E_KEEP:-}" = 1 ]; then
		echo "Kept the container $CONTAINER ($NC_URL, admin/admin)."
	else
		docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
	exit "$status"
}
trap cleanup EXIT

section "Starting nextcloud:$TAG on $NC_URL"
docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
docker pull -q "nextcloud:$TAG" >/dev/null
docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:80" \
	-e SQLITE_DATABASE=nextcloud \
	-e NEXTCLOUD_ADMIN_USER=admin -e NEXTCLOUD_ADMIN_PASSWORD=admin \
	-e NEXTCLOUD_TRUSTED_DOMAINS=localhost \
	--add-host host.docker.internal:host-gateway \
	"nextcloud:$TAG" >/dev/null

# The image installs Nextcloud before it starts Apache, so status.php answers
# only after the installation.
installed=false
for _ in $(seq 1 120); do
	if curl -sf "$NC_URL/status.php" | grep -q '"installed":true'; then
		installed=true
		break
	fi
	if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != true ]; then
		fail "the Nextcloud container stopped during the installation"
	fi
	sleep 5
done
[ "$installed" = true ] || fail "Nextcloud did not finish the installation in 10 minutes"
NC_VERSION="$(occ status --output=json | python3 -c 'import json, sys; print(json.load(sys.stdin)["versionstring"])')"
PHP_VERSION="$(docker exec "$CONTAINER" php -r 'echo PHP_VERSION;')"
echo "Nextcloud $NC_VERSION, PHP $PHP_VERSION"

section "Starting the mock privacyIDEA on port $MOCK_PORT"
start_mock()
{
	MOCK_BIND="$1"
	python3 -I "$HERE/mock_privacyidea.py" "$MOCK_BIND" "$MOCK_PORT" >"$WORK/mock.log" 2>&1 &
	MOCK_PID=$!
}
# host.docker.internal maps to the gateway of the default bridge network. Listen
# only there, so that other hosts cannot reach the mock.
GATEWAY="$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || true)"
start_mock "${E2E_MOCK_BIND:-${GATEWAY:-0.0.0.0}}"
reachable=false
for _ in $(seq 1 20); do
	if docker exec "$CONTAINER" curl -sf -m 2 -X POST -d 'user=e2e&pass=none' "$PI_URL/validate/check" >/dev/null; then
		reachable=true
		break
	fi
	# If the address is not an address of this host (for example the gateway
	# with Docker Desktop), the mock cannot listen on it and exits.
	if ! kill -0 "$MOCK_PID" 2>/dev/null && [ "$MOCK_BIND" != 0.0.0.0 ]; then
		echo "The mock cannot listen on $MOCK_BIND. It listens on all addresses (0.0.0.0) instead."
		start_mock 0.0.0.0
	fi
	sleep 0.5
done
[ "$reachable" = true ] || fail "the Nextcloud container cannot reach the mock privacyIDEA at $PI_URL"

section "Installing the app from $APP_DIR"
docker exec "$CONTAINER" mkdir -p /var/www/html/custom_apps/privacyidea
# Tracked and new files of the working tree, without ignored and local-only files.
git -C "$APP_DIR" ls-files -z --cached --others --exclude-standard \
	| tar -C "$APP_DIR" --null --ignore-failed-read -T - -cf - \
	| docker exec -i "$CONTAINER" tar -xf - -C /var/www/html/custom_apps/privacyidea
docker exec "$CONTAINER" chown -R www-data:www-data /var/www/html/custom_apps/privacyidea
# Set the configuration before the app is enabled, so that the wait below also
# covers these values.
occ config:system:set auth.bruteforce.protection.enabled --value false --type boolean >/dev/null
occ config:app:set privacyidea piActivatePI --value 1 >/dev/null
occ config:app:set privacyidea piURL --value "$PI_URL" >/dev/null
# The post-installation hook of the dev stack: it enables the app with --force
# (the test also runs above max-version), sets the debug log level and turns
# off the rate limiter.
docker exec -i -u www-data "$CONTAINER" sh <"$REPO_ROOT/dev/enable-app.sh"
# Nextcloud caches the app configuration of the web server in APCu (3 seconds
# in Nextcloud 35, AppConfig::LOCAL_CACHE_TTL), and occ cannot clear that cache.
# Until the web server sees the enabled app, the app routes answer 404 and a
# login skips the privacyIDEA provider.
enabled=false
for _ in $(seq 1 60); do
	if [ "$(curl -s -o /dev/null -w '%{http_code}' "$NC_URL/index.php/apps/privacyidea/getValue")" != 404 ]; then
		enabled=true
		break
	fi
	sleep 0.5
done
[ "$enabled" = true ] || fail "the web server does not see the enabled app after 30 seconds"

section "Browser smoke test"
node "$HERE/smoke.mjs" "$NC_URL" "$PI_URL"
realm="$(occ config:app:get privacyidea piRealm || true)"
[ "$realm" = e2e-realm ] || fail "the settings page did not store piRealm (stored value: '$realm')"
echo "ok   the changed value is stored in the app configuration"

section "Nextcloud log"
docker exec "$CONTAINER" cat /var/www/html/data/nextcloud.log | python3 -I "$HERE/check_log.py"

section "Passed against Nextcloud $NC_VERSION (PHP $PHP_VERSION)"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	echo "E2E smoke test passed against Nextcloud $NC_VERSION (PHP $PHP_VERSION)." >>"$GITHUB_STEP_SUMMARY"
fi
