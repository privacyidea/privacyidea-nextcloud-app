#!/usr/bin/env bash
# Finds released Nextcloud major versions that the psalm OCP matrix in
# php-tests.yml does not cover yet. A version counts as released when the
# Docker image nextcloud:<major> exists. Prints GitHub step outputs:
#
#   versions=<new majors, separated by spaces>
#   newest=<highest new major>
#
# Prints no outputs when there is no new version, when the nextcloud/ocp stubs
# for it are missing, or when a pull request for the newest version exists
# already (open, merged or closed). Messages go to stderr.
# Needs curl, jq and gh (GH_TOKEN, GH_REPO). Used by nextcloud-version-watch.yml.
set -euo pipefail

WORKFLOW=.github/workflows/php-tests.yml

current="$(grep -E '^\s*ocp-branch:' "$WORKFLOW" | grep -oE 'stable[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1 || true)"
if [ -z "$current" ]; then
	echo "No 'ocp-branch: [...stableNN...]' line found in $WORKFLOW." >&2
	exit 1
fi
echo "The psalm matrix covers Nextcloud up to $current." >&2

image_exists()
{
	local code
	code="$(curl -s -o /dev/null -w '%{http_code}' "https://hub.docker.com/v2/repositories/library/nextcloud/tags/$1")"
	case "$code" in
		200) return 0 ;;
		404) return 1 ;;
		*)
			echo "Docker Hub answered HTTP $code for nextcloud:$1." >&2
			exit 1
			;;
	esac
}

stubs="$(curl -sSf https://repo.packagist.org/p2/nextcloud/ocp~dev.json | jq -r '.packages["nextcloud/ocp"][].version')"

versions=()
next=$((current + 1))
while image_exists "$next"; do
	if ! grep -qx "dev-stable$next" <<<"$stubs"; then
		echo "nextcloud:$next exists, but nextcloud/ocp has no dev-stable$next yet." >&2
		break
	fi
	versions+=("$next")
	next=$((next + 1))
done

if [ ${#versions[@]} -eq 0 ]; then
	echo "No new Nextcloud version." >&2
	exit 0
fi

newest="${versions[-1]}"
existing="$(gh pr list --head "ci/nextcloud-$newest" --state all --json url --jq '.[0].url // empty')"
if [ -n "$existing" ]; then
	echo "A pull request for Nextcloud $newest exists already: $existing" >&2
	exit 0
fi

echo "New Nextcloud versions: ${versions[*]}" >&2
echo "versions=${versions[*]}"
echo "newest=$newest"
