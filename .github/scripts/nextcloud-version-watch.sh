#!/usr/bin/env bash
# Helper of nextcloud-version-watch.yml.
#
#   nextcloud-version-watch.sh detect
#     Finds the lowest Nextcloud major version N that is released (the Docker
#     image nextcloud:N exists), that has OCP stubs (nextcloud/ocp dev-stableN),
#     that the psalm OCP matrix in php-tests.yml does not cover, and that has no
#     issue yet (open or closed). Writes version=N to GITHUB_OUTPUT, or prints it
#     when GITHUB_OUTPUT is not set. Writes nothing when there is no such version.
#
#   nextcloud-version-watch.sh report
#     Opens the issue for VERSION with PSALM_RESULT, E2E_RESULT and RUN_URL.
#     DRY_RUN=1 prints the issue instead.
#
# Needs curl, jq and gh (GH_TOKEN, GH_REPO).
set -euo pipefail

WORKFLOW=.github/workflows/php-tests.yml

issue_title() { echo "Nextcloud $1 is released: test the app and declare support"; }

output()
{
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		echo "$1" >>"$GITHUB_OUTPUT"
	else
		echo "$1"
	fi
}

warn()
{
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		echo "::warning title=Nextcloud version watch::$*"
	else
		echo "WARNING: $*" >&2
	fi
}

detect()
{
	local current stubs titles next code title
	current="$(grep -oE "['\"]stable[0-9]+['\"]" "$WORKFLOW" | grep -oE '[0-9]+' | sort -n | tail -1 || true)"
	if [ -z "$current" ]; then
		echo "No 'stableNN' matrix entry found in $WORKFLOW." >&2
		exit 1
	fi
	echo "The psalm matrix covers Nextcloud up to $current."

	# A failed lookup is no reason for a red nightly run: the next night tries again.
	if ! stubs="$(curl -sSf --retry 3 --retry-delay 5 https://repo.packagist.org/p2/nextcloud/ocp~dev.json \
		| jq -r '.packages["nextcloud/ocp"][].version')"; then
		warn "Packagist did not answer. No check tonight."
		exit 0
	fi
	titles="$(gh issue list --state all --limit 1000 --json title --jq '.[].title')"

	next=$((current + 1))
	while true; do
		code="$(curl -s -o /dev/null -w '%{http_code}' --retry 3 --retry-delay 5 \
			"https://hub.docker.com/v2/repositories/library/nextcloud/tags/$next")"
		case "$code" in
			200) ;;
			404)
				echo "No new Nextcloud version without an issue."
				exit 0
				;;
			*)
				warn "Docker Hub answered HTTP $code for nextcloud:$next. No check tonight."
				exit 0
				;;
		esac
		if ! grep -qx "dev-stable$next" <<<"$stubs"; then
			echo "nextcloud:$next exists, but nextcloud/ocp has no dev-stable$next yet."
			exit 0
		fi
		title="$(issue_title "$next")"
		if grep -qxF "$title" <<<"$titles"; then
			echo "Nextcloud $next: the issue exists already."
		else
			echo "Nextcloud $next is new."
			output "version=$next"
			exit 0
		fi
		next=$((next + 1))
	done
}

describe_result()
{
	case "$1" in
		success) echo "passed" ;;
		failure) echo "FAILED" ;;
		*) echo "did not finish (result: $1)" ;;
	esac
}

report()
{
	local title body
	title="$(issue_title "$VERSION")"
	body="$(cat <<EOF
The nightly version watch found that Nextcloud $VERSION is released: the Docker image \`nextcloud:$VERSION\` exists, and \`nextcloud/ocp\` has the stubs \`dev-stable$VERSION\`. The psalm OCP matrix in \`$WORKFLOW\` does not cover this version yet.

## Results

- Psalm against \`nextcloud/ocp:dev-stable$VERSION\`: $(describe_result "$PSALM_RESULT")
- E2E smoke test against \`nextcloud:$VERSION\`: $(describe_result "$E2E_RESULT")

Logs: $RUN_URL

## To do

- [ ] Add \`'stable$VERSION'\` to the \`ocp-branch\` matrix in \`$WORKFLOW\`.
- [ ] If a check failed, fix the app.
- [ ] Raise \`max-version\` in \`appinfo/info.xml\` to $VERSION. That change needs a minor release.

The watch opens one issue for each version. After you close this issue, the watch does not open it again.
EOF
)"
	if [ "${DRY_RUN:-}" = 1 ]; then
		printf 'Title: %s\n\n%s\n' "$title" "$body"
		return
	fi
	gh issue create --title "$title" --body "$body"
}

case "${1:-}" in
	detect) detect ;;
	report) report ;;
	*)
		echo "usage: $0 detect|report" >&2
		exit 2
		;;
esac
