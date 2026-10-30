#!/usr/bin/env bash
# Adds new Nextcloud versions to the psalm OCP matrix in php-tests.yml, pushes
# the change to the branch ci/nextcloud-<newest> and opens a pull request that
# reports the E2E result. Then it starts php-tests.yml on that branch, because
# a pull request that GitHub Actions opens does not start pull_request
# workflows by itself. Used by nextcloud-version-watch.yml.
#
# Environment: VERSIONS, NEWEST, E2E_RESULT, RUN_URL, GH_TOKEN, GH_REPO.
# DRY_RUN=1 changes php-tests.yml and prints the pull request text, but does
# not commit, push or open anything.
set -euo pipefail

WORKFLOW=.github/workflows/php-tests.yml
branch="ci/nextcloud-$NEWEST"
list="${VERSIONS// /, }"

for version in $VERSIONS; do
	sed -i -E "/^\s*ocp-branch:/ s/\]\s*$/, 'stable$version']/" "$WORKFLOW"
done
if git diff --quiet -- "$WORKFLOW"; then
	echo "The matrix in $WORKFLOW did not change." >&2
	exit 1
fi

case "$E2E_RESULT" in
	success) e2e="passed" ;;
	failure) e2e="FAILED" ;;
	*) e2e="did not finish (result: $E2E_RESULT)" ;;
esac
checks_url="https://github.com/$GH_REPO/actions/workflows/php-tests.yml?query=branch%3A${branch//\//%2F}"

body="$(cat <<EOF
A nightly check found Nextcloud versions that are released, but not in the psalm OCP matrix yet: Nextcloud $list.

This pull request adds them to the \`psalm-ocp-compat\` matrix in \`$WORKFLOW\`. It does not change \`max-version\` in \`appinfo/info.xml\`.

## Results

- The E2E smoke test against the \`nextcloud:$NEWEST\` Docker image $e2e. Log: $RUN_URL
- Psalm against the new OCP stubs: see the checks of this pull request. GitHub Actions does not start the pull request workflows for a pull request that it opened. For that reason, the nightly workflow starts \`php-tests.yml\` on this branch. If no checks show up here, look at $checks_url.

## Before you merge

- [ ] The psalm jobs for the new versions pass.
- [ ] The E2E smoke test passed, or a fix for the app is merged.
- [ ] Decide whether to raise \`max-version\` in \`appinfo/info.xml\`. That change needs a minor release.
EOF
)"

if [ "${DRY_RUN:-}" = 1 ]; then
	git diff -- "$WORKFLOW"
	printf '\nBranch: %s\nTitle: CI: test against Nextcloud %s\n\n%s\n' "$branch" "$list" "$body"
	exit 0
fi

base="$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)"
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
gh auth setup-git
git switch -c "$branch"
git commit -q -m "CI: add Nextcloud $list to the psalm OCP matrix" -- "$WORKFLOW"
git push -q origin "HEAD:refs/heads/$branch"
gh pr create --base "$base" --head "$branch" --title "CI: test against Nextcloud $list" --body "$body"
gh workflow run php-tests.yml --ref "$branch"
