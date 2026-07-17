# Local development / testing

A disposable Nextcloud instance for testing the app, using Docker. It runs on
SQLite (no separate database container), auto-installs on first boot, and
bind-mounts this repository as the `privacyidea` app so your changes are live.

You also need a reachable **privacyIDEA server** with a test token — that is not
part of this stack. Configure its URL in the Nextcloud admin settings after
logging in.

## Start

```bash
docker compose -f docker-compose.dev.yml up -d
```

Open <http://localhost:8080> and log in as **admin / admin**. The app is enabled
automatically; configure it under **Settings → Administration → privacyIDEA**,
then enable two-factor for a user to exercise the login flow.

## Test a specific Nextcloud version

The version is just the image tag (`NC_VERSION`, default `stable`):

```bash
NC_VERSION=latest docker compose -f docker-compose.dev.yml up -d   # newest release
NC_VERSION=31     docker compose -f docker-compose.dev.yml up -d   # a specific major
```

To switch versions cleanly, wipe the data first (see reset below) so you get a
fresh install rather than an in-place upgrade.

The app is enabled with `occ app:enable --force`, so it loads even on a
Nextcloud newer than the `max-version` in `appinfo/info.xml` — handy for
checking compatibility before bumping that value.

## Stop / reset

```bash
docker compose -f docker-compose.dev.yml down       # stop, keep the instance
docker compose -f docker-compose.dev.yml down -v    # stop and wipe all data
```

## Run occ / see logs

```bash
docker compose -f docker-compose.dev.yml exec -u www-data nextcloud php occ app:list
docker compose -f docker-compose.dev.yml logs -f
```

## Live edits

PHP changes take effect on the next request. The app ships its JavaScript from
`js/` as-is (no build step), so JS changes are live too — just reload. Only
Nextcloud's server-side cache occasionally needs a nudge:

```bash
docker compose -f docker-compose.dev.yml exec -u www-data nextcloud php occ maintenance:repair
```
