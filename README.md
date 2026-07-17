# privacyIDEA Nextcloud App
This app adds flexible, enterprise-grade multi-factor authentication to Nextcloud.

It enables Nextcloud to perform MFA against the privacyIDEA server in your network.

PrivacyIDEA supports classic OTP tokens, and challenge-response tokens like E-Mail, SMS, PUSH, or WebAuthn.

## Installation
### Nextcloud App Store
privacyIDEA Nextcloud App is now available in the Nextcloud App Store.

You can install it from the Nextcloud Admin Panel.
For more information see the Nextcloud documentation: https://docs.nextcloud.com/server/stable/admin_manual/apps_management.html

### Install from release archive
1. Download `privacyidea.tar.gz` archive from the latest release.
2. Unpack the archive to the Nextcloud apps directory: ``tar -xzf privacyidea.tar.gz -C <nextcloud>/apps/``.
3. Enable the app in the Nextcloud WebUI: go to settings(admin) -> apps -> disabled page with "Not enabled" apps and click "Enable" for the privacyIDEA application.

### Manual installation from GitHub repository (build from source)
1. Copy the files of this repository to ``<nextcloud>/apps/privacyidea``.
2. Install npm package in the privacyIDEA app directory: ``npm install``. Note: Remember that you need npm installed on the server first (``apt install npm``). Check your node (``node -v``) and npm (``npm install -g npm@latest``) versions to fulfill the requirements.
3. Build webpack in privacyIDEA app directory: ``npm run build``.
4. In the Nextcloud WebUI go to settings(admin) -> apps -> disabled page with "Not enabled" apps and click "Enable" for the privacyIDEA application.

## Configuration

All settings live in Nextcloud under **Settings → Administration → privacyIDEA**
(or scriptable via `occ config:app:set privacyidea <key> --value=<value>`). At a
minimum, set the server URL and tick **Activate privacyIDEA**.

### Server connection

| Setting | Key | Description |
| --- | --- | --- |
| Activate privacyIDEA | `piActivatePI` | Master switch for MFA via privacyIDEA. Configure the server connection before enabling. |
| URL of the privacyIDEA server | `piURL` | Base URL of your privacyIDEA instance, e.g. `https://pi.example.com`. |
| SSL certificate verification | `piSSLVerify` | Verify the server's TLS certificate (host and peer). **Keep enabled in production.** |
| Realm | `piRealm` | privacyIDEA realm to authenticate against, if not the default. |
| Timeout | `piTimeout` | Connection timeout in seconds (default `5`). Prevents an unresponsive server from hanging the login page. |
| No proxy | `piNoProxy` | Ignore the system-wide proxy and talk to privacyIDEA directly. |
| Forward client IP | `piForwardClientIP` | Send the user's IP as the `client` parameter so privacyIDEA policies can match on the original address. |

### Who has to use MFA

| Setting | Key | Description |
| --- | --- | --- |
| Exclude IP addresses | `piExcludeIPs` | Skip MFA for these IPv4 addresses/ranges, e.g. `10.0.1.12,10.0.1.20-10.0.1.40`. (IPv4 only; non-IPv4 or unparseable entries are ignored and never skip MFA.) |
| Group names + Include/Exclude | `piInExGroupsField`, `piInOrExSelected` | Restrict MFA to (Include) or skip it for (Exclude) members of the listed Nextcloud groups (comma-separated). |

### Authentication flow

The **Authentication flow** radios (`piSelectedAuthFlow`) control what is sent to
privacyIDEA *before the login screen is shown* — used to trigger the user's token
challenges (or complete authentication) up front. Mutually exclusive:

| Flow (setting value) | What happens | Extra settings |
| --- | --- | --- |
| **None (prompt only)** — default (`piAuthFlowDefault`) | Nothing is sent up front; the login screen is shown and whatever the user submits goes to `/validate/check`. Any challenges the server returns are then shown. | — |
| **Trigger Challenge** (`piAuthFlowTriggerChallenge`) | On page load the app uses a **service account** to call `/validate/triggerchallenge` for the user, so all of the user's challenges (push, SMS, email, …) are triggered up front. | Service name + Service password (Service realm optional). |
| **Send Password** (`piAuthFlowSendPassword`) | On page load the app sends the user's Nextcloud login password to `/validate/check` — completing login (e.g. `passthru`) or triggering challenges. Password logins only; for SSO/passkey/token logins it falls back to prompting. | — |
| **Send Static Pass** (`piAuthFlowSendStaticPass`) | On page load the app sends a fixed configured password to `/validate/check` — completing login (e.g. `passOnNoToken`) or triggering challenges. | Static password. |

The *input layout* on the login screen (single OTP field, or a separate
password/PIN field plus OTP) is a separate **Login screen** setting — see below.

### Login experience

| Setting | Key | Description |
| --- | --- | --- |
| Input layout | `piInputLayout` | Login-screen layout: a single OTP field (`otp`, default) or a separate password/PIN field plus an OTP field (`separate`), combined and sent to privacyIDEA. |
| OTP field hint | `piOTPFieldHint` | Placeholder text shown in the OTP input field (default "One-Time-Password"). |
| Auto-submit by OTP length | `piActivateAutoSubmitOtpLength`, `piAutoSubmitOtpLength` | Submit the form automatically once the configured number of characters (default `6`) is entered in the OTP field. |
| Poll in browser | `piPollInBrowser`, `piPollInBrowserURL` | For PUSH tokens, poll privacyIDEA directly from the browser so the page advances the moment the user confirms, instead of periodic page reloads. Requires a privacyIDEA URL reachable from the browser. |
| Forward headers to privacyIDEA | `piForwardHeaders` | Comma-separated list of request header names to forward to privacyIDEA (useful for header-based policies). |

## Protips
### Enable or disable privacyIDEA app using command line
Go to your Nextcloud installation directory and run one of the following commands:
- ``sudo -u www-data php occ app:enable privacyidea``
- ``sudo -u www-data php occ app:disable privacyidea``

### How to install node with nvm?
1. If you don't have nvm run: ``sudo apt update``, then: ``curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash``
2. Restart your terminal.
3. Install node: ``nvm install node``
4. To update node to a new version: ``nvm install node --reinstall-packeges-from=current``

## Development and testing

A throwaway Nextcloud for testing the app is provided via Docker Compose. It
runs on SQLite (no separate database), auto-installs on first boot, and
bind-mounts this repository as the `privacyidea` app (auto-enabled), so your
changes are live without a rebuild. You still need your own reachable
privacyIDEA server; set its URL in the admin settings after logging in.

```bash
docker compose -f docker-compose.dev.yml up -d          # start (Nextcloud "stable")
NC_VERSION=latest docker compose -f docker-compose.dev.yml up -d   # test the newest release
docker compose -f docker-compose.dev.yml down -v        # stop and wipe
```

Then open http://localhost:8080 and log in as `admin` / `admin`. The Nextcloud
version is just the `NC_VERSION` image tag. See [`dev/README.md`](dev/README.md)
for details (version switching, running `occ`, logs).

### Running the checks

The PHP test suite and static analysis run via Composer:

```bash
composer install
composer run lint         # php -l
composer run cs:check     # coding standard (composer run cs:fix to apply)
composer run psalm        # static analysis
composer run test:unit    # PHPUnit
```