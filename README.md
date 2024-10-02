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