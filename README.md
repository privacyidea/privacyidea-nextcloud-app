# privacyIDEA Nextcloud App

This module adds flexible, enterprise-grade multi-factor authentication to Nextcloud.

It enables Nextcloud to perform MFA against the privacyIDEA server in your network.

PrivacyIDEA supports classic OTP tokens, and challenge-response tokens like E-Mail, SMS, PUSH, or WebAuthn.

## Installation

privacyIDEA Nextcloud App is available in the Nextcloud App Store. You can install it from the Nextcloud Admin Panel.
For more information see the Nextcloud documentation: https://docs.nextcloud.com/server/stable/admin_manual/apps_management.html

### Manual Installation
1. Copy the files of this repository to ``<nextcloud>/apps/privacyidea``.
2. Install npm package in privacyIDEA app directory: ``npm install``. Note: Remember that you need npm installed on the server first (``apt install npm``). Check your node (``node -v``) and npm (``npm install -g npm@latest``) version to fulfill the requirements.
3. Build webpack in privacyIDEA app directory: ``npm run build``. 
4. In the Nextcloud WebUI go to settings -> apps -> disabled page with "Not enabled" apps by administrator and click "Enable" for the privacyIDEA application.

## Protip

You can enable and disable privacyIDEA app using command line. Simply go to your Nextcloud installation directory and run:
- ``sudo -u www-data php occ app:enable privacyidea``
- ``sudo -u www-data php occ app:disable privacyidea``
