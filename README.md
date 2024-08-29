# privacyIDEA Nextcloud App

This module adds flexible, enterprise-grade multi-factor authentication to Nextcloud.

It enables Nextcloud to perform MFA against the privacyIDEA server in your network.

PrivacyIDEA supports classic OTP tokens, and challenge-response tokens like E-Mail, SMS, PUSH, or WebAuthn.

## Installation

privacyIDEA Nextcloud App is available in the Nextcloud App Store. You can install it from the Nextcloud Admin Panel.
For more information see the Nextcloud documentation: https://docs.nextcloud.com/server/stable/admin_manual/apps_management.html

### Manual Installation
1. Copy the files of this repository to ``<nextcloud>/apps/privacyidea``.
2. Build webpack in the privacyidea directory: ``npm install && npm run build``.
3. In the Nextcloud WebUI go to settings -> apps -> disabled page with "Not enabled" apps by administrator and click "Enable" for the privacyIDEA application.
