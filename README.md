# privacyIDEA Nextcloud App

This module adds flexible, enterprise-grade multi-factor authentication to Nextcloud.
It enables Nextcloud to perform MFA against the privacyIDEA server, that runs in your network.
Users can authenticate with classic OTP tokens, and Challenge-Response tokens like E-Mail, SMS, PUSH, or WebAuthn devices.

## Installation

- privacyIDEA Nextcloud App is available in the Nextcloud App Store. You can install it from the Nextcloud Admin Panel.
   For more information see the Nextcloud documentation: https://docs.nextcloud.com/server/stable/admin_manual/apps_management.html
- To install the privacyIDEA app manually:
1. copy the repo files to  ``<nextcloud>/apps/privacyidea`` directory.
2. Build webpack in privacyidea directory: ``npm install && npm run build``.
3. In Nextcloud UI go to settings -> apps -> disabled page with "Not enabled" apps by administrator and click "Enable" for the privacyIDEA application.