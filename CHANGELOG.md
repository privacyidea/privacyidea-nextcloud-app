# Changelog

All notable changes to this project will be documented in this file.

## v1.1.2 - 07/2026

### Bug fixes

- Fixed forwarding of configured request headers to the privacyIDEA server; the feature was previously non-functional.
- Fixed excluded-IP handling that could silently skip two-factor authentication for IPv6 clients or malformed/empty entries.
- Hardened the login flow against empty or malformed server responses and edge cases (unconfigured client, tampered poll counter) that could produce a 500 error.
- Fixed WebAuthn logins not forwarding the authenticator's `userHandle`.
- Fixed the WebAuthn token image not being displayed on the login screen.
- Fixed a non-functional "Push" button being shown for push tokens using `code_to_phone`.

### Improvements

- Added a client-side connection timeout so an unresponsive privacyIDEA server no longer hangs the login page; the server timeout from the settings is now applied to the request itself.
- Browser-based push polling is more responsive and no longer hangs on an unexpected response.
- Added an automated test suite, continuous integration (lint, static analysis, unit tests) and security scanning.

## v1.1.1 - 06/2026

### Maintenance

- Updated build dependencies (`@nextcloud/webpack-vue-config`).

## v1.1.0 - 09/2025

### Features

- Passkey token, usable with PIN/Triggerchallenge.
- Passkey registration.
- Smartphone container enrollment.
- enroll_via_multichallenge cancellable if enabled in privacyIDEA.

### Improvements

- Improved error handling and user feedback during authentication and registration processes.
- Minor bug fixes and performance improvements.

## v1.0.0 - First release

### Features

- Authentication flows: Default, Trigger Challenges, Separate OTP Field, Send Static Pass.
- Forward chosen headers to privacyIDEA server with every request.
- Support for WebAuthn and PUSH tokens.
- Auto-submit form after x digits entered to the OTP field.
- Polling in browser for PUSH token confirmation.
- Specify included / excluded groups for privacyIDEA Authentication.
