# Changelog

All notable changes to this project will be documented in this file.

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
