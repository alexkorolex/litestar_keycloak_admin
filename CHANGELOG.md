# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026.10.08

### Fixed

- The package includes `litestar_keycloak_admin.preferences`; the 0.3.0 build lacked it and
  was never published.

## [0.3.0] - 2026.10.08

### Added

- `LoginVerificationConfig.user_choice`: users turn the login code on or off for themselves
  through `GET`/`PUT /me/login-verification` (the change needs the current password). The
  choice is kept in a Keycloak user attribute; when it cannot be read, the code is required.
- `KeycloakAdminClient.get_user` and `set_user_attribute`.

## [0.2.0] - 2026.10.08

### Added

- Optional login verification by a one-time code (`LoginVerificationConfig`): `/login` and
  `/initial-password` answer `202` with a challenge, `/login/verify` issues the tokens and
  `/login/resend` sends a new code. The application delivers codes through `send_code`.
- `LoginChallengeError` with machine-readable reasons for the second login step.

## [0.1.0] - 2026.10.02

### Added

- Password login, refresh, logout, and temporary-password completion endpoints.
- Authenticated profile and password management.
- Administrator endpoints for realm roles and user registration.
- A reusable asynchronous Keycloak Admin REST API client.
- A Litestar CLI command for creating bootstrap users.
- Consistent machine-readable errors for authentication and account endpoints.
- Type information through the `py.typed` marker.

[Unreleased]: https://github.com/alexkorolex/litestar_keycloak_admin/commits/main
