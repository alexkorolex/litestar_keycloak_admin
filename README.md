# litestar-keycloak-admin

Account and user management for Litestar applications that use Keycloak as their identity
provider. It lets your frontend keep its own login form, lets users manage their own account,
and lets administrators create users with any realm roles. Neither the browser nor your code
ever has to talk to Keycloak directly.

The package is built on top of [litestar-keycloak](https://github.com/smirnoffmg/litestar-keycloak)
and complements it rather than replacing it:

| Concern | Handled by |
| --- | --- |
| Validating access tokens (JWKS, `iss`, `aud`, `exp`) | `litestar-keycloak` |
| `current_user` injection, `require_roles` / `require_scopes` guards | `litestar-keycloak` |
| Login with username and password, refresh, logout | **this package** |
| Replacing a temporary password at first login | **this package** |
| Own profile and password | **this package** |
| Listing realm roles, registering users | **this package** |
| Creating users from the command line (e.g. the first admin) | **this package** |

`KeycloakAdminPlugin` installs `litestar-keycloak`'s `KeycloakPlugin` for you, so an application
registers exactly one plugin.

## Installation

```bash
uv add litestar-keycloak-admin
```

It depends on `litestar-keycloak` (0.3.x) and `aiohttp`; both are installed with it.

## Quick start

```python
from litestar import Litestar, get
from litestar_keycloak import CurrentUser, MatchStrategy, require_roles
from litestar_keycloak_admin import KeycloakAdminConfig, KeycloakAdminPlugin


@get("/reports", guards=[require_roles("admin", "analyst", strategy=MatchStrategy.ANY)])
async def reports(current_user: CurrentUser) -> dict[str, str]:
    return {"requested_by": current_user.preferred_username or current_user.sub}


app = Litestar(
    route_handlers=[reports],
    plugins=[
        KeycloakAdminPlugin(
            KeycloakAdminConfig.from_env(keycloak={"exclude_patterns": ("^/schema", "^/health$")}),
        )
    ],
)
```

With `KEYCLOAK_INTERNAL_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET`
set, the application now has:

- every route protected by a Keycloak access token, except `/schema`, `/health` and the public
  auth endpoints;
- `/reports` open to users holding `admin` **or** `analyst`;
- the auth endpoints under `/auth` (see [Endpoints](#endpoints)).

## Keycloak setup

The package expects:

1. **A confidential client** (Client authentication *On*) with *Direct access grants* enabled.
   This is the client the backend uses for the password grant. Its ID and secret go into
   `KEYCLOAK_CLIENT_ID` / `KEYCLOAK_CLIENT_SECRET`.
2. **An audience mapper** on that client, so access tokens carry its ID in `aud`
   (*Client scopes → dedicated scope → Add mapper → Audience*). Without it every token is rejected
   as having the wrong audience.
3. **Realm roles** for your application, e.g. `admin`, `user`, `dispatcher`. They are not listed
   anywhere in code: define them in Keycloak (or in the realm export you import) and they can be
   assigned and checked right away. One realm role, `admin` by default, is the *admin role*: its
   holders may list roles and register users.
4. **Admin REST API access**, in one of two ways:
   - set `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` to a master-realm administrator (simplest,
     fine for development); or
   - leave them unset and enable *Service accounts* on the client, then give its service account
     the `realm-management` roles `manage-users` and `view-realm` (recommended in production: the
     backend gets only the rights it needs, in one realm).

A minimal realm export with both roles and the client:

```json
{
  "realm": "my-realm",
  "roles": {
    "realm": [
      { "name": "admin", "description": "Full administrative access" },
      { "name": "user", "description": "Regular user" }
    ]
  },
  "clients": [
    {
      "clientId": "my-backend",
      "publicClient": false,
      "secret": "${KEYCLOAK_CLIENT_SECRET}",
      "directAccessGrantsEnabled": true,
      "standardFlowEnabled": false,
      "protocolMappers": [
        {
          "name": "audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": { "included.client.audience": "my-backend", "access.token.claim": "true" }
        }
      ]
    }
  ]
}
```

## Protecting routes

Authentication is **on by default**: `litestar-keycloak` rejects any request without a valid
token with `401`. Make a route public in one of two ways:

- a path pattern in `exclude_patterns` (regular expressions, matched against the path):
  `KeycloakAdminConfig.from_env(keycloak={"exclude_patterns": ("^/schema", "^/webhooks/")})`;
- a handler flag: `@get("/health", opt={"exclude_from_auth": True})`.

On a protected route, inject the caller as `current_user: CurrentUser` (the parameter must have
exactly this name). It is a `litestar_keycloak.KeycloakUser` with `sub`, `preferred_username`,
`email`, `given_name`, `family_name`, `realm_roles` and `client_roles`.

Restrict a route to certain roles with `require_roles`:

```python
from litestar_keycloak import MatchStrategy, require_roles
from litestar_keycloak_admin import requires_admin

require_roles("admin", "dispatcher", strategy=MatchStrategy.ANY)  # holds at least one of them
require_roles("dispatcher", "supervisor")  # holds every one of them
requires_admin  # holds the configured admin role
```

> **Note:** `require_roles` defaults to `MatchStrategy.ALL`. For "any of these roles", which is
> what most role checks mean, pass `strategy=MatchStrategy.ANY` explicitly.

A caller lacking the roles gets `403`.

## Login flow

The endpoints are designed for a browser frontend with its own login form:

1. **Log in**: `POST /auth/login` with `{"username", "password"}`. The response holds the access
   token. The refresh token is set as an `httponly` cookie and is never visible to JavaScript.
2. **First login of a new user**: users created by an admin have a temporary password, so the
   login responds `403` with the reason `passwordChangeRequired` (see [Errors](#errors)). The frontend asks for
   a new password and calls `POST /auth/initial-password` with
   `{"username", "password", "new_password"}`. On success it returns tokens, just like a login.
3. **Calling the API**: send `Authorization: Bearer <token>`.
4. **Keeping the session alive**: before the access token expires (`expires_in`, in seconds), call
   `POST /auth/refresh`, or call it when an API request fails with the reason `expired`. The
   browser sends the cookie on its own; no body is needed. A `401` from `/refresh` itself means
   the Keycloak session is over and the user has to log in again.
5. **Logging out**: `POST /auth/logout` ends the Keycloak session and clears the cookie. Dropping
   the access token in the browser alone would leave the session usable until it expires.

For non-browser clients (mobile apps, scripts), disable the cookie with
`refresh_cookie=RefreshCookieConfig(enabled=False)`: the refresh token is then returned in the
response body and sent back as `{"refresh_token": "..."}` to `/refresh` and `/logout`.

## Endpoints

All paths are relative to `auth_path` (default `/auth`).

### Public (no token)

| Method and path | Body | Success |
| --- | --- | --- |
| `POST /login` | `username`, `password` | `200`, `TokenResponse` |
| `POST /initial-password` | `username`, `password` (the temporary one), `new_password` | `200`, `TokenResponse` |
| `POST /refresh` | `refresh_token` (only without the cookie) | `200`, `TokenResponse` |
| `POST /logout` | `refresh_token` (only without the cookie) | `204` |

`TokenResponse` is
`{"token": str, "expires_in": int, "refresh_expires_in": int, "refresh_token": str | null}`;
`refresh_token` is `null` while the cookie is enabled.

### Any authenticated user

| Method and path | Body | Success |
| --- | --- | --- |
| `GET /me` | | `200`, `UserResponse` |
| `PATCH /me` | any of `first_name`, `last_name`, `email` (`""` removes the e-mail) | `200`, `UserResponse` |
| `POST /password` | `current_password`, `new_password` | `204` |

`UserResponse` is
`{"id", "username", "email", "first_name", "last_name", "roles": [str]}`. It is built from the
access token, so after `PATCH /me` the token itself keeps the old values until it is refreshed.

### Admin role only

| Method and path | Body | Success |
| --- | --- | --- |
| `GET /roles` | | `200`, `[{"name", "description"}]` |
| `POST /register` | `username`, `password`, `roles: [str]`, optional `email`, `first_name`, `last_name` | `201`, `UserResponse` |

`GET /roles` returns the realm's own roles and leaves out Keycloak's built-in ones
(`offline_access`, `uma_authorization`, `default-roles-<realm>`). Use it to fill a role picker.

`POST /register` creates the user with a **temporary** password and the given roles, at least
one. It fails with `400`, and creates nothing, if a role doesn't exist in the realm or isn't in
`assignable_roles`.

## Errors

Every error, whether it comes from this package, from `litestar-keycloak` (tokens, roles) or from
Litestar itself (validation), has the same shape:

```json
{
  "error": {
    "errors": [
      {
        "domain": "global",
        "reason": "invalidParameter",
        "message": "Password must be at least 8 characters long",
        "locationType": "body",
        "location": "password"
      }
    ],
    "code": 400,
    "message": "Password must be at least 8 characters long"
  }
}
```

- `code` repeats the HTTP status, and `message` is meant for humans.
- `errors[].reason` is the stable, machine-readable part: **branch on it, not on the message**.
- `location` and `locationType` say what the error is about, when that is known: a body field
  (`body`), a query or path parameter (`query`, `path`), or a header (`header`, e.g.
  `Authorization`).

| Status | `reason` | When |
| --- | --- | --- |
| `400` | `invalidParameter` | A field is missing, has the wrong type or fails a check (password too short, no roles); one item per field |
| `400` | `invalid` | Keycloak refused the input: role missing from the realm, password breaks the realm's policy |
| `400` | `badRequest` | Malformed request, e.g. invalid JSON |
| `401` | `required` | No access token, or no session to refresh |
| `401` | `expired` | The access token has expired: refresh it |
| `401` | `authError` | Invalid token, wrong credentials, expired or ended session |
| `403` | `passwordChangeRequired` | Login with a temporary password: call `/initial-password` |
| `403` | `insufficientPermissions` | The caller lacks a required role |
| `403` | `insufficientScope` | The token lacks a required scope |
| `409` | `conflict` | User or e-mail already exists; `/initial-password` for an account without a temporary password |
| `500` | `internalError` | Unexpected server error; no details are exposed |
| `502` | `backendError` | Keycloak answered with something unexpected |
| `503` | `backendError` | Keycloak is unreachable |

Token errors also set `WWW-Authenticate: Bearer`.

The plugin applies this format to its own endpoints and to token and role errors. To use it for
the whole application, register the same handlers app-wide:

```python
from litestar import Litestar
from litestar.exceptions import HTTPException
from litestar.status_codes import HTTP_500_INTERNAL_SERVER_ERROR
from litestar_keycloak_admin import handle_http_exception, handle_internal_error

app = Litestar(
    exception_handlers={
        HTTPException: handle_http_exception,
        HTTP_500_INTERNAL_SERVER_ERROR: handle_internal_error,
    },
    ...,
)
```

In your own handlers, `HTTPException(..., extra={"reason": "..."})` sets the `reason`, and
`error_response(status, message, [ErrorItem(...)])` builds a response directly.

## Configuration

`KeycloakAdminConfig.from_env()` reads these variables (prefix `KEYCLOAK_`, change it with
`from_env(prefix=...)`):

| Variable | Required | Meaning |
| --- | --- | --- |
| `INTERNAL_URL` | yes | Where the backend reaches Keycloak, e.g. `http://keycloak:8080` |
| `REALM` | yes | Realm name |
| `CLIENT_ID` | yes | The confidential client (see [Keycloak setup](#keycloak-setup)) |
| `CLIENT_SECRET` | yes | Its secret |
| `ISSUER` | no | Expected `iss`: the URL users reach Keycloak at, plus `/realms/<realm>`. Needed when it differs from `INTERNAL_URL`, e.g. behind a reverse proxy |
| `AUDIENCE` | no | Expected `aud`; defaults to `CLIENT_ID` |
| `ADMIN`, `ADMIN_PASSWORD` | no | Master-realm administrator for the Admin REST API; without them the client's service account is used |
| `REFRESH_COOKIE_PATH` | no | Cookie path when a reverse proxy serves the API under a prefix, e.g. `/api/auth`; otherwise the browser never sends the cookie back |

Keyword arguments refine the result:

- `keycloak={...}` passes extra arguments to `litestar_keycloak.KeycloakConfig`, e.g.
  `exclude_patterns`, `jwks_cache_ttl`, `optional_audiences`;
- other arguments override `KeycloakAdminConfig` fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `admin_role` | `"admin"` | Realm role allowed to list roles and register users |
| `assignable_roles` | `()` | Roles registration may assign; empty means every realm role |
| `auth_path` | `"/auth"` | Where the endpoints are mounted |
| `refresh_cookie` | `RefreshCookieConfig()` | `enabled`, `name` (`kc_refresh`), `path`, `secure`, `samesite` (`strict`) |
| `min_password_length` | `8` | Checked before Keycloak's own password policy |
| `timeout` | `10` | Seconds per request to Keycloak |

`KeycloakAdminConfig(keycloak=KeycloakConfig(...), ...)` can also be built directly, without
environment variables.

## Command line

The plugin adds a `keycloak` group to the `litestar` CLI. Its main use is creating the first
administrator, when nobody can log in to `/register` yet:

```bash
KEYCLOAK_NEW_USER_PASSWORD='temporary-secret' \
  litestar keycloak create-user root --role admin --exist-ok
```

- `--role` may be repeated to assign several roles;
- the password comes from `KEYCLOAK_NEW_USER_PASSWORD` or an interactive prompt, never from
  command-line arguments, which other processes can see;
- the password is temporary: the user replaces it at first login;
- `--exist-ok` exits successfully if the user already exists, so the command is safe to run on
  every deployment.

## Using the client in your own code

`KeycloakAdminClient` is available to any handler as the `keycloak_admin` dependency, for
user-management needs beyond the built-in endpoints:

```python
from litestar import post
from litestar.di import NamedDependency
from litestar_keycloak_admin import KeycloakAdminClient, requires_admin


@post("/users/{username:str}/reset-password", guards=[requires_admin], status_code=204)
async def reset_password(username: str, keycloak_admin: NamedDependency[KeycloakAdminClient]) -> None:
    subject = await keycloak_admin.find_user_id(username)
    ...
```

It covers `login`, `refresh`, `logout`, `check_password`, `complete_initial_password`,
`list_roles`, `create_user`, `update_user`, `set_password` and `find_user_id`. Its errors
(`KeycloakClientError` and subclasses) are turned into the HTTP responses listed in
[Errors](#errors) wherever they are raised.

## Security notes

- **Password grant.** The login endpoints use OAuth's *Resource Owner Password Credentials*
  grant: the password passes through your backend to Keycloak and is never stored. It is what
  allows a custom login form, but OAuth 2.1 deprecates it, and it rules out Keycloak features
  that need its own login page (social login, WebAuthn, its two-factor flows). If you need them,
  use `litestar-keycloak`'s own routes (Authorization Code flow) instead of the public endpoints
  here.
- **Refresh token.** By default it stays in an `httponly`, `secure`, `SameSite=Strict` cookie
  scoped to `auth_path`, out of reach of JavaScript. `secure` cookies need HTTPS; disable it only
  for local development.
- **Admin credentials.** Prefer a service account with `manage-users` and `view-realm` to a
  master-realm administrator in production.

## Development

```bash
uv run pytest packages/litestar-keycloak-admin/tests
```

The tests start a fake Keycloak on `aiohttp.web` (`tests/fake_keycloak.py`), so they run real
HTTP against both this package and `litestar-keycloak` without a Keycloak instance.
