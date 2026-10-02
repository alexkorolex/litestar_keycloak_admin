import asyncio
import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

import aiohttp

from litestar_keycloak_admin.config import KeycloakAdminConfig
from litestar_keycloak_admin.exceptions import (
    KeycloakAdminError,
    KeycloakLoginError,
    KeycloakUnavailableError,
    PasswordChangeRequiredError,
)

PASSWORD_CHANGE_REQUIRED_DESCRIPTION = "Account is not fully set up"
"""Keycloak's ``error_description`` for a password grant on an account with pending required actions."""

BUILT_IN_ROLES = frozenset({"offline_access", "uma_authorization"})
"""Roles every Keycloak realm has; not application roles, so ``list_roles`` leaves them out."""

_ADMIN_TOKEN_LEEWAY_SECONDS = 15


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    text: str
    headers: Mapping[str, str]

    def json(self) -> Any:  # noqa: ANN401
        return json.loads(self.text)

    def error_description(self) -> str | None:
        try:
            payload = self.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        return (
            payload.get("error_description") or payload.get("errorMessage") or payload.get("error")
        )


class KeycloakAdminClient:
    """Calls Keycloak on behalf of the backend: the OIDC token endpoints (password grant,
    refresh, logout) and the Admin REST API.

    One instance lives per application (see ``KeycloakAdminPlugin``); it reuses one aiohttp
    session and one admin token until it expires.
    """

    def __init__(self, config: KeycloakAdminConfig) -> None:
        self.config = config
        self._session: aiohttp.ClientSession | None = None
        self._session_lock = asyncio.Lock()
        self._admin_token: str | None = None
        self._admin_token_expires_at = 0.0

    async def _get_session(self) -> aiohttp.ClientSession:
        # Created lazily inside the running loop - there is none yet when the app is built.
        if self._session is None or self._session.closed:
            async with self._session_lock:
                if self._session is None or self._session.closed:
                    self._session = aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                    )
        return self._session

    async def close(self) -> None:
        """Close the HTTP session; the plugin calls it at application shutdown."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None

    async def _request(self, method: str, url: str, **kwargs: Any) -> _Response:  # noqa: ANN401
        session = await self._get_session()
        try:
            async with session.request(method, url, **kwargs) as response:
                return _Response(response.status, await response.text(), dict(response.headers))
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise KeycloakUnavailableError(f"Keycloak is unreachable: {exc!r}") from exc

    # --- tokens ---------------------------------------------------------------------------

    async def _token_grant(self, data: dict[str, str]) -> dict[str, Any]:
        response = await self._request(
            "POST",
            self.config.keycloak.token_url,
            data={
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                **data,
            },
        )
        if response.status == HTTPStatus.OK:
            return response.json()
        if response.status >= HTTPStatus.INTERNAL_SERVER_ERROR:
            raise KeycloakUnavailableError(f"Keycloak token endpoint failed: {response.text}")
        description = response.error_description() or "Invalid credentials"
        if description == PASSWORD_CHANGE_REQUIRED_DESCRIPTION:
            raise PasswordChangeRequiredError(description)
        raise KeycloakLoginError(description)

    async def login(self, username: str, password: str) -> dict[str, Any]:
        """Resource Owner Password Credentials grant - the password passes through to
        Keycloak and is never stored. Returns Keycloak's token response as is.

        Raises:
            PasswordChangeRequiredError: the account still has a temporary password.
            KeycloakLoginError: wrong credentials.
        """
        return await self._token_grant(
            {"grant_type": "password", "username": username, "password": password}
        )

    async def refresh(self, refresh_token: str) -> dict[str, Any]:
        """New tokens for a live session (Keycloak rotates the refresh token too).

        Raises:
            KeycloakLoginError: the refresh token is expired, revoked or malformed.
        """
        return await self._token_grant(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}
        )

    async def logout(self, refresh_token: str) -> None:
        """End the session behind ``refresh_token``. An already dead session is fine."""
        await self._request(
            "POST",
            self.config.keycloak.logout_url,
            data={
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "refresh_token": refresh_token,
            },
        )

    async def check_password(self, username: str, password: str) -> bool:
        """Whether ``password`` is the user's current one; the session this opens is closed again."""
        try:
            tokens = await self.login(username, password)
        except PasswordChangeRequiredError:
            return True
        except KeycloakLoginError:
            return False
        if refresh_token := tokens.get("refresh_token"):
            await self.logout(refresh_token)
        return True

    async def complete_initial_password(
        self, username: str, password: str, new_password: str
    ) -> dict[str, Any]:
        """Swap a temporary password for a permanent one and log in with it.

        Raises:
            KeycloakLoginError: ``password`` is wrong.
            KeycloakAdminError: the account has no temporary password (``conflict``), or the
                new one breaks the realm's password policy (``invalid``).
        """
        try:
            tokens = await self.login(username, password)
        except PasswordChangeRequiredError:
            subject = await self.find_user_id(username)
            if subject is None:
                raise KeycloakLoginError("Invalid credentials") from None
            await self.set_password(subject, new_password)
            await self.update_user(subject, requiredActions=[])
            return await self.login(username, new_password)
        if refresh_token := tokens.get("refresh_token"):
            await self.logout(refresh_token)
        raise KeycloakAdminError("This account has no temporary password", conflict=True)

    # --- Admin REST API -------------------------------------------------------------------

    async def _fetch_admin_token(self) -> str:
        if self._admin_token and time.monotonic() < self._admin_token_expires_at:
            return self._admin_token
        if self.config.admin_username and self.config.admin_password:
            url = self.config.master_token_url
            data = {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.config.admin_username,
                "password": self.config.admin_password,
            }
        else:
            url = self.config.keycloak.token_url
            data = {
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            }
        response = await self._request("POST", url, data=data)
        if response.status != HTTPStatus.OK:
            raise KeycloakAdminError(f"Could not obtain a Keycloak admin token: {response.text}")
        payload = response.json()
        self._admin_token = token = payload["access_token"]
        self._admin_token_expires_at = (
            time.monotonic() + payload.get("expires_in", 60) - _ADMIN_TOKEN_LEEWAY_SECONDS
        )
        return token

    async def _admin(self, method: str, path: str, **kwargs: Any) -> _Response:  # noqa: ANN401
        token = await self._fetch_admin_token()
        response = await self._request(
            method,
            self.config.admin_realm_url + path,
            headers={"Authorization": f"Bearer {token}"},
            **kwargs,
        )
        if response.status == HTTPStatus.UNAUTHORIZED:
            # Revoked or expired early (e.g. Keycloak restarted) - drop it so the next call re-fetches.
            self._admin_token = None
        return response

    async def list_roles(self) -> list[dict[str, Any]]:
        """The realm's own roles (``name``, ``description``), without Keycloak's built-in ones."""
        found = await self._admin("GET", "/roles", params={"briefRepresentation": "true"})
        if found.status != HTTPStatus.OK:
            raise KeycloakAdminError(f"Could not list realm roles: {found.text}")
        default_roles = f"default-roles-{self.config.keycloak.realm}"
        return sorted(
            (
                role
                for role in found.json()
                if role["name"] not in BUILT_IN_ROLES and role["name"] != default_roles
            ),
            key=lambda role: role["name"],
        )

    async def create_user(
        self,
        *,
        username: str,
        password: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        roles: Iterable[str] = (),
        temporary_password: bool = True,
    ) -> str:
        """Create a realm user, assign ``roles`` and return the new subject id. A temporary
        password must be changed at first login (see ``complete_initial_password``)."""
        role_representations = [await self._role(role) for role in roles]
        created = await self._admin(
            "POST",
            "/users",
            json={
                "username": username,
                "email": email,
                "firstName": first_name,
                "lastName": last_name,
                "enabled": True,
                "emailVerified": email is not None,
                "requiredActions": ["UPDATE_PASSWORD"] if temporary_password else [],
                "credentials": [
                    {"type": "password", "value": password, "temporary": temporary_password}
                ],
            },
        )
        if created.status == HTTPStatus.CONFLICT:
            raise KeycloakAdminError(f"User {username!r} already exists", conflict=True)
        if created.status == HTTPStatus.BAD_REQUEST:
            raise KeycloakAdminError(
                created.error_description() or "User rejected by Keycloak", invalid=True
            )
        if created.status != HTTPStatus.CREATED:
            raise KeycloakAdminError(f"Could not create Keycloak user: {created.text}")
        subject = created.headers["Location"].rsplit("/", 1)[-1]
        if role_representations:
            assigned = await self._admin(
                "POST", f"/users/{subject}/role-mappings/realm", json=role_representations
            )
            if assigned.status != HTTPStatus.NO_CONTENT:
                raise KeycloakAdminError(f"Could not assign roles: {assigned.text}")
        return subject

    async def _role(self, role: str) -> dict[str, Any]:
        found = await self._admin("GET", f"/roles/{role}")
        if found.status == HTTPStatus.NOT_FOUND:
            raise KeycloakAdminError(f"Unknown realm role {role!r}", invalid=True)
        if found.status != HTTPStatus.OK:
            raise KeycloakAdminError(f"Could not look up role {role!r}: {found.text}")
        return found.json()

    async def update_user(self, subject: str, **representation: Any) -> None:  # noqa: ANN401
        """Partial update with Keycloak's own ``UserRepresentation`` field names
        (``firstName``, ``email``, ``requiredActions``, ...)."""
        updated = await self._admin("PUT", f"/users/{subject}", json=representation)
        if updated.status == HTTPStatus.CONFLICT:
            raise KeycloakAdminError(
                "This e-mail is already used by another account", conflict=True
            )
        if updated.status == HTTPStatus.BAD_REQUEST:
            raise KeycloakAdminError(
                updated.error_description() or "Update rejected by Keycloak", invalid=True
            )
        if updated.status != HTTPStatus.NO_CONTENT:
            raise KeycloakAdminError(f"Could not update Keycloak user: {updated.text}")

    async def set_password(self, subject: str, password: str, *, temporary: bool = False) -> None:
        """Set the user's password; a ``temporary`` one has to be replaced at the next login.

        Raises:
            KeycloakAdminError: the password breaks the realm's password policy (``invalid``).
        """
        reset = await self._admin(
            "PUT",
            f"/users/{subject}/reset-password",
            json={"type": "password", "value": password, "temporary": temporary},
        )
        if reset.status == HTTPStatus.BAD_REQUEST:
            detail = reset.error_description() or "Password rejected by the password policy"
            raise KeycloakAdminError(detail, invalid=True)
        if reset.status != HTTPStatus.NO_CONTENT:
            raise KeycloakAdminError(f"Could not set Keycloak password: {reset.text}")

    async def find_user_id(self, username: str) -> str | None:
        """The subject id of the user with exactly this username, or ``None``."""
        found = await self._admin("GET", "/users", params={"username": username, "exact": "true"})
        if found.status != HTTPStatus.OK:
            raise KeycloakAdminError(f"Could not look up user {username!r}: {found.text}")
        users = found.json()
        return users[0]["id"] if users else None
