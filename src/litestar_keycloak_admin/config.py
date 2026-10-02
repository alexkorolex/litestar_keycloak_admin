import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from litestar_keycloak import KeycloakConfig


@dataclass(frozen=True, slots=True)
class RefreshCookieConfig:
    """Where the session endpoints keep the refresh token.

    With ``enabled`` the token lives in an ``httponly`` cookie only and is never returned in
    a response body - what a browser frontend wants. Disable it for non-browser clients:
    the token is then returned in the body and must be sent back in ``refresh_token``.
    """

    enabled: bool = True
    name: str = "kc_refresh"
    path: str | None = None
    """Defaults to ``auth_path``. Set it when a reverse proxy serves the API under a
    prefix (e.g. ``/api/auth``), or the browser won't send the cookie back."""
    secure: bool = True
    samesite: Literal["lax", "strict", "none"] = "strict"


@dataclass(frozen=True, slots=True)
class KeycloakAdminConfig:
    keycloak: KeycloakConfig
    """Token validation settings of ``litestar-keycloak``; its ``server_url``, ``realm``,
    ``client_id`` and ``client_secret`` are reused for every call made here."""

    admin_username: str | None = None
    admin_password: str | None = None
    """Master-realm admin used for the Admin REST API. Leave both unset to use the client's
    own service account instead (``client_credentials``; give it the ``realm-management``
    roles ``manage-users`` and ``view-realm``)."""

    admin_role: str = "admin"
    """Realm role allowed to register users and list roles."""
    assignable_roles: tuple[str, ...] = ()
    """Realm roles registration may assign. Empty (the default) allows every role the realm
    defines, so new roles only need to be added in Keycloak."""

    auth_path: str = "/auth"
    refresh_cookie: RefreshCookieConfig = field(default_factory=RefreshCookieConfig)
    min_password_length: int = 8
    timeout: float = 10

    @classmethod
    def from_env(
        cls,
        prefix: str = "KEYCLOAK_",
        *,
        keycloak: Mapping[str, Any] | None = None,
        **overrides: Any,  # noqa: ANN401
    ) -> "KeycloakAdminConfig":
        """Read ``{prefix}INTERNAL_URL``, ``REALM``, ``CLIENT_ID``, ``CLIENT_SECRET`` (required) and
        ``ISSUER``, ``AUDIENCE``, ``ADMIN``, ``ADMIN_PASSWORD``, ``REFRESH_COOKIE_PATH`` (optional).

        ``keycloak`` holds extra ``litestar_keycloak.KeycloakConfig`` arguments (e.g.
        ``exclude_patterns``); ``overrides`` win over the environment for this config.
        """

        def required(name: str) -> str:
            value = os.environ.get(prefix + name)
            if not value:
                raise ValueError(f"{prefix}{name} is required")
            return value

        def optional(name: str) -> str | None:
            return os.environ.get(prefix + name) or None

        keycloak_config = KeycloakConfig(
            server_url=required("INTERNAL_URL"),
            realm=required("REALM"),
            client_id=required("CLIENT_ID"),
            client_secret=required("CLIENT_SECRET"),
            expected_issuer=optional("ISSUER"),
            audience=optional("AUDIENCE"),
            **(keycloak or {}),
        )
        config = cls(
            keycloak=keycloak_config,
            admin_username=optional("ADMIN"),
            admin_password=optional("ADMIN_PASSWORD"),
            refresh_cookie=RefreshCookieConfig(path=optional("REFRESH_COOKIE_PATH")),
        )
        return replace(config, **overrides)

    @property
    def client_id(self) -> str:
        return self.keycloak.client_id

    @property
    def client_secret(self) -> str:
        if not self.keycloak.client_secret:
            raise ValueError("KeycloakConfig.client_secret is required for litestar-keycloak-admin")
        return self.keycloak.client_secret

    @property
    def admin_realm_url(self) -> str:
        return f"{self.keycloak.server_url.rstrip('/')}/admin/realms/{self.keycloak.realm}"

    @property
    def master_token_url(self) -> str:
        return f"{self.keycloak.server_url.rstrip('/')}/realms/master/protocol/openid-connect/token"

    @property
    def cookie_path(self) -> str:
        return self.refresh_cookie.path or self.auth_path
