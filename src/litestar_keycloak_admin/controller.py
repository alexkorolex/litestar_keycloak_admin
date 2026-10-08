from dataclasses import dataclass, field
from typing import Any

from litestar import Controller, Request, Response, get, patch, post, put
from litestar.connection import ASGIConnection
from litestar.datastructures import Cookie
from litestar.exceptions import ClientException, NotAuthorizedException, NotFoundException
from litestar.handlers.base import BaseRouteHandler
from litestar_keycloak import CurrentUser, KeycloakUser, MatchStrategy, require_roles

from litestar_keycloak_admin.challenges import LoginChallenge, LoginChallenges, unverified_claims
from litestar_keycloak_admin.client import KeycloakAdminClient
from litestar_keycloak_admin.config import KeycloakAdminConfig
from litestar_keycloak_admin.preferences import LoginVerificationPreferences
from litestar_keycloak_admin.verification import LoginVerificationConfig

STATE_KEY = "keycloak_admin"
"""``app.state`` key of the application's ``KeycloakAdminClient``."""


def keycloak_admin(connection: ASGIConnection[Any, Any, Any, Any]) -> KeycloakAdminClient:
    return connection.app.state[STATE_KEY]


def requires_admin(
    connection: ASGIConnection[Any, Any, Any, Any], handler: BaseRouteHandler
) -> None:
    """Guard: the caller holds the configured ``admin_role``."""
    role = keycloak_admin(connection).config.admin_role
    require_roles(role, strategy=MatchStrategy.ANY)(connection, handler)


@dataclass
class LoginRequest:
    username: str
    password: str


@dataclass
class InitialPasswordRequest:
    username: str
    password: str
    """The temporary password the account was created with."""
    new_password: str


@dataclass
class RefreshTokenRequest:
    refresh_token: str | None = None
    """Only needed when the refresh cookie is disabled."""


@dataclass
class TokenResponse:
    token: str
    expires_in: int | None
    refresh_expires_in: int | None
    refresh_token: str | None = None
    """Only returned when the refresh cookie is disabled - otherwise it lives in the cookie."""


@dataclass
class LoginCodeRequest:
    challenge_id: str
    code: str


@dataclass
class LoginChallengeRequest:
    challenge_id: str


@dataclass
class LoginChallengeResponse:
    """Answer of ``/login`` while the second step is on: the code went to ``destination``."""

    challenge_id: str
    expires_in: int
    destination: str
    """The masked e-mail, e.g. ``a***@example.com``."""
    code_required: bool = True

    @classmethod
    def from_challenge(cls, challenge: LoginChallenge) -> "LoginChallengeResponse":
        return cls(
            challenge_id=challenge.challenge_id,
            expires_in=challenge.expires_in,
            destination=challenge.destination,
        )


SessionResponse = Response[TokenResponse | LoginChallengeResponse]


@dataclass
class LoginVerificationSettings:
    """The caller's login code setting; ``changeable`` is false when the app decides alone."""

    enabled: bool
    changeable: bool


@dataclass
class LoginVerificationUpdate:
    enabled: bool
    password: str
    """The current password: a stolen session alone must not turn the code off."""


@dataclass
class RegisterRequest:
    username: str
    password: str
    """Temporary: the user has to replace it at first login (``/initial-password``)."""
    roles: list[str]
    """Any realm roles (see ``GET /roles``), unless ``assignable_roles`` narrows them."""
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None


@dataclass
class ProfileUpdateRequest:
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    """An empty string removes the e-mail."""


@dataclass
class PasswordChangeRequest:
    current_password: str
    new_password: str


@dataclass
class RoleResponse:
    name: str
    description: str | None = None


@dataclass
class UserResponse:
    """A user as returned by ``/me`` and ``/register``; ``roles`` are realm roles."""

    id: str
    """The Keycloak subject id (``sub``)."""
    username: str | None
    email: str | None
    first_name: str | None
    last_name: str | None
    roles: list[str] = field(default_factory=list)

    @classmethod
    def from_user(cls, user: KeycloakUser) -> "UserResponse":
        return cls(
            id=user.sub,
            username=user.preferred_username,
            email=user.email,
            first_name=user.given_name,
            last_name=user.family_name,
            roles=sorted(user.realm_roles),
        )


def _refresh_cookie(config: KeycloakAdminConfig, value: str, max_age: int | None) -> Cookie:
    cookie = config.refresh_cookie
    return Cookie(
        key=cookie.name,
        value=value,
        max_age=max_age,
        path=config.cookie_path,
        httponly=True,
        secure=cookie.secure,
        samesite=cookie.samesite,
    )


def _token_response(config: KeycloakAdminConfig, tokens: dict[str, Any]) -> Response[TokenResponse]:
    refresh_token = tokens.get("refresh_token")
    in_cookie = config.refresh_cookie.enabled and refresh_token is not None
    body = TokenResponse(
        token=tokens["access_token"],
        expires_in=tokens.get("expires_in"),
        refresh_expires_in=tokens.get("refresh_expires_in"),
        refresh_token=None if in_cookie else refresh_token,
    )
    cookies = (
        [_refresh_cookie(config, refresh_token, tokens.get("refresh_expires_in"))]
        if in_cookie and refresh_token
        else []
    )
    return Response(content=body, cookies=cookies)


def _verification(request: Request[Any, Any, Any]) -> LoginVerificationConfig:
    verification = keycloak_admin(request).config.login_verification
    if verification is None:
        raise NotFoundException("Login verification is not enabled")
    return verification


def _login_challenges(request: Request[Any, Any, Any]) -> LoginChallenges:
    verification = _verification(request)
    store = request.app.stores.get(verification.store)
    return LoginChallenges(verification, keycloak_admin(request), store)


def _preferences(request: Request[Any, Any, Any]) -> LoginVerificationPreferences:
    return LoginVerificationPreferences(_verification(request), keycloak_admin(request))


def _challenge_response(challenge: LoginChallenge) -> Response[LoginChallengeResponse]:
    return Response(content=LoginChallengeResponse.from_challenge(challenge), status_code=202)


async def _session_response(
    request: Request[Any, Any, Any], tokens: dict[str, Any]
) -> SessionResponse:
    """Tokens right away, or - with ``login_verification`` - a challenge to confirm first,
    unless the user has turned the code off."""
    client = keycloak_admin(request)
    if client.config.login_verification is None:
        return _token_response(client.config, tokens)
    subject = str(unverified_claims(str(tokens["access_token"])).get("sub") or "")
    if not await _preferences(request).enabled(subject):
        return _token_response(client.config, tokens)
    return _challenge_response(await _login_challenges(request).start(tokens))


def _refresh_token(request: Request[Any, Any, Any], data: RefreshTokenRequest | None) -> str | None:
    config = keycloak_admin(request).config
    from_cookie = (
        request.cookies.get(config.refresh_cookie.name) if config.refresh_cookie.enabled else None
    )
    return from_cookie or (data.refresh_token if data else None)


def _invalid(field: str, message: str) -> ClientException:
    """A 400 about one body field - rendered as an ``invalidParameter`` error located at it."""
    return ClientException(message, extra=[{"message": message, "key": field, "source": "body"}])


def _check_password_length(config: KeycloakAdminConfig, field: str, password: str) -> None:
    if len(password) < config.min_password_length:
        raise _invalid(
            field, f"Password must be at least {config.min_password_length} characters long"
        )


class KeycloakSessionController(Controller):
    """Public endpoints (no access token): the plugin mounts them excluded from
    ``litestar-keycloak``'s authentication middleware.

    Keycloak errors raised here become responses through the plugin's exception handlers
    (401 bad credentials, 403 ``passwordChangeRequired``, 409, 503), see ``errors``.
    """

    path = "/"
    tags = ("auth",)

    @post("/login", status_code=200, name="keycloak:login")
    async def login(self, request: Request[Any, Any, Any], data: LoginRequest) -> SessionResponse:
        """Tokens, or ``202`` with a challenge when ``login_verification`` is on."""
        client = keycloak_admin(request)
        return await _session_response(request, await client.login(data.username, data.password))

    @post("/login/verify", status_code=200, name="keycloak:login-verify")
    async def verify_login(
        self, request: Request[Any, Any, Any], data: LoginCodeRequest
    ) -> Response[TokenResponse]:
        """Confirm the code sent at ``/login`` and get the session tokens."""
        tokens = await _login_challenges(request).verify(data.challenge_id, data.code)
        return _token_response(keycloak_admin(request).config, tokens)

    @post("/login/resend", status_code=202, name="keycloak:login-resend")
    async def resend_login_code(
        self, request: Request[Any, Any, Any], data: LoginChallengeRequest
    ) -> Response[LoginChallengeResponse]:
        """Send a new code for the same challenge; the previous one stops working."""
        return _challenge_response(await _login_challenges(request).resend(data.challenge_id))

    @post("/initial-password", status_code=200, name="keycloak:initial-password")
    async def initial_password(
        self, request: Request[Any, Any, Any], data: InitialPasswordRequest
    ) -> SessionResponse:
        """Replace the temporary password of a freshly registered account and log in."""
        client = keycloak_admin(request)
        _check_password_length(client.config, "new_password", data.new_password)
        if data.new_password == data.password:
            raise _invalid("new_password", "The new password must differ from the temporary one")
        tokens = await client.complete_initial_password(
            data.username, data.password, data.new_password
        )
        return await _session_response(request, tokens)

    @post("/refresh", status_code=200, name="keycloak:refresh")
    async def refresh(
        self, request: Request[Any, Any, Any], data: RefreshTokenRequest | None = None
    ) -> Response[TokenResponse]:
        """New access token while the Keycloak session lives; 401 once it expired or ended."""
        refresh_token = _refresh_token(request, data)
        if not refresh_token:
            raise NotAuthorizedException("No session", extra={"reason": "required"})
        client = keycloak_admin(request)
        return _token_response(client.config, await client.refresh(refresh_token))

    @post("/logout", status_code=204, name="keycloak:logout")
    async def logout(
        self, request: Request[Any, Any, Any], data: RefreshTokenRequest | None = None
    ) -> Response[None]:
        """End the Keycloak session, so its refresh token can't be used any more."""
        client = keycloak_admin(request)
        if refresh_token := _refresh_token(request, data):
            await client.logout(refresh_token)
        cookies = (
            [_refresh_cookie(client.config, "", 0)] if client.config.refresh_cookie.enabled else []
        )
        return Response(content=None, status_code=204, cookies=cookies)


class KeycloakAccountController(Controller):
    """Endpoints for an authenticated caller; registration and roles are admin-only."""

    path = "/"
    tags = ("auth",)

    @get("/me", name="keycloak:me")
    async def me(self, current_user: CurrentUser) -> UserResponse:
        return UserResponse.from_user(current_user)

    @patch("/me", name="keycloak:me-update")
    async def update_me(
        self, request: Request[Any, Any, Any], current_user: CurrentUser, data: ProfileUpdateRequest
    ) -> UserResponse:
        """Edit the caller's own name and e-mail. The current access token keeps the old
        values until it is refreshed."""
        changes = {
            key: value.strip()
            for key, value in (
                ("firstName", data.first_name),
                ("lastName", data.last_name),
                ("email", data.email),
            )
            if value is not None
        }
        if changes:
            await keycloak_admin(request).update_user(current_user.sub, **changes)
        response = UserResponse.from_user(current_user)
        response.first_name = changes.get("firstName", response.first_name)
        response.last_name = changes.get("lastName", response.last_name)
        if "email" in changes:
            response.email = changes["email"] or None
        return response

    @post("/password", status_code=204, name="keycloak:password")
    async def change_password(
        self,
        request: Request[Any, Any, Any],
        current_user: CurrentUser,
        data: PasswordChangeRequest,
    ) -> None:
        client = keycloak_admin(request)
        _check_password_length(client.config, "new_password", data.new_password)
        username = current_user.preferred_username
        if not username or not await client.check_password(username, data.current_password):
            raise _invalid("current_password", "Current password is incorrect")
        await client.set_password(current_user.sub, data.new_password)

    @get("/me/login-verification", name="keycloak:me-login-verification")
    async def login_verification(
        self, request: Request[Any, Any, Any], current_user: CurrentUser
    ) -> LoginVerificationSettings:
        """Whether the caller's logins need an e-mailed code, and if they may change it."""
        if keycloak_admin(request).config.login_verification is None:
            return LoginVerificationSettings(enabled=False, changeable=False)
        preferences = _preferences(request)
        return LoginVerificationSettings(
            enabled=await preferences.enabled(current_user.sub),
            changeable=preferences.changeable,
        )

    @put("/me/login-verification", name="keycloak:me-login-verification-update")
    async def update_login_verification(
        self,
        request: Request[Any, Any, Any],
        current_user: CurrentUser,
        data: LoginVerificationUpdate,
    ) -> LoginVerificationSettings:
        """Turn the login code on or off for the caller; needs the current password."""
        preferences = _preferences(request)
        if not preferences.changeable:
            raise NotFoundException("Login verification cannot be changed by users")
        username = current_user.preferred_username
        client = keycloak_admin(request)
        if not username or not await client.check_password(username, data.password):
            raise _invalid("password", "Password is incorrect")
        await preferences.set_enabled(current_user.sub, data.enabled)
        return LoginVerificationSettings(enabled=data.enabled, changeable=True)

    @get("/roles", name="keycloak:roles", guards=[requires_admin])
    async def roles(self, request: Request[Any, Any, Any]) -> list[RoleResponse]:
        """Roles registration may assign - whatever the realm defines (e.g. in its
        ``realm-export.json``), narrowed by ``assignable_roles`` when that is set."""
        client = keycloak_admin(request)
        assignable = client.config.assignable_roles
        return [
            RoleResponse(name=role["name"], description=role.get("description"))
            for role in await client.list_roles()
            if not assignable or role["name"] in assignable
        ]

    @post("/register", status_code=201, name="keycloak:register", guards=[requires_admin])
    async def register(
        self, request: Request[Any, Any, Any], data: RegisterRequest
    ) -> UserResponse:
        """Create a user with a temporary password and any number of realm roles."""
        client = keycloak_admin(request)
        config = client.config
        roles = list(dict.fromkeys(data.roles))
        if not roles:
            raise _invalid("roles", "At least one role is required")
        if config.assignable_roles and (
            unknown := [r for r in roles if r not in config.assignable_roles]
        ):
            raise _invalid("roles", f"Roles cannot be assigned: {', '.join(unknown)}")
        _check_password_length(config, "password", data.password)

        subject = await client.create_user(
            username=data.username,
            password=data.password,
            email=data.email,
            first_name=data.first_name,
            last_name=data.last_name,
            roles=roles,
        )
        return UserResponse(
            id=subject,
            username=data.username,
            email=data.email,
            first_name=data.first_name,
            last_name=data.last_name,
            roles=sorted(roles),
        )
