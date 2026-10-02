import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jwt
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric import rsa
from fake_keycloak import REALM, FakeKeycloak
from httpx import Response
from litestar import Litestar, get
from litestar.cli.main import litestar_group
from litestar.testing import TestClient
from litestar_keycloak import CurrentUser, MatchStrategy, require_roles
from litestar_keycloak_admin import KeycloakAdminConfig, KeycloakAdminPlugin, RefreshCookieConfig

ISSUER = f"https://sso.example.com/realms/{REALM}"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_token(*roles: str, **claims: Any) -> str:  # noqa: ANN401
    now = int(time.time())
    payload = {
        "sub": "user-1",
        "iss": ISSUER,
        "aud": "backend",
        "typ": "Bearer",
        "iat": now,
        "exp": now + 300,
        "preferred_username": "alice",
        "realm_access": {"roles": list(roles)},
        **claims,
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": "key-1"})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def error_reasons(response: Response) -> list[str]:
    return [item["reason"] for item in response.json()["error"]["errors"]]


@get(
    "/dispatch",
    guards=[require_roles("dispatcher", "admin", strategy=MatchStrategy.ANY)],
    sync_to_thread=False,
)
def dispatch(current_user: CurrentUser) -> dict[str, str]:
    return {"subject": current_user.sub}


def create_app() -> Litestar:
    """Configured from the environment, like a real app (see the ``keycloak`` fixture)."""
    config = KeycloakAdminConfig.from_env(refresh_cookie=RefreshCookieConfig(secure=False))
    return Litestar(route_handlers=[dispatch], plugins=[KeycloakAdminPlugin(config)])


@pytest.fixture
def keycloak(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeKeycloak]:
    with FakeKeycloak(PRIVATE_KEY.public_key()) as fake:
        for name, value in {
            "INTERNAL_URL": fake.url,
            "REALM": REALM,
            "CLIENT_ID": "backend",
            "CLIENT_SECRET": "secret",
            "ISSUER": ISSUER,
            "ADMIN": "root",
            "ADMIN_PASSWORD": "root",
        }.items():
            monkeypatch.setenv(f"KEYCLOAK_{name}", value)
        yield fake


@pytest.fixture
def client(keycloak: FakeKeycloak) -> Iterator[TestClient[Litestar]]:
    with TestClient(create_app()) as test_client:
        yield test_client


def test_me_returns_token_user_with_all_roles(client: TestClient[Litestar]) -> None:
    response = client.get("/auth/me", headers=bearer(make_token("user", "dispatcher", email="a@example.com")))

    assert response.status_code == 200
    assert response.json() == {
        "id": "user-1",
        "username": "alice",
        "email": "a@example.com",
        "first_name": None,
        "last_name": None,
        "roles": ["dispatcher", "user"],
    }


@pytest.mark.parametrize(
    "headers",
    [
        {},
        bearer("not-a-jwt"),
        bearer(make_token("user", exp=int(time.time()) - 10)),
        bearer(make_token("user", iss="https://evil.example.com/realms/demo")),
        bearer(make_token("user", aud="someone-else", azp="someone-else")),
    ],
)
def test_me_rejects_missing_or_invalid_token(client: TestClient[Litestar], headers: dict[str, str]) -> None:
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_any_realm_role_can_guard_a_route(client: TestClient[Litestar]) -> None:
    assert client.get("/dispatch", headers=bearer(make_token("user"))).status_code == 403
    assert client.get("/dispatch", headers=bearer(make_token("dispatcher"))).status_code == 200
    assert client.get("/dispatch", headers=bearer(make_token("admin", "user"))).status_code == 200


def test_login_needs_no_token_and_keeps_refresh_token_in_cookie(
    keycloak: FakeKeycloak, client: TestClient[Litestar]
) -> None:
    keycloak.token_response = (
        200,
        {"access_token": "access", "refresh_token": "refresh", "expires_in": 300, "refresh_expires_in": 900},
    )

    response = client.post("/auth/login", json={"username": "alice", "password": "secret-password"})

    assert response.status_code == 200
    assert response.json() == {
        "token": "access",
        "expires_in": 300,
        "refresh_expires_in": 900,
        "refresh_token": None,
    }
    assert response.cookies["kc_refresh"] == "refresh"


@pytest.mark.parametrize(
    ("description", "status", "reason"),
    [
        ("Invalid user credentials", 401, "authError"),
        ("Account is not fully set up", 403, "passwordChangeRequired"),
    ],
)
def test_login_errors(
    keycloak: FakeKeycloak, client: TestClient[Litestar], description: str, status: int, reason: str
) -> None:
    keycloak.token_response = (400, {"error": "invalid_grant", "error_description": description})

    response = client.post("/auth/login", json={"username": "alice", "password": "wrong-password"})

    assert response.status_code == status
    assert error_reasons(response) == [reason]


def test_roles_lists_realm_roles_without_built_ins(client: TestClient[Litestar]) -> None:
    response = client.get("/auth/roles", headers=bearer(make_token("admin")))

    assert response.status_code == 200
    assert [role["name"] for role in response.json()] == ["admin", "dispatcher", "user"]


def test_admin_registers_user_with_several_roles(
    keycloak: FakeKeycloak, client: TestClient[Litestar]
) -> None:
    payload = {"username": "bob", "password": "temporary-1", "roles": ["user", "dispatcher"]}

    response = client.post("/auth/register", json=payload, headers=bearer(make_token("admin")))

    assert response.status_code == 201
    assert response.json()["roles"] == ["dispatcher", "user"]
    assert keycloak.created[0]["requiredActions"] == ["UPDATE_PASSWORD"]
    assert keycloak.assigned == ["user", "dispatcher"]


def test_register_rejects_role_missing_from_realm(
    keycloak: FakeKeycloak, client: TestClient[Litestar]
) -> None:
    payload = {"username": "bob", "password": "temporary-1", "roles": ["user", "superuser"]}

    response = client.post("/auth/register", json=payload, headers=bearer(make_token("admin")))

    assert response.status_code == 400
    assert keycloak.created == []


def test_register_and_roles_are_admin_only(client: TestClient[Litestar]) -> None:
    user = bearer(make_token("user", "dispatcher"))
    payload = {"username": "bob", "password": "temporary-1", "roles": ["user"]}
    assert client.post("/auth/register", json=payload, headers=user).status_code == 403
    assert client.get("/auth/roles", headers=user).status_code == 403


def test_cli_creates_user(keycloak: FakeKeycloak) -> None:
    result = CliRunner().invoke(
        litestar_group,
        [
            "--app-dir",
            str(Path(__file__).parent),
            "--app",
            "test_plugin:create_app",
            "keycloak",
            "create-user",
            "root",
            "--role",
            "admin",
            "--role",
            "dispatcher",
            "--password",
            "temporary-1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert keycloak.created[0]["username"] == "root"
    assert keycloak.assigned == ["admin", "dispatcher"]


def test_missing_token_error_format(client: TestClient[Litestar]) -> None:
    response = client.get("/auth/me")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == {
        "error": {
            "errors": [
                {
                    "domain": "global",
                    "reason": "required",
                    "message": "Authentication required",
                    "locationType": "header",
                    "location": "Authorization",
                }
            ],
            "code": 401,
            "message": "Authentication required",
        }
    }


def test_expired_token_and_missing_role_reasons(client: TestClient[Litestar]) -> None:
    expired = client.get("/auth/me", headers=bearer(make_token("user", exp=int(time.time()) - 10)))
    assert error_reasons(expired) == ["expired"]

    forbidden = client.get("/dispatch", headers=bearer(make_token("user")))
    assert forbidden.json()["error"]["code"] == 403
    assert error_reasons(forbidden) == ["insufficientPermissions"]


def test_validation_errors_point_at_fields(client: TestClient[Litestar]) -> None:
    response = client.post("/auth/login", json={"username": 1})

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "errors": [
                {
                    "domain": "global",
                    "reason": "invalidParameter",
                    "message": "Expected `str`, got `int`",
                    "locationType": "body",
                    "location": "username",
                }
            ],
            "code": 400,
            "message": "Expected `str`, got `int`",
        }
    }


def test_short_password_points_at_field(client: TestClient[Litestar]) -> None:
    payload = {"username": "bob", "password": "short", "roles": ["user"]}

    response = client.post("/auth/register", json=payload, headers=bearer(make_token("admin")))

    assert response.status_code == 400
    assert response.json()["error"]["errors"] == [
        {
            "domain": "global",
            "reason": "invalidParameter",
            "message": "Password must be at least 8 characters long",
            "locationType": "body",
            "location": "password",
        }
    ]


def test_unknown_role_reason(client: TestClient[Litestar]) -> None:
    payload = {"username": "bob", "password": "temporary-1", "roles": ["superuser"]}

    response = client.post("/auth/register", json=payload, headers=bearer(make_token("admin")))

    assert response.status_code == 400
    assert error_reasons(response) == ["invalid"]
