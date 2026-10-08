from collections.abc import Iterator

import pytest
from fake_keycloak import FakeKeycloak
from litestar import Litestar
from litestar.testing import TestClient
from test_login_verification import CREDENTIALS, CodeOutbox, tokens, verification_app
from test_plugin import bearer, create_app, keycloak, make_token  # noqa: F401

USER = {
    "id": "user-1",
    "username": "alice",
    "email": "alice@example.com",
    "attributes": {"organization_roles": ["org:15:employee"]},
}


@pytest.fixture
def outbox() -> CodeOutbox:
    return CodeOutbox()


@pytest.fixture
def client(keycloak: FakeKeycloak, outbox: CodeOutbox) -> Iterator[TestClient[Litestar]]:  # noqa: F811
    keycloak.token_response = (200, tokens())
    keycloak.users["user-1"] = {**USER, "attributes": dict(USER["attributes"])}
    with TestClient(verification_app(outbox, user_choice=True)) as app:
        yield app


def turn(client: TestClient[Litestar], enabled: bool, password: str = "secret") -> object:
    return client.put(
        "/auth/me/login-verification",
        json={"enabled": enabled, "password": password},
        headers=bearer(make_token("user")),
    )


def test_code_is_required_until_the_user_turns_it_off(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
    outbox: CodeOutbox,
) -> None:
    assert client.post("/auth/login", json=CREDENTIALS).status_code == 202

    response = turn(client, enabled=False)

    assert response.status_code == 200
    assert response.json() == {"enabled": False, "changeable": True}
    login = client.post("/auth/login", json=CREDENTIALS)
    assert login.status_code == 200 and "token" in login.json()
    assert len(outbox.sent) == 1


def test_choice_keeps_other_attributes_and_profile(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
) -> None:
    turn(client, enabled=False)

    stored = keycloak.users["user-1"]
    assert stored["email"] == "alice@example.com"
    assert stored["attributes"] == {
        "organization_roles": ["org:15:employee"],
        "login_verification": ["off"],
    }
    turn(client, enabled=True)
    assert keycloak.users["user-1"]["attributes"]["login_verification"] == ["on"]


def test_wrong_password_does_not_change_the_choice(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
) -> None:
    keycloak.token_response = (400, {"error": "invalid_grant"})

    response = turn(client, enabled=False, password="wrong")

    assert response.status_code == 400
    assert response.json()["error"]["errors"][0]["location"] == "password"
    assert "login_verification" not in keycloak.users["user-1"]["attributes"]


def test_settings_of_the_caller(client: TestClient[Litestar]) -> None:
    response = client.get("/auth/me/login-verification", headers=bearer(make_token("user")))

    assert response.json() == {"enabled": True, "changeable": True}


def test_unreadable_choice_still_requires_code(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
) -> None:
    keycloak.users["user-1"]["attributes"]["login_verification"] = ["off"]
    keycloak.user_status = 500

    assert client.post("/auth/login", json=CREDENTIALS).status_code == 202


def test_without_user_choice_the_attribute_is_ignored(
    keycloak: FakeKeycloak,  # noqa: F811
    outbox: CodeOutbox,
) -> None:
    keycloak.token_response = (200, tokens())
    keycloak.users["user-1"] = {**USER, "attributes": {"login_verification": ["off"]}}
    with TestClient(verification_app(outbox)) as client:
        login = client.post("/auth/login", json=CREDENTIALS)
        settings = client.get("/auth/me/login-verification", headers=bearer(make_token("user")))
        update = turn(client, enabled=False)

    assert login.status_code == 202
    assert settings.json() == {"enabled": True, "changeable": False}
    assert update.status_code == 404


def test_settings_without_verification(keycloak: FakeKeycloak) -> None:  # noqa: F811
    with TestClient(create_app()) as client:
        response = client.get("/auth/me/login-verification", headers=bearer(make_token("user")))

    assert response.json() == {"enabled": False, "changeable": False}
