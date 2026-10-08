from collections.abc import Iterator

import pytest
from fake_keycloak import FakeKeycloak
from litestar import Litestar
from litestar.testing import TestClient
from test_plugin import create_app, error_reasons, keycloak, make_token  # noqa: F401

import litestar_keycloak_admin.challenges as challenges
from litestar_keycloak_admin import (
    KeycloakAdminConfig,
    KeycloakAdminPlugin,
    LoginCode,
    LoginVerificationConfig,
    RefreshCookieConfig,
)
from litestar_keycloak_admin.challenges import mask_email

CREDENTIALS = {"username": "alice", "password": "secret-password"}


class CodeOutbox:
    def __init__(self) -> None:
        self.sent: list[LoginCode] = []
        self.fail = False

    async def __call__(self, code: LoginCode) -> None:
        if self.fail:
            raise ConnectionError("broker is down")
        self.sent.append(code)


def tokens(**claims: str) -> dict[str, object]:
    return {
        "access_token": make_token("user", email="alice@example.com", given_name="Alice", **claims),
        "refresh_token": "refresh-1",
        "expires_in": 300,
        "refresh_expires_in": 900,
    }


def verification_app(outbox: CodeOutbox, **settings: int) -> Litestar:
    config = KeycloakAdminConfig.from_env(
        refresh_cookie=RefreshCookieConfig(secure=False),
        login_verification=LoginVerificationConfig(send_code=outbox, **settings),
    )
    return Litestar(plugins=[KeycloakAdminPlugin(config)])


@pytest.fixture
def outbox() -> CodeOutbox:
    return CodeOutbox()


@pytest.fixture
def client(keycloak: FakeKeycloak, outbox: CodeOutbox) -> Iterator[TestClient[Litestar]]:  # noqa: F811
    keycloak.token_response = (200, tokens())
    with TestClient(verification_app(outbox, resend_interval_seconds=0, max_attempts=3)) as app:
        yield app


def start(client: TestClient[Litestar]) -> str:
    response = client.post("/auth/login", json=CREDENTIALS)
    assert response.status_code == 202
    return str(response.json()["challenge_id"])


def test_login_sends_code_instead_of_tokens(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
    outbox: CodeOutbox,
) -> None:
    response = client.post("/auth/login", json=CREDENTIALS)

    assert response.status_code == 202
    body = response.json()
    assert body["destination"] == "a***@example.com"
    assert body["code_required"] is True
    assert 0 < body["expires_in"] <= 300
    assert "token" not in body and "kc_refresh" not in response.cookies
    [sent] = outbox.sent
    assert (sent.challenge_id, sent.email, sent.subject) == (
        body["challenge_id"],
        "alice@example.com",
        "user-1",
    )
    assert sent.first_name == "Alice" and len(sent.code) == 6 and sent.code.isdigit()


def test_right_code_issues_fresh_tokens_once(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
    outbox: CodeOutbox,
) -> None:
    challenge_id = start(client)
    payload = {"challenge_id": challenge_id, "code": outbox.sent[0].code}

    response = client.post("/auth/login/verify", json=payload)

    assert response.status_code == 200
    assert response.json()["token"] == tokens()["access_token"]
    assert response.cookies["kc_refresh"] == "refresh-1"
    assert keycloak.grants == ["password", "refresh_token"]
    repeated = client.post("/auth/login/verify", json=payload)
    assert repeated.status_code == 401
    assert error_reasons(repeated) == ["challengeExpired"]


def test_wrong_codes_lock_challenge_and_end_session(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
    outbox: CodeOutbox,
) -> None:
    challenge_id = start(client)
    wrong = {"challenge_id": challenge_id, "code": "not-it"}

    first = client.post("/auth/login/verify", json=wrong)
    client.post("/auth/login/verify", json=wrong)
    last = client.post("/auth/login/verify", json=wrong)

    assert first.status_code == 401
    assert first.json()["error"]["errors"][0]["location"] == "code"
    assert error_reasons(first) == ["invalidCode"]
    assert last.status_code == 429 and error_reasons(last) == ["tooManyAttempts"]
    assert keycloak.logged_out == ["refresh-1"]
    right = {"challenge_id": challenge_id, "code": outbox.sent[0].code}
    assert error_reasons(client.post("/auth/login/verify", json=right)) == ["challengeExpired"]


def test_resend_replaces_code(client: TestClient[Litestar], outbox: CodeOutbox) -> None:
    challenge_id = start(client)

    response = client.post("/auth/login/resend", json={"challenge_id": challenge_id})

    assert response.status_code == 202
    old, new = (code.code for code in outbox.sent)
    if old != new:
        stale = client.post("/auth/login/verify", json={"challenge_id": challenge_id, "code": old})
        assert error_reasons(stale) == ["invalidCode"]
    fresh = client.post("/auth/login/verify", json={"challenge_id": challenge_id, "code": new})
    assert fresh.status_code == 200


def test_resend_limits(keycloak: FakeKeycloak, outbox: CodeOutbox) -> None:  # noqa: F811
    keycloak.token_response = (200, tokens())
    with TestClient(verification_app(outbox, resend_interval_seconds=60)) as client:
        challenge_id = start(client)
        too_soon = client.post("/auth/login/resend", json={"challenge_id": challenge_id})

    assert too_soon.status_code == 429
    assert error_reasons(too_soon) == ["resendTooSoon"]
    assert 0 < int(too_soon.headers["Retry-After"]) <= 60

    with TestClient(verification_app(outbox, resend_interval_seconds=0, max_sends=2)) as client:
        challenge_id = start(client)
        statuses = [
            client.post("/auth/login/resend", json={"challenge_id": challenge_id}).status_code
            for _ in range(2)
        ]
    assert statuses == [202, 429]


def test_expired_challenge_is_rejected(
    client: TestClient[Litestar], outbox: CodeOutbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    challenge_id = start(client)
    later = challenges.time.time() + 301
    monkeypatch.setattr(challenges.time, "time", lambda: later)

    response = client.post(
        "/auth/login/verify", json={"challenge_id": challenge_id, "code": outbox.sent[0].code}
    )
    assert response.status_code == 401 and error_reasons(response) == ["challengeExpired"]


def test_failed_delivery_ends_session(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
    outbox: CodeOutbox,
) -> None:
    outbox.fail = True

    response = client.post("/auth/login", json=CREDENTIALS)

    assert response.status_code == 503 and error_reasons(response) == ["codeDeliveryFailed"]
    assert keycloak.logged_out == ["refresh-1"]


def test_account_without_email_cannot_log_in(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
) -> None:
    keycloak.token_response = (200, {**tokens(), "access_token": make_token("user")})

    response = client.post("/auth/login", json=CREDENTIALS)

    assert response.status_code == 403 and error_reasons(response) == ["emailRequired"]
    assert keycloak.logged_out == ["refresh-1"]


def test_wrong_password_sends_no_code(
    keycloak: FakeKeycloak,  # noqa: F811
    client: TestClient[Litestar],
    outbox: CodeOutbox,
) -> None:
    keycloak.token_response = (400, {"error": "invalid_grant"})

    assert client.post("/auth/login", json=CREDENTIALS).status_code == 401
    assert outbox.sent == []


def test_verify_is_not_found_without_verification(keycloak: FakeKeycloak) -> None:  # noqa: F811
    with TestClient(create_app()) as client:
        response = client.post("/auth/login/verify", json={"challenge_id": "x", "code": "1"})

    assert response.status_code == 404


@pytest.mark.parametrize(
    "settings",
    [{"code_length": 3}, {"ttl_seconds": 0}, {"max_attempts": 0}, {"resend_interval_seconds": -1}],
)
def test_invalid_settings_are_rejected(outbox: CodeOutbox, settings: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        LoginVerificationConfig(send_code=outbox, **settings)


def test_mask_email() -> None:
    assert mask_email("bob@example.com") == "b***@example.com"
    assert mask_email("broken") == "***"
