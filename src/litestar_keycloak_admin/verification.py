"""Settings and data of the optional second login step: a one-time code sent to the user."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class LoginCode:
    """A code the application has to deliver, e.g. by e-mail."""

    challenge_id: str
    subject: str
    """The Keycloak subject id (``sub``) of the user logging in."""
    email: str
    code: str
    expires_in: int
    """Seconds until the challenge, and so the code, expires."""
    username: str | None = None
    first_name: str | None = None


class LoginCodeSender(Protocol):
    """Delivers a login code; raising makes the login fail with ``codeDeliveryFailed``."""

    async def __call__(self, code: LoginCode) -> None: ...


@dataclass(frozen=True, slots=True)
class LoginVerificationConfig:
    """Turns on the second login step.

    ``/login`` and ``/initial-password`` then check the password, send a code through
    ``send_code`` and answer ``202`` with a ``challenge_id`` instead of tokens. The tokens
    are issued by ``/login/verify`` for the right code; ``/login/resend`` sends a new one.
    """

    send_code: LoginCodeSender
    store: str = "keycloak_login_challenges"
    """Name of the Litestar store holding pending challenges. Register a shared store (e.g.
    Redis) under this name when the app runs several workers - the default one is in memory."""
    code_length: int = 6
    ttl_seconds: int = 300
    max_attempts: int = 5
    """Wrong codes allowed per challenge; the last one ends the Keycloak session."""
    resend_interval_seconds: int = 60
    max_sends: int = 4
    """Codes sent per challenge, the first one included."""

    def __post_init__(self) -> None:
        if not 4 <= self.code_length <= 10:
            raise ValueError("code_length must be between 4 and 10")
        for name in ("ttl_seconds", "max_attempts", "max_sends"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.resend_interval_seconds < 0:
            raise ValueError("resend_interval_seconds must not be negative")
