"""Pending second login steps, kept in a Litestar store until the code is confirmed."""

import base64
import hashlib
import hmac
import json
import logging
import math
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any

from litestar.stores.base import Store

from litestar_keycloak_admin.client import KeycloakAdminClient
from litestar_keycloak_admin.exceptions import KeycloakLoginError, LoginChallengeError
from litestar_keycloak_admin.verification import LoginCode, LoginVerificationConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LoginChallenge:
    """What the client learns about a started challenge - never the code itself."""

    challenge_id: str
    expires_in: int
    destination: str
    """The masked e-mail the code went to, e.g. ``a***@example.com``."""


@dataclass(slots=True)
class _Record:
    tokens: dict[str, Any]
    subject: str
    email: str
    username: str | None
    first_name: str | None
    code_hash: str
    expires_at: float
    sent_at: float
    attempts: int = 0
    sends: int = 1


class LoginChallenges:
    """Issues, checks and resends login codes.

    Keycloak tokens of the already checked password wait in the store and are released
    only for the right code, so a password alone never yields a session. A challenge that
    is used up, or has too many wrong codes, ends that Keycloak session.
    """

    def __init__(
        self, config: LoginVerificationConfig, client: KeycloakAdminClient, store: Store
    ) -> None:
        self._config = config
        self._client = client
        self._store = store

    async def start(self, tokens: dict[str, Any]) -> LoginChallenge:
        claims = unverified_claims(str(tokens["access_token"]))
        email = claims.get("email")
        if not email:
            await self._end_session(tokens)
            raise LoginChallengeError(
                "The account has no e-mail to send the login code to",
                reason="emailRequired",
                status_code=403,
            )
        challenge_id = secrets.token_urlsafe(32)
        code = self._new_code()
        now = time.time()
        record = _Record(
            tokens=tokens,
            subject=str(claims.get("sub") or ""),
            email=str(email),
            username=claims.get("preferred_username"),
            first_name=claims.get("given_name"),
            code_hash=_hash(challenge_id, code),
            expires_at=now + self._config.ttl_seconds,
            sent_at=now,
        )
        await self._save(challenge_id, record)
        await self._deliver(challenge_id, record, code)
        return self._challenge(challenge_id, record)

    async def verify(self, challenge_id: str, code: str) -> dict[str, Any]:
        record = await self._load(challenge_id)
        if hmac.compare_digest(record.code_hash, _hash(challenge_id, code.strip())):
            await self._store.delete(challenge_id)
            return await self._fresh_tokens(record.tokens)
        record.attempts += 1
        attempts_left = self._config.max_attempts - record.attempts
        if attempts_left <= 0:
            await self._drop(challenge_id, record)
            logger.warning("Login challenge locked after wrong codes: %s", record.subject)
            raise LoginChallengeError(
                "Too many wrong codes, log in again", reason="tooManyAttempts", status_code=429
            )
        await self._save(challenge_id, record)
        raise LoginChallengeError(
            f"Invalid code, {attempts_left} attempt(s) left",
            reason="invalidCode",
            status_code=401,
            location="code",
        )

    async def resend(self, challenge_id: str) -> LoginChallenge:
        record = await self._load(challenge_id)
        if record.sends >= self._config.max_sends:
            raise LoginChallengeError(
                "No more codes can be sent, log in again", reason="tooManySends", status_code=429
            )
        retry_at = record.sent_at + self._config.resend_interval_seconds
        if time.time() < retry_at:
            wait = max(1, math.ceil(retry_at - time.time()))
            raise LoginChallengeError(
                f"A new code can be requested in {wait} s",
                reason="resendTooSoon",
                status_code=429,
                retry_after=wait,
            )
        code = self._new_code()
        record.code_hash = _hash(challenge_id, code)
        record.sends += 1
        record.sent_at = time.time()
        await self._save(challenge_id, record)
        await self._deliver(challenge_id, record, code)
        return self._challenge(challenge_id, record)

    async def _deliver(self, challenge_id: str, record: _Record, code: str) -> None:
        delivery = LoginCode(
            challenge_id=challenge_id,
            subject=record.subject,
            email=record.email,
            code=code,
            expires_in=_remaining(record),
            username=record.username,
            first_name=record.first_name,
        )
        try:
            await self._config.send_code(delivery)
        except Exception as exc:
            logger.exception("Could not send a login code to %s", record.subject)
            await self._drop(challenge_id, record)
            raise LoginChallengeError(
                "Could not send the login code, try again later",
                reason="codeDeliveryFailed",
                status_code=503,
            ) from exc

    async def _fresh_tokens(self, tokens: dict[str, Any]) -> dict[str, Any]:
        """The access token may have expired while the user read the e-mail."""
        refresh_token = tokens.get("refresh_token")
        if not refresh_token:
            return tokens
        try:
            return await self._client.refresh(str(refresh_token))
        except KeycloakLoginError as exc:
            raise _expired() from exc

    async def _load(self, challenge_id: str) -> _Record:
        raw = await self._store.get(challenge_id) if challenge_id else None
        if raw is None:
            raise _expired()
        record = _Record(**json.loads(raw))
        if _remaining(record) <= 0:
            await self._drop(challenge_id, record)
            raise _expired()
        return record

    async def _save(self, challenge_id: str, record: _Record) -> None:
        await self._store.set(
            challenge_id, json.dumps(asdict(record)), expires_in=max(1, _remaining(record))
        )

    async def _drop(self, challenge_id: str, record: _Record) -> None:
        await self._store.delete(challenge_id)
        await self._end_session(record.tokens)

    async def _end_session(self, tokens: dict[str, Any]) -> None:
        if refresh_token := tokens.get("refresh_token"):
            await self._client.logout(str(refresh_token))

    def _new_code(self) -> str:
        length = self._config.code_length
        return f"{secrets.randbelow(10**length):0{length}d}"

    @staticmethod
    def _challenge(challenge_id: str, record: _Record) -> LoginChallenge:
        return LoginChallenge(
            challenge_id=challenge_id,
            expires_in=_remaining(record),
            destination=mask_email(record.email),
        )


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"


def _hash(challenge_id: str, code: str) -> str:
    return hmac.new(challenge_id.encode(), code.encode(), hashlib.sha256).hexdigest()


def _remaining(record: _Record) -> int:
    return int(record.expires_at - time.time())


def _expired() -> LoginChallengeError:
    return LoginChallengeError(
        "The login code has expired, log in again", reason="challengeExpired", status_code=401
    )


def unverified_claims(access_token: str) -> dict[str, Any]:
    """Claims of a token the client has just received from Keycloak's token endpoint
    itself, so there is nobody to forge it - no signature check needed here."""
    try:
        payload = access_token.split(".")[1]
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as exc:
        raise KeycloakLoginError("Keycloak returned a malformed access token") from exc
    return decoded if isinstance(decoded, dict) else {}
