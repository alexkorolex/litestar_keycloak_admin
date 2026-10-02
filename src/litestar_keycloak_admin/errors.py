"""One error format for every response, in the style of Google's JSON APIs::

    {
      "error": {
        "errors": [
          {
            "domain": "global",
            "reason": "invalidParameter",
            "message": "Expected `str`, got `int`",
            "locationType": "body",
            "location": "username"
          }
        ],
        "code": 400,
        "message": "Expected `str`, got `int`"
      }
    }

``code`` repeats the HTTP status, ``message`` is for humans, and each item's ``reason`` is the
stable, machine-readable part clients should branch on.
"""

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from litestar import MediaType, Request, Response
from litestar.exceptions import HTTPException
from litestar.status_codes import HTTP_500_INTERNAL_SERVER_ERROR
from litestar_keycloak.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InsufficientScopeError,
    KeycloakBackendError,
    KeycloakError,
    MissingTokenError,
    TokenExpiredError,
)

from litestar_keycloak_admin.exceptions import (
    KeycloakAdminError,
    KeycloakClientError,
    KeycloakLoginError,
    KeycloakUnavailableError,
    PasswordChangeRequiredError,
)

logger = logging.getLogger(__name__)

REASONS: Mapping[int, str] = {
    400: "badRequest",
    401: "authError",
    403: "forbidden",
    404: "notFound",
    405: "methodNotAllowed",
    409: "conflict",
    413: "requestTooLarge",
    415: "unsupportedMediaType",
    429: "rateLimitExceeded",
    500: "internalError",
    502: "backendError",
    503: "backendError",
}
"""Default ``reason`` for a status code, when nothing more specific is known."""


@dataclass(frozen=True, slots=True)
class ErrorItem:
    """One entry of ``error.errors`` in an error response."""

    reason: str
    """Stable, machine-readable cause, e.g. ``invalidParameter`` or ``expired``."""
    message: str
    location: str | None = None
    """What the error is about, e.g. a field name or ``Authorization``."""
    location_type: str | None = None
    """Where ``location`` is: ``body``, ``query``, ``path``, ``header``, ``cookie``."""
    domain: str = "global"

    def to_dict(self) -> dict[str, str]:
        item = {"domain": self.domain, "reason": self.reason, "message": self.message}
        if self.location_type is not None:
            item["locationType"] = self.location_type
        if self.location is not None:
            item["location"] = self.location
        return item


def error_response(
    status_code: int,
    message: str,
    errors: Sequence[ErrorItem] = (),
    *,
    headers: Mapping[str, str] | None = None,
) -> Response[dict[str, Any]]:
    """Build an error response; without ``errors``, one item with the status's default reason."""
    items = errors or [ErrorItem(reason=REASONS.get(status_code, "unknown"), message=message)]
    return Response(
        content={
            "error": {
                "errors": [item.to_dict() for item in items],
                "code": status_code,
                "message": message,
            }
        },
        status_code=status_code,
        media_type=MediaType.JSON,
        headers=dict(headers) if headers else None,
    )


def handle_http_exception(
    _: Request[Any, Any, Any], exc: HTTPException
) -> Response[dict[str, Any]]:
    """Litestar's own errors and any ``HTTPException`` raised by handlers.

    Validation errors (``extra`` as a list of ``{"message", "key", "source"}``) become one
    ``invalidParameter`` item per field. ``extra={"reason": ...}`` overrides the default reason.
    """
    extra = exc.extra
    if (
        isinstance(extra, list)
        and extra
        and all(isinstance(item, dict) and "message" in item for item in extra)
    ):
        items = [
            ErrorItem(
                reason="invalidParameter",
                message=str(item["message"]),
                location=item.get("key"),
                location_type=item.get("source"),
            )
            for item in extra
        ]
        return error_response(exc.status_code, items[0].message, items, headers=exc.headers)
    reason = extra.get("reason") if isinstance(extra, dict) else None
    items = [ErrorItem(reason=str(reason), message=exc.detail)] if reason else []
    return error_response(exc.status_code, exc.detail, items, headers=exc.headers)


def handle_internal_error(_: Request[Any, Any, Any], exc: Exception) -> Response[dict[str, Any]]:
    """Unhandled exceptions: never leak their text to the client."""
    if isinstance(exc, HTTPException):
        return handle_http_exception(_, exc)
    return error_response(HTTP_500_INTERNAL_SERVER_ERROR, "Internal Server Error")


def handle_keycloak_client_error(
    _: Request[Any, Any, Any], exc: KeycloakClientError
) -> Response[dict[str, Any]]:
    """Errors of ``KeycloakAdminClient``, wherever they're raised from."""
    if isinstance(exc, KeycloakUnavailableError):
        return error_response(503, "Authentication service is unavailable")
    if isinstance(exc, PasswordChangeRequiredError):
        message = "The temporary password must be changed"
        return error_response(
            403, message, [ErrorItem(reason="passwordChangeRequired", message=message)]
        )
    if isinstance(exc, KeycloakLoginError):
        return error_response(401, str(exc))
    if isinstance(exc, KeycloakAdminError) and exc.invalid:
        return error_response(400, str(exc), [ErrorItem(reason="invalid", message=str(exc))])
    if isinstance(exc, KeycloakAdminError) and exc.conflict:
        return error_response(409, str(exc))
    return error_response(502, str(exc))


def handle_token_error(_: Request[Any, Any, Any], exc: KeycloakError) -> Response[dict[str, Any]]:
    """Errors of ``litestar-keycloak`` (token validation and its role/scope guards)."""
    if isinstance(exc, AuthenticationError):
        if isinstance(exc, MissingTokenError):
            message, reason = "Authentication required", "required"
        elif isinstance(exc, TokenExpiredError):
            message, reason = "Token expired", "expired"
        else:
            # Keep the details (expected issuer, audiences) out of the response, as litestar-keycloak does.
            logger.info("Authentication failed: %s: %s", type(exc).__name__, exc)
            message, reason = "Invalid token", "authError"
        item = ErrorItem(
            reason=reason, message=message, location="Authorization", location_type="header"
        )
        return error_response(401, message, [item], headers={"WWW-Authenticate": "Bearer"})
    if isinstance(exc, AuthorizationError):
        reason = (
            "insufficientScope"
            if isinstance(exc, InsufficientScopeError)
            else "insufficientPermissions"
        )
        return error_response(403, str(exc), [ErrorItem(reason=reason, message=str(exc))])
    if isinstance(exc, KeycloakBackendError):
        logger.warning("Cannot validate a token: %s", exc)
        return error_response(503, "Authentication service is unavailable")
    return error_response(500, "Internal Server Error")


TOKEN_ERROR_TYPES = (AuthenticationError, AuthorizationError, KeycloakBackendError, KeycloakError)
"""Keys ``litestar-keycloak`` registers its own handlers under."""
