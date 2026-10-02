class KeycloakClientError(RuntimeError):
    """Base class for errors raised by ``KeycloakAdminClient``.

    Separate from ``litestar_keycloak.exceptions.KeycloakError``, which covers token
    validation and is handled by that package.
    """


class KeycloakUnavailableError(KeycloakClientError):
    """Keycloak could not be reached (or answered with a server error) - not the caller's
    fault, so it must never be reported as wrong credentials."""


class KeycloakLoginError(KeycloakClientError):
    """Keycloak rejected the credentials or the refresh token."""


class PasswordChangeRequiredError(KeycloakLoginError):
    """The credentials are right, but the account still has a temporary password."""


class KeycloakAdminError(KeycloakClientError):
    """An Admin REST API call failed."""

    def __init__(self, message: str, *, conflict: bool = False, invalid: bool = False) -> None:
        super().__init__(message)
        self.conflict = conflict
        """The user (or e-mail) already exists, or the action doesn't apply to it."""
        self.invalid = invalid
        """Keycloak refused the input itself, e.g. an unknown role or a password that breaks
        the realm's policy."""
