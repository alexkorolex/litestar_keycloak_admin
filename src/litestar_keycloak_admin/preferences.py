"""Each user's choice whether to confirm logins with a code."""

import logging

from litestar_keycloak_admin.client import KeycloakAdminClient
from litestar_keycloak_admin.exceptions import KeycloakClientError
from litestar_keycloak_admin.verification import LoginVerificationConfig

logger = logging.getLogger(__name__)

ENABLED = "on"
DISABLED = "off"


class LoginVerificationPreferences:
    """Reads and stores the choice in a Keycloak user attribute.

    Without ``user_choice`` the code is required from everyone. A choice that cannot be
    read (Keycloak unavailable) also requires it: a failure must not weaken the login.
    """

    def __init__(self, config: LoginVerificationConfig, client: KeycloakAdminClient) -> None:
        self._config = config
        self._client = client

    @property
    def changeable(self) -> bool:
        return self._config.user_choice

    async def enabled(self, subject: str) -> bool:
        if not self._config.user_choice:
            return True
        try:
            user = await self._client.get_user(subject)
        except KeycloakClientError:
            logger.warning("Login verification choice of %s is unknown, code required", subject)
            return True
        values = ((user or {}).get("attributes") or {}).get(self._config.user_attribute) or []
        return DISABLED not in values

    async def set_enabled(self, subject: str, enabled: bool) -> None:
        value = ENABLED if enabled else DISABLED
        await self._client.set_user_attribute(subject, self._config.user_attribute, [value])
        logger.info("Login verification of %s turned %s", subject, value)
