import asyncio

import click
from litestar import Litestar, Router
from litestar.config.app import AppConfig
from litestar.datastructures import State
from litestar.di import Provide
from litestar.exceptions import HTTPException
from litestar.plugins import CLIPlugin, InitPluginProtocol
from litestar.types import ExceptionHandlersMap
from litestar_keycloak import KeycloakPlugin
from litestar_keycloak.exceptions import exception_handlers as token_exception_handlers

from litestar_keycloak_admin.client import KeycloakAdminClient
from litestar_keycloak_admin.config import KeycloakAdminConfig
from litestar_keycloak_admin.controller import (
    STATE_KEY,
    KeycloakAccountController,
    KeycloakSessionController,
)
from litestar_keycloak_admin.errors import (
    handle_http_exception,
    handle_keycloak_client_error,
    handle_token_error,
)
from litestar_keycloak_admin.exceptions import KeycloakAdminError, KeycloakClientError


def provide_keycloak_admin(state: State) -> KeycloakAdminClient:
    return state[STATE_KEY]


class KeycloakAdminPlugin(InitPluginProtocol, CLIPlugin):
    """Keycloak authentication plus user management for a Litestar app.

    Installs ``litestar_keycloak.KeycloakPlugin`` for ``config.keycloak`` (token validation,
    ``current_user``, ``require_roles``) - don't add that plugin separately - and on top of it:

    - session endpoints at ``auth_path`` without a token: login, initial-password, refresh, logout;
    - account endpoints with a token: ``/me``, ``/password``; admin-only ``/roles``, ``/register``;
    - the ``keycloak_admin`` dependency (``KeycloakAdminClient``);
    - one error format (see ``errors``) for its endpoints and for token/role errors;
    - ``litestar keycloak create-user`` to create users (e.g. the first admin) from the CLI.
    """

    def __init__(
        self, config: KeycloakAdminConfig, *, client: KeycloakAdminClient | None = None
    ) -> None:
        self.config = config
        self.client = client or KeycloakAdminClient(config)
        self._keycloak = KeycloakPlugin(config.keycloak)

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        own_handlers = set(app_config.exception_handlers)
        app_config = self._keycloak.on_app_init(app_config)
        # Same error format for token errors - unless the application brought its own handlers.
        for exc_type in token_exception_handlers:
            if exc_type not in own_handlers:
                app_config.exception_handlers[exc_type] = handle_token_error

        app_config.state[STATE_KEY] = self.client
        app_config.on_shutdown.append(self.client.close)
        app_config.dependencies.setdefault(
            "keycloak_admin", Provide(provide_keycloak_admin, sync_to_thread=False)
        )
        app_config.signature_namespace.update({"KeycloakAdminClient": KeycloakAdminClient})
        app_config.exception_handlers.setdefault(KeycloakClientError, handle_keycloak_client_error)

        public = {self.config.keycloak.exclude_opt_key: True}
        # The package's own endpoints answer in the package's error format whatever the app uses;
        # ``errors.handle_http_exception`` can be registered app-wide to match.
        own_format: ExceptionHandlersMap = {HTTPException: handle_http_exception}
        app_config.route_handlers.extend(
            [
                Router(
                    path=self.config.auth_path,
                    route_handlers=[KeycloakSessionController],
                    opt=public,
                    exception_handlers=own_format,
                ),
                Router(
                    path=self.config.auth_path,
                    route_handlers=[KeycloakAccountController],
                    exception_handlers=own_format,
                ),
            ]
        )
        return app_config

    def on_cli_init(self, cli: click.Group) -> None:
        @cli.group(name="keycloak", help="Manage Keycloak users.")
        def keycloak_group() -> None: ...

        @keycloak_group.command(name="create-user", help="Create a user with a temporary password.")
        @click.argument("username")
        @click.option(
            "--role", "roles", multiple=True, required=True, help="Realm role; repeat for several."
        )
        @click.option(
            "--password", prompt=True, hide_input=True, envvar="KEYCLOAK_NEW_USER_PASSWORD"
        )
        @click.option("--email", default=None)
        @click.option("--first-name", default=None)
        @click.option("--last-name", default=None)
        @click.option(
            "--exist-ok", is_flag=True, help="Exit successfully if the user already exists."
        )
        def create_user(
            app: Litestar,
            username: str,
            roles: tuple[str, ...],
            password: str,
            email: str | None,
            first_name: str | None,
            last_name: str | None,
            exist_ok: bool,
        ) -> None:
            client = KeycloakAdminClient(app.plugins.get(KeycloakAdminPlugin).config)

            async def run() -> str:
                try:
                    return await client.create_user(
                        username=username,
                        password=password,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        roles=roles,
                    )
                finally:
                    await client.close()

            try:
                subject = asyncio.run(run())
            except KeycloakAdminError as exc:
                if exc.conflict and exist_ok:
                    click.echo(f"User {username!r} already exists, nothing to do")
                    return
                raise click.ClickException(str(exc)) from exc
            except KeycloakClientError as exc:
                raise click.ClickException(str(exc)) from exc
            click.echo(f"Created user {username!r} ({subject}) with roles: {', '.join(roles)}")
