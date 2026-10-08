import asyncio
import json
import socket
import threading
from typing import Any

from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm

REALM = "demo"

# Roles as a realm export defines them - nothing in the plugin knows these names.
REALM_ROLES = [
    {"name": "admin", "description": "Administrator"},
    {"name": "dispatcher", "description": "Dispatcher"},
    {"name": "user", "description": "Regular user"},
    {"name": "offline_access"},
    {"name": "uma_authorization"},
    {"name": f"default-roles-{REALM}"},
]


class FakeKeycloak:
    """The parts of Keycloak's HTTP API the plugin talks to, served for real on localhost
    from a background thread, so both this package and ``litestar-keycloak`` hit it."""

    def __init__(self, public_key: RSAPublicKey) -> None:
        self.jwk = {**json.loads(RSAAlgorithm.to_jwk(public_key)), "kid": "key-1", "use": "sig"}
        self.created: list[dict[str, Any]] = []
        self.assigned: list[str] = []
        self.token_response: tuple[int, dict[str, Any]] = (400, {"error": "invalid_grant"})
        self.grants: list[str] = []
        self.users: dict[str, dict[str, Any]] = {}
        self.user_status = 200
        """Status of ``GET /users/{id}``; set to 500 to simulate an Admin API failure."""
        self.logged_out: list[str] = []
        self._loop = asyncio.new_event_loop()
        self._socket = socket.socket()
        self._socket.bind(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self._socket.getsockname()[1]}"
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)

    def __enter__(self) -> "FakeKeycloak":
        self._thread.start()
        self._runner = web.AppRunner(self._app())
        asyncio.run_coroutine_threadsafe(self._start(), self._loop).result()
        return self

    def __exit__(self, *_: object) -> None:
        asyncio.run_coroutine_threadsafe(self._runner.cleanup(), self._loop).result()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()
        self._loop.close()

    async def _start(self) -> None:
        await self._runner.setup()
        await web.SockSite(self._runner, self._socket).start()

    def _app(self) -> web.Application:
        realm = f"/realms/{REALM}/protocol/openid-connect"
        admin = f"/admin/realms/{REALM}"
        app = web.Application()
        app.router.add_get(f"{realm}/certs", self._certs)
        app.router.add_post(f"{realm}/token", self._token)
        app.router.add_post(f"{realm}/logout", self._logout)
        app.router.add_post("/realms/master/protocol/openid-connect/token", self._admin_token)
        app.router.add_get(f"{admin}/roles", self._roles)
        app.router.add_get(f"{admin}/roles/{{name}}", self._role)
        app.router.add_post(f"{admin}/users", self._create_user)
        app.router.add_post(f"{admin}/users/{{id}}/role-mappings/realm", self._assign)
        app.router.add_get(f"{admin}/users/{{id}}", self._get_user)
        app.router.add_put(f"{admin}/users/{{id}}", self._put_user)
        return app

    async def _certs(self, _: web.Request) -> web.Response:
        return web.json_response({"keys": [self.jwk]})

    async def _token(self, request: web.Request) -> web.Response:
        self.grants.append(str((await request.post()).get("grant_type")))
        status, payload = self.token_response
        return web.json_response(payload, status=status)

    async def _logout(self, request: web.Request) -> web.Response:
        self.logged_out.append(str((await request.post()).get("refresh_token")))
        return web.Response(status=204)

    async def _admin_token(self, _: web.Request) -> web.Response:
        return web.json_response({"access_token": "admin-token", "expires_in": 60})

    @staticmethod
    def _authorized(request: web.Request) -> None:
        if request.headers.get("Authorization") != "Bearer admin-token":
            raise web.HTTPUnauthorized

    async def _roles(self, request: web.Request) -> web.Response:
        self._authorized(request)
        return web.json_response(REALM_ROLES)

    async def _role(self, request: web.Request) -> web.Response:
        self._authorized(request)
        role = next(
            (role for role in REALM_ROLES if role["name"] == request.match_info["name"]), None
        )
        return web.json_response(role) if role else web.json_response({}, status=404)

    async def _create_user(self, request: web.Request) -> web.Response:
        self._authorized(request)
        self.created.append(await request.json())
        return web.Response(
            status=201, headers={"Location": f"{self.url}/admin/realms/{REALM}/users/new-id"}
        )

    async def _get_user(self, request: web.Request) -> web.Response:
        self._authorized(request)
        user = self.users.get(request.match_info["id"])
        if self.user_status != 200:
            return web.json_response({}, status=self.user_status)
        return web.json_response(user) if user else web.json_response({}, status=404)

    async def _put_user(self, request: web.Request) -> web.Response:
        self._authorized(request)
        self.users[request.match_info["id"]] = await request.json()
        return web.Response(status=204)

    async def _assign(self, request: web.Request) -> web.Response:
        self._authorized(request)
        self.assigned += [role["name"] for role in await request.json()]
        return web.Response(status=204)
