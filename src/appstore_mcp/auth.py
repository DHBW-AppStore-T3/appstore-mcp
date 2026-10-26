"""OAuth 2.1 authorization server for MCP clients, with GitHub as the identity provider.

Flow (MCP spec, authorization code + PKCE, dynamic client registration):
  client -> /authorize -> GitHub login -> /github/callback (we check org membership)
         -> client redirect_uri?code=... -> /token -> access token (1 h) + refresh token (7 d)

Every refresh checks the org membership again, with the person's GitHub token (kept Fernet-encrypted
with the refresh token): leaving the org ends the access within the hour (review S10). Clients may
only send a login back to a loopback address or one of ``allowed_redirect_uris``.

Also accepted as a Bearer token: static tokens minted with `python -m appstore_mcp.mint`; only their
SHA-256 is stored (Secret `appstore-mcp`, key `static-tokens`).
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .config import Settings

log = logging.getLogger(__name__)

SCOPE = "mcp"
ACCESS_TTL = 3600
REFRESH_TTL = 7 * 86400
CODE_TTL = 300
PENDING_TTL = 600
ACCESS_PREFIX = "asa_"
STATIC_PREFIX = "asmcp_"
LOOPBACK = ("localhost", "127.0.0.1", "[::1]", "::1")


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    """Small SQLite store: dynamic clients, pending logins, authorization codes, refresh tokens."""

    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        for table in ("clients", "pending", "codes", "refresh"):
            self._db.execute(
                f"CREATE TABLE IF NOT EXISTS {table} (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp REAL NOT NULL)"  # noqa: S608
            )

    def put(self, table: str, key: str, value: dict, ttl: float) -> None:
        with self._lock:
            self._db.execute(f"DELETE FROM {table} WHERE exp < ?", (time.time(),))  # noqa: S608
            self._db.execute(
                f"INSERT OR REPLACE INTO {table} VALUES (?,?,?)",  # noqa: S608
                (key, json.dumps(value), time.time() + ttl),
            )

    def get(self, table: str, key: str) -> dict | None:
        with self._lock:
            row = self._db.execute(f"SELECT v, exp FROM {table} WHERE k=?", (key,)).fetchone()  # noqa: S608
        return json.loads(row[0]) if row and row[1] >= time.time() else None

    def pop(self, table: str, key: str) -> dict | None:
        with self._lock:
            row = self._db.execute(f"SELECT v, exp FROM {table} WHERE k=?", (key,)).fetchone()  # noqa: S608
            self._db.execute(f"DELETE FROM {table} WHERE k=?", (key,))  # noqa: S608
        return json.loads(row[0]) if row and row[1] >= time.time() else None


def parse_static_tokens(text: str) -> dict[str, str]:
    """`name:sha256hex` per line (# comments allowed) -> {sha256hex: name}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, _, digest = line.partition(":")
        digest = digest.strip().lower()
        if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
            out[digest] = name.strip()
        else:
            log.warning("ignoring malformed static token entry %r", name)
    return out


class AppStoreAuthProvider:
    def __init__(self, settings: Settings, store: Store | None = None, http: httpx.AsyncClient | None = None):
        self.s = settings
        self.store = store or Store(str(Path(settings.data_dir) / "auth.sqlite3"))
        self.http = http or httpx.AsyncClient(timeout=10.0)
        self.fernet = Fernet(settings.token_signing_key.encode()) if settings.token_signing_key else None
        self.static = parse_static_tokens(settings.static_tokens)

    # ---- dynamic client registration
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self.store.get("clients", client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    def redirect_allowed(self, uri) -> bool:
        """A login may go back to this machine (loopback: a local MCP client) or to an allowed hosted client.

        Any other https redirect would let whoever registered the client collect an org member's login
        with a link to /authorize (there is no consent step).
        """
        if uri.scheme in ("http", "https") and uri.host in LOOPBACK:
            return True
        return str(uri) in self.s.allowed_redirect_uris

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not self.redirect_allowed(uri):
                from mcp.server.auth.provider import RegistrationError

                raise RegistrationError(
                    "invalid_redirect_uri", "redirect URIs must be loopback or one of the allowed hosted clients"
                )
        self.store.put("clients", client_info.client_id, client_info.model_dump(mode="json"), 365 * 86400)

    # ---- authorization: hand over to GitHub
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not self.s.github_client_id:
            raise AuthorizeError("server_error", "GitHub login is not configured on this server")
        # Clients registered before the redirect rule are held to it here.
        if not self.redirect_allowed(params.redirect_uri):
            raise AuthorizeError("unauthorized_client", "this client's redirect URI is not allowed")
        pending_id = secrets.token_urlsafe(32)
        self.store.put("pending", pending_id, {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "explicit": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "state": params.state,
            "scopes": params.scopes or [SCOPE],
            "resource": params.resource,
        }, PENDING_TTL)  # fmt: skip
        query = urlencode({
            "client_id": self.s.github_client_id,
            "redirect_uri": self.s.public_url + "/github/callback",
            "scope": "read:org",
            "state": pending_id,
            "allow_signup": "false",
        })  # fmt: skip
        return "https://github.com/login/oauth/authorize?" + query

    async def github_callback(self, request: Request) -> Response:
        pending = self.store.pop("pending", request.query_params.get("state", ""))
        if not pending:
            return HTMLResponse("<h1>Login expired</h1><p>Start again from your MCP client.</p>", 400)

        def back(**kw: str | None) -> RedirectResponse:
            return RedirectResponse(construct_redirect_uri(pending["redirect_uri"], state=pending["state"], **kw), 302)

        code = request.query_params.get("code")
        if request.query_params.get("error") or not code:
            return back(error="access_denied", error_description="GitHub login was not completed")
        try:
            found = await self._github_member(code)
        except httpx.HTTPError:
            log.exception("GitHub login failed")
            return back(error="server_error", error_description="GitHub is not reachable")
        if found is None or not self.fernet:
            return back(error="access_denied",
                        error_description=f"not an active member of the GitHub org {self.s.github_org}")  # fmt: skip
        login, gh_token = found
        auth_code = secrets.token_urlsafe(32)
        self.store.put("codes", _h(auth_code), {**pending, "subject": f"github:{login}",
                                                "gh": self.fernet.encrypt(gh_token.encode()).decode()},
                       CODE_TTL)  # fmt: skip
        log.info("issued authorization code for github:%s", login)
        return back(code=auth_code)

    async def _github_member(self, code: str) -> tuple[str, str] | None:
        """The GitHub login and token of an active member of the org, else None."""
        r = await self.http.post(
            "https://github.com/login/oauth/access_token",
            json={"client_id": self.s.github_client_id, "client_secret": self.s.github_client_secret,
                  "code": code, "redirect_uri": self.s.public_url + "/github/callback"},
            headers={"Accept": "application/json"},
        )  # fmt: skip
        token = r.json().get("access_token")
        if not token:
            log.warning("github token exchange failed: %s", r.json().get("error", "no access_token"))
            return None
        h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        user = await self.http.get("https://api.github.com/user", headers=h)
        if user.status_code != 200:
            log.warning("github /user returned %s", user.status_code)
            return None
        if await self._active_member(token):
            return user.json()["login"], token
        return None

    async def _active_member(self, gh_token: str) -> bool:
        """Whether the owner of ``gh_token`` is an active member of the org (fails closed)."""
        h = {"Authorization": f"Bearer {gh_token}", "Accept": "application/vnd.github+json"}
        try:
            member = await self.http.get(f"https://api.github.com/user/memberships/orgs/{self.s.github_org}", headers=h)
        except httpx.HTTPError:
            log.warning("github org membership check failed", exc_info=True)
            return False
        if member.status_code == 200 and member.json().get("state") == "active":
            return True
        log.warning("github org membership check: status %s, state %s", member.status_code,
                    member.json().get("state") if member.status_code == 200 else None)  # fmt: skip
        return False

    # ---- code -> tokens
    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        d = self.store.get("codes", _h(authorization_code))
        if not d or d["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code, scopes=d["scopes"], expires_at=time.time() + CODE_TTL,
            client_id=d["client_id"], code_challenge=d["code_challenge"], redirect_uri=d["redirect_uri"],
            redirect_uri_provided_explicitly=d["explicit"], resource=d["resource"], subject=d["subject"],
        )  # fmt: skip

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: AuthorizationCode) -> OAuthToken:
        code = self.store.pop("codes", _h(authorization_code.code))  # single use
        if not code:
            raise TokenError("invalid_grant", "authorization code already used")
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.subject or "",
                           authorization_code.resource, code.get("gh", ""))  # fmt: skip

    def _issue(self, client_id: str, scopes: list[str], subject: str, resource: str | None,
               gh: str = "") -> OAuthToken:  # fmt: skip
        if not self.fernet:
            raise TokenError("invalid_request", "token signing key is not configured")
        now = int(time.time())
        access = ACCESS_PREFIX + self.fernet.encrypt(json.dumps({
            "cid": client_id, "sc": scopes, "sub": subject, "res": resource, "exp": now + ACCESS_TTL,
        }).encode()).decode()  # fmt: skip
        refresh = secrets.token_urlsafe(48)
        self.store.put("refresh", _h(refresh), {"client_id": client_id, "scopes": scopes, "subject": subject,
                                                "resource": resource, "gh": gh}, REFRESH_TTL)  # fmt: skip
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,  # noqa: S106
                          scope=" ".join(scopes), refresh_token=refresh)  # fmt: skip

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        d = self.store.get("refresh", _h(refresh_token))
        if not d or d["client_id"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=d["client_id"], scopes=d["scopes"],
                            expires_at=int(time.time()) + REFRESH_TTL, resource=d["resource"],
                            subject=d["subject"])  # fmt: skip

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken,
                                     scopes: list[str]) -> OAuthToken:
        stored = self.store.pop("refresh", _h(refresh_token.token))  # rotate
        if not stored:
            raise TokenError("invalid_grant", "refresh token already used")
        # Still in the org? A refresh token of before this check carries no GitHub token: log in again.
        gh = stored.get("gh", "")
        try:
            gh_token = self.fernet.decrypt(gh.encode()).decode() if gh and self.fernet else ""
        except InvalidToken:
            gh_token = ""
        if not gh_token or not await self._active_member(gh_token):
            log.info("refresh refused for %s: not (any more) an active member of %s",
                     refresh_token.subject, self.s.github_org)  # fmt: skip
            raise TokenError("invalid_grant", f"not an active member of the GitHub org {self.s.github_org}")
        granted = [s for s in scopes if s in refresh_token.scopes] or refresh_token.scopes
        return self._issue(client.client_id, granted, refresh_token.subject or "", refresh_token.resource, gh)

    # ---- verifying Bearer tokens
    async def load_access_token(self, token: str) -> AccessToken | None:
        if token.startswith(STATIC_PREFIX):
            digest = _h(token)
            for known, name in self.static.items():
                if hmac.compare_digest(known, digest):
                    return AccessToken(token=token, client_id=f"static:{name}", scopes=[SCOPE],
                                       expires_at=None, subject=f"static:{name}")  # fmt: skip
            return None
        if token.startswith(ACCESS_PREFIX) and self.fernet:
            try:
                d = json.loads(self.fernet.decrypt(token[len(ACCESS_PREFIX):].encode()))
            except (InvalidToken, ValueError):
                return None
            if d["exp"] < time.time():
                return None
            return AccessToken(token=token, client_id=d["cid"], scopes=d["sc"], expires_at=d["exp"],
                               resource=d.get("res"), subject=d["sub"])  # fmt: skip
        return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, RefreshToken):
            self.store.pop("refresh", _h(token.token))
        # Access tokens are stateless and expire within an hour; static tokens are revoked by
        # removing their line from the Secret.


def landing_page(settings: Settings) -> str:
    return (
        "<h1>appstore-mcp</h1><p>Read-only MCP server of the DHBW AppStore T3 team. Add it with:</p>"
        f"<pre>claude mcp add --transport http appstore {html.escape(settings.resource_url)}</pre>"
    )
