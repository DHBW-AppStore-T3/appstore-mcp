import base64
import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.testclient import TestClient

from appstore_mcp import mint
from appstore_mcp.auth import AppStoreAuthProvider, Store, parse_static_tokens
from appstore_mcp.server import build_app

from .conftest import jsonrpc

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
           "MCP-Protocol-Version": "2025-06-18"}  # fmt: skip
REDIRECT = "http://localhost:33418/callback"


def github(member: bool = True, state: str = "active"):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "gho_x"})
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "alice"})
        if request.url.path.startswith("/user/memberships/orgs/DHBW-AppStore-T3"):
            return httpx.Response(200, json={"state": state}) if member else httpx.Response(404)
        return httpx.Response(500)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def mint_static(name="ci") -> tuple[str, str]:
    token = mint.STATIC_PREFIX + secrets.token_urlsafe(32)
    return token, f"{name}:{hashlib.sha256(token.encode()).hexdigest()}"


def make_client(settings, toolbox, *, gh=None, static=""):
    from dataclasses import replace

    s = replace(settings, static_tokens=static)
    provider = AppStoreAuthProvider(s, Store(":memory:"), gh or github())
    return TestClient(build_app(s, toolbox=toolbox, provider=provider), base_url="https://mcp.example.org")


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def login(client: TestClient):
    """Register, authorize, come back from GitHub, exchange the code. Returns (token response, client info)."""
    reg = client.post("/register", json={"redirect_uris": [REDIRECT], "client_name": "t",
                                         "token_endpoint_auth_method": "none"})  # fmt: skip
    assert reg.status_code == 201, reg.text
    info = reg.json()
    verifier, challenge = pkce()
    r = client.get("/authorize", params={
        "response_type": "code", "client_id": info["client_id"], "redirect_uri": REDIRECT, "state": "xyz",
        "code_challenge": challenge, "code_challenge_method": "S256", "scope": "mcp"},
        follow_redirects=False)  # fmt: skip
    assert r.status_code == 302 and r.headers["location"].startswith("https://github.com/login/oauth/authorize")
    gh_state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    cb = client.get("/github/callback", params={"code": "ghcode", "state": gh_state}, follow_redirects=False)
    assert cb.status_code == 302
    back = urlparse(cb.headers["location"])
    assert f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT
    q = parse_qs(back.query)
    assert q["state"] == ["xyz"]
    return q, info, verifier


def test_static_token_parsing():
    token, line = mint_static("ci-bot")
    parsed = parse_static_tokens(f"# comment\n{line}\nbroken:zz\n\n")
    assert list(parsed.values()) == ["ci-bot"] and token not in str(parsed)


def test_mint_prints_token_and_hash(capsys):
    assert mint.main(["agent-1"]) == 0
    out = capsys.readouterr()
    token = out.out.strip()
    assert out.err.strip() == f"agent-1:{hashlib.sha256(token.encode()).hexdigest()}"
    assert mint.main(["Bad Name"]) == 2


def test_mcp_requires_auth_and_advertises_metadata(settings, toolbox):
    with make_client(settings, toolbox) as c:
        r = c.post("/mcp", content=jsonrpc("tools/list"), headers=HEADERS)
        assert r.status_code == 401
        assert "resource_metadata" in r.headers["www-authenticate"]
        meta = c.get("/.well-known/oauth-authorization-server").json()
        assert meta["code_challenge_methods_supported"] == ["S256"] and meta["registration_endpoint"].endswith("/register")
        prm = c.get("/.well-known/oauth-protected-resource/mcp").json()
        assert prm["resource"] == "https://mcp.example.org/mcp"
        assert c.get("/healthz").json() == {"status": "ok"}


def test_static_token_lists_only_readonly_tools_and_calls_one(settings, toolbox):
    token, line = mint_static()
    with make_client(settings, toolbox, static=line) as c:
        h = {**HEADERS, "Authorization": f"Bearer {token}"}
        init = c.post("/mcp", content=jsonrpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}), headers=h)
        assert init.status_code == 200, init.text
        tools = c.post("/mcp", content=jsonrpc("tools/list", id_=2), headers=h).json()["result"]["tools"]
        names = {t["name"] for t in tools}
        assert {"staging_verdict", "logs", "dep_namespaces"} <= names
        assert all(t["annotations"]["readOnlyHint"] for t in tools)
        call = c.post("/mcp", content=jsonrpc("tools/call", {"name": "events", "arguments": {
            "namespace": "appstore-staging"}}, id_=3), headers=h).json()["result"]
        assert not call.get("isError")
        assert "hunter2" not in json.dumps(call), "secret-looking values in events must be redacted"
        deny = c.post("/mcp", content=jsonrpc("tools/call", {"name": "events", "arguments": {
            "namespace": "dep-12345678"}}, id_=4), headers=h).json()["result"]
        assert deny["isError"]
        bad = c.post("/mcp", content=jsonrpc("tools/list", id_=5), headers={**HEADERS, "Authorization": "Bearer asmcp_nope"})
        assert bad.status_code == 401


def test_full_oauth_flow_for_org_member(settings, toolbox):
    with make_client(settings, toolbox) as c:
        q, info, verifier = login(c)
        tok = c.post("/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                     "redirect_uri": REDIRECT, "client_id": info["client_id"],
                                     "code_verifier": verifier})  # fmt: skip
        assert tok.status_code == 200, tok.text
        t = tok.json()
        assert t["access_token"].startswith("asa_") and t["refresh_token"]
        # code is single-use
        again = c.post("/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                       "redirect_uri": REDIRECT, "client_id": info["client_id"],
                                       "code_verifier": verifier})  # fmt: skip
        assert again.status_code == 400
        h = {**HEADERS, "Authorization": "Bearer " + t["access_token"]}
        ok = c.post("/mcp", content=jsonrpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}), headers=h)
        assert ok.status_code == 200
        # refresh rotates
        ref = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                                     "client_id": info["client_id"]})  # fmt: skip
        assert ref.status_code == 200 and ref.json()["refresh_token"] != t["refresh_token"]
        reuse = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                                       "client_id": info["client_id"]})  # fmt: skip
        assert reuse.status_code == 400


def test_non_member_gets_access_denied(settings, toolbox):
    with make_client(settings, toolbox, gh=github(member=False)) as c:
        q, _, _ = login(c)
        assert q["error"] == ["access_denied"] and "code" not in q


def test_pending_member_is_not_a_member(settings, toolbox):
    with make_client(settings, toolbox, gh=github(state="pending")) as c:
        q, _, _ = login(c)
        assert q["error"] == ["access_denied"]


def test_callback_with_unknown_state_is_rejected(settings, toolbox):
    with make_client(settings, toolbox) as c:
        assert c.get("/github/callback", params={"code": "x", "state": "forged"}).status_code == 400


def test_registration_refuses_plain_http_redirects(settings, toolbox):
    with make_client(settings, toolbox) as c:
        r = c.post("/register", json={"redirect_uris": ["http://evil.example/cb"],
                                      "token_endpoint_auth_method": "none"})  # fmt: skip
        assert r.status_code == 400


async def test_expired_and_tampered_access_tokens(settings):
    p = AppStoreAuthProvider(settings, Store(":memory:"))
    tok = p._issue("c", ["mcp"], "github:alice", None).access_token
    assert (await p.load_access_token(tok)).subject == "github:alice"
    assert await p.load_access_token(tok[:-3] + "AAA") is None
    assert await p.load_access_token("garbage") is None
    real = time.time
    time.time = lambda: real() + 7200
    try:
        assert await p.load_access_token(tok) is None
    finally:
        time.time = real


@pytest.mark.parametrize("missing", ["github_client_id"])
async def test_authorize_without_github_config_fails(settings, missing):
    from dataclasses import replace

    from mcp.server.auth.provider import AuthorizeError

    p = AppStoreAuthProvider(replace(settings, **{missing: ""}), Store(":memory:"))
    with pytest.raises(AuthorizeError):
        await p.authorize(None, None)  # type: ignore[arg-type]


def github_org(members: set[str]):
    """GitHub whose org membership can change while the test runs (alice's token is gho_alice)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "gho_alice"})
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "alice"})
        if request.url.path.startswith("/user/memberships/orgs/DHBW-AppStore-T3"):
            who = request.headers["Authorization"].removeprefix("Bearer gho_")
            return httpx.Response(200, json={"state": "active"}) if who in members else httpx.Response(404)
        return httpx.Response(500)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def tokens(c: TestClient):
    q, info, verifier = login(c)
    tok = c.post("/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                 "redirect_uri": REDIRECT, "client_id": info["client_id"],
                                 "code_verifier": verifier})  # fmt: skip
    assert tok.status_code == 200, tok.text
    return tok.json(), info


def test_leaving_the_org_ends_the_access_at_the_next_refresh(settings, toolbox):
    """Review S10: refresh tokens used to be rotated for 30 days without asking GitHub again."""
    members = {"alice"}
    with make_client(settings, toolbox, gh=github_org(members)) as c:
        t, info = tokens(c)
        ok = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                                    "client_id": info["client_id"]})  # fmt: skip
        assert ok.status_code == 200, ok.text

        members.discard("alice")
        gone = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": ok.json()["refresh_token"],
                                      "client_id": info["client_id"]})  # fmt: skip
        assert gone.status_code == 400
        assert gone.json()["error"] == "invalid_grant"


def test_the_github_token_is_kept_encrypted(settings, toolbox):
    store = Store(":memory:")
    provider = AppStoreAuthProvider(settings, store, github_org({"alice"}))
    with TestClient(build_app(settings, toolbox=toolbox, provider=provider), base_url="https://mcp.example.org") as c:
        tokens(c)
    rows = store._db.execute("SELECT v FROM refresh").fetchall()
    assert rows and all("gho_alice" not in row[0] and json.loads(row[0])["gh"] for row in rows)


async def test_a_refresh_token_without_a_github_token_needs_a_new_login(settings):
    from mcp.server.auth.provider import RefreshToken, TokenError

    p = AppStoreAuthProvider(settings, Store(":memory:"), github_org({"alice"}))
    old = p._issue("c", ["mcp"], "github:alice", None).refresh_token  # issued before the check existed
    rt = RefreshToken(token=old, client_id="c", scopes=["mcp"], expires_at=None, subject="github:alice")
    with pytest.raises(TokenError):
        await p.exchange_refresh_token(None, rt, ["mcp"])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("uri", "allowed"),
    [
        ("http://localhost:33418/callback", True),
        ("http://127.0.0.1:5000/cb", True),
        ("https://claude.ai/api/mcp/auth_callback", True),
        ("https://evil.example/cb", False),
        ("https://claude.ai.evil.example/api/mcp/auth_callback", False),
        ("http://evil.example/cb", False),
    ],
)
def test_registration_allows_loopback_and_the_hosted_clients_only(settings, toolbox, uri, allowed):
    with make_client(settings, toolbox) as c:
        r = c.post("/register", json={"redirect_uris": [uri], "token_endpoint_auth_method": "none"})
        assert (r.status_code == 201) is allowed, r.text


async def test_a_client_registered_with_a_foreign_redirect_before_cannot_log_in(settings):
    from mcp.server.auth.provider import AuthorizationParams, AuthorizeError
    from mcp.shared.auth import OAuthClientInformationFull

    p = AppStoreAuthProvider(settings, Store(":memory:"), github())
    evil = OAuthClientInformationFull(client_id="old", redirect_uris=["https://evil.example/cb"],
                                      token_endpoint_auth_method="none")  # fmt: skip
    p.store.put("clients", "old", evil.model_dump(mode="json"), 3600)
    params = AuthorizationParams(state="s", scopes=["mcp"], code_challenge="x" * 43,
                                 redirect_uri="https://evil.example/cb", redirect_uri_provided_explicitly=True)  # fmt: skip
    with pytest.raises(AuthorizeError):
        await p.authorize(evil, params)
