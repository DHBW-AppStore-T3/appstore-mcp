"""Server wiring: MCP tools + OAuth routes + health endpoints."""

from __future__ import annotations

import functools
import logging
import os
from collections.abc import Callable
from typing import Any

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from .auth import SCOPE, AppStoreAuthProvider, landing_page
from .config import Settings
from .github import GitHub
from .kube import KubeClient, KubeError
from .redact import RedactingFilter, redact, redact_obj
from .tools import Toolbox, ToolError

log = logging.getLogger("appstore_mcp")

TOOLS = [
    "staging_verdict", "rollout_status", "argocd_apps", "argocd_app", "pods", "deployments", "events",
    "logs", "dep_namespaces", "cnpg_clusters", "health", "ingress_and_certificates", "nodes",
    "github_runs", "github_open_prs",
]  # fmt: skip

INSTRUCTIONS = (
    "Read-only insight into the DHBW AppStore T3 clusters (staging = namespace appstore-staging, branch dev; "
    "prod = appstore-prod, branch main). After a push to dev, call staging_verdict first: healthy | "
    "progressing (wait and call again) | unhealthy (see problems; then use pods, events, logs, "
    "argocd_app, rollout_status). dep-* namespaces (student apps) expose counts and status only. "
    "Secrets are never returned and log output is redacted."
)


def _guard(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    async def run(*args: Any, **kwargs: Any) -> Any:
        tok = get_access_token()
        log.info("tool %s by %s args=%s", name, tok.subject if tok else "-", redact(str(kwargs))[:200])
        try:
            return redact_obj(await fn(*args, **kwargs))
        except ToolError as e:
            raise ValueError(str(e)) from None
        except KubeError as e:
            raise RuntimeError(redact(str(e))) from None
        except httpx.HTTPStatusError as e:
            raise RuntimeError(f"HTTP {e.response.status_code} from {e.request.url.host}") from None
        except httpx.HTTPError as e:
            raise RuntimeError(f"request failed: {type(e).__name__}") from None

    return run


def build_server(settings: Settings, toolbox: Toolbox | None = None,
                 provider: AppStoreAuthProvider | None = None) -> MCPServer:  # fmt: skip
    logging.getLogger().addFilter(RedactingFilter())
    for handler in logging.getLogger().handlers:
        handler.addFilter(RedactingFilter())
    provider = provider or AppStoreAuthProvider(settings)
    if toolbox is None:
        http = httpx.AsyncClient(timeout=10.0)
        toolbox = Toolbox(settings, KubeClient.in_cluster(), GitHub(http, settings.github_org,
                                                                    settings.github_api_token), http)
    server = MCPServer(
        "appstore-mcp",
        instructions=INSTRUCTIONS,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=settings.public_url,
            resource_server_url=settings.resource_url,
            validate_token_resource=False,
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )  # fmt: skip
    for name in TOOLS:
        server.add_tool(_guard(name, getattr(toolbox, name)), name=name,
                        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                                    idempotentHint=True, openWorldHint=True))  # fmt: skip

    @server.custom_route("/github/callback", methods=["GET"])
    async def github_callback(request: Request) -> Response:
        return await provider.github_callback(request)

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    @server.custom_route("/", methods=["GET"])
    async def index(_: Request) -> Response:
        return HTMLResponse(landing_page(settings))

    return server


def build_app(settings: Settings, **kw: Any):
    server = build_server(settings, **kw)
    return server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[settings.public_host, "localhost:*", "127.0.0.1:*", "[::1]:*"],
            allowed_origins=[settings.public_url, "http://localhost:*", "http://127.0.0.1:*"],
        ),
    )


def main() -> None:
    import uvicorn

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")  # fmt: skip
    settings = Settings.from_env()
    missing = [k for k, v in {"GITHUB_CLIENT_ID": settings.github_client_id,
                              "GITHUB_CLIENT_SECRET": settings.github_client_secret,
                              "TOKEN_SIGNING_KEY": settings.token_signing_key}.items() if not v]  # fmt: skip
    if missing:
        log.warning("not configured: %s (browser login is disabled until set)", ", ".join(missing))
    uvicorn.run(build_app(settings), host=os.environ.get("BIND_HOST", "::"),
                port=int(os.environ.get("PORT", "8000")), proxy_headers=True, forwarded_allow_ips="*",
                access_log=False)  # fmt: skip


if __name__ == "__main__":
    main()
