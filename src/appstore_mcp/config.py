"""Settings, read from environment variables (Secrets and chart values set them)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

DEFAULT_REPOS = (
    "backend", "worker", "frontend", "deployment", "appstore-mcp",
    "self-service-ui", "moodle_appstore", ".github",
)  # fmt: skip
DEFAULT_LOG_NAMESPACES = (
    "appstore-staging", "appstore-prod", "argocd", "cert-manager", "cnpg-system", "kube-system",
)  # fmt: skip
DEP_PREFIX = "dep-"
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?$")


@dataclass(frozen=True)
class Env:
    name: str
    namespace: str
    branch: str
    app_url: str
    sso_url: str

    @property
    def argo_prefix(self) -> str:
        return f"{self.name}-"


@dataclass(frozen=True)
class Settings:
    public_url: str
    default_env: str = "staging"
    github_org: str = "DHBW-AppStore-T3"
    github_client_id: str = ""
    github_client_secret: str = ""
    github_api_token: str = ""
    token_signing_key: str = ""
    static_tokens: str = ""
    data_dir: str = "/data"
    repos: tuple[str, ...] = DEFAULT_REPOS
    readable_namespaces: tuple[str, ...] = DEFAULT_LOG_NAMESPACES
    argocd_namespace: str = "argocd"
    environments: Mapping[str, Env] = field(default_factory=dict)

    @property
    def resource_url(self) -> str:
        return self.public_url.rstrip("/") + "/mcp"

    @property
    def public_host(self) -> str:
        return self.public_url.split("://", 1)[-1].split("/", 1)[0]

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        e = environ if environ is not None else os.environ
        zone = e.get("ZONE", "")

        def csv(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
            raw = e.get(key, "")
            return tuple(p.strip() for p in raw.split(",") if p.strip()) or default

        envs = {
            "staging": Env("staging", "appstore-staging", "dev",
                           f"https://appstore-staging.{zone}", f"https://sso-staging.{zone}"),
            "prod": Env("prod", "appstore-prod", "main",
                        f"https://appstore.{zone}", f"https://sso.{zone}"),
        }  # fmt: skip
        return cls(
            public_url=e.get("MCP_PUBLIC_URL", "http://localhost:8000").rstrip("/"),
            default_env=e.get("DEFAULT_ENV", "staging"),
            github_org=e.get("GITHUB_ORG", "DHBW-AppStore-T3"),
            github_client_id=e.get("GITHUB_CLIENT_ID", ""),
            github_client_secret=e.get("GITHUB_CLIENT_SECRET", ""),
            github_api_token=e.get("GITHUB_API_TOKEN", ""),
            token_signing_key=e.get("TOKEN_SIGNING_KEY", ""),
            static_tokens=e.get("STATIC_TOKENS", ""),
            data_dir=e.get("DATA_DIR", "/data"),
            repos=csv("GITHUB_REPOS", DEFAULT_REPOS),
            readable_namespaces=csv("READABLE_NAMESPACES", DEFAULT_LOG_NAMESPACES),
            argocd_namespace=e.get("ARGOCD_NAMESPACE", "argocd"),
            environments=envs,
        )
