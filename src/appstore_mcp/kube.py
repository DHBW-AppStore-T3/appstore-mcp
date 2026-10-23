"""A GET-only Kubernetes API client (the ServiceAccount has get/list/watch anyway)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class KubeError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"kubernetes API {status}: {message}")
        self.status = status


class _FileTokenAuth(httpx.Auth):
    """Bearer token re-read per request: projected tokens rotate."""

    def __init__(self, path: Path):
        self.path = path

    def auth_flow(self, request: httpx.Request):
        request.headers["Authorization"] = "Bearer " + self.path.read_text().strip()
        yield request


class KubeClient:
    def __init__(self, client: httpx.AsyncClient):
        self._c = client

    @classmethod
    def in_cluster(cls) -> KubeClient:
        return cls(
            httpx.AsyncClient(
                base_url="https://kubernetes.default.svc",
                verify=str(SA_DIR / "ca.crt"),
                auth=_FileTokenAuth(SA_DIR / "token"),
                timeout=httpx.Timeout(10.0),
            )
        )

    async def _get(self, path: str, params: dict[str, Any] | None = None, accept: str = "application/json"):
        r = await self._c.get(path, params=params, headers={"Accept": accept})
        if r.status_code >= 400:
            raise KubeError(r.status_code, r.text[:200])
        return r

    async def get(self, path: str, **params: Any) -> dict[str, Any]:
        return (await self._get(path, params or None)).json()

    async def items(self, path: str, limit: int = 500, **params: Any) -> list[dict[str, Any]]:
        return (await self.get(path, limit=limit, **params)).get("items", [])

    async def text(self, path: str, **params: Any) -> str:
        return (await self._get(path, params or None, accept="text/plain")).text

    async def aclose(self) -> None:
        await self._c.aclose()
