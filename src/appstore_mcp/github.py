"""Read-only GitHub REST access (Actions runs, pull requests, raw files)."""

from __future__ import annotations

from typing import Any

import httpx


class GitHub:
    def __init__(self, client: httpx.AsyncClient, org: str, token: str = ""):
        self._c = client
        self.org = org
        self._headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    async def api(self, path: str, **params: Any) -> Any:
        r = await self._c.get(f"https://api.github.com{path}", params=params or None, headers=self._headers)
        r.raise_for_status()
        return r.json()

    async def raw(self, repo: str, ref: str, path: str) -> str:
        r = await self._c.get(
            f"https://api.github.com/repos/{self.org}/{repo}/contents/{path}",
            params={"ref": ref},
            headers={**self._headers, "Accept": "application/vnd.github.raw+json"},
        )
        r.raise_for_status()
        return r.text
