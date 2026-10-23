from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet

from appstore_mcp.config import Settings
from appstore_mcp.github import GitHub
from appstore_mcp.kube import KubeClient
from appstore_mcp.tools import Toolbox

DIGEST_NEW = "sha256:" + "a" * 64
DIGEST_OLD = "sha256:" + "b" * 64
REG = "ghcr.io/dhbw-appstore-t3/"


def pod(name: str, ns: str, image: str, digest: str, *, ready: bool = True, waiting: str | None = None,
        restarts: int = 0, phase: str = "Running") -> dict[str, Any]:  # fmt: skip
    state = {"waiting": {"reason": waiting}} if waiting else {"running": {}}
    return {
        "metadata": {"name": name, "namespace": ns},
        "spec": {"nodeName": "n1", "containers": [{"name": "c", "image": f"{REG}{image}@{digest}"}]},
        "status": {"phase": phase, "containerStatuses": [{
            "name": "c", "ready": ready, "restartCount": restarts, "state": state,
            "image": f"{REG}{image}:sha", "imageID": f"{REG}{image}@{digest}"}]},
    }  # fmt: skip


def argo_app(name: str, sync: str = "Synced", health: str = "Healthy") -> dict[str, Any]:
    return {"metadata": {"name": name}, "spec": {"source": {"targetRevision": "dev"}},
            "status": {"sync": {"status": sync, "revision": "0123456789abcdef"}, "health": {"status": health},
                       "history": [{"id": 1, "revision": "abc", "deployedAt": "2026-01-01T00:00:00Z"}]}}  # fmt: skip


class FakeCluster:
    """Answers the Kubernetes API, GitHub and the public endpoints from dicts."""

    def __init__(self) -> None:
        self.pods: dict[str, list[dict]] = {}
        self.apps: list[dict] = []
        self.cnpg: list[dict] = []
        self.logs_text = ""
        self.images_yaml = ""
        self.runs: list[dict] = []
        self.health_status = 200
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path, host = request.url.path, request.url.host
        assert request.method == "GET", "the server must only ever GET"
        assert "/secrets" not in path, "the server must never touch Secrets"
        if host == "kube":
            if path.endswith("/applications"):
                return httpx.Response(200, json={"items": self.apps})
            if path.startswith("/apis/argoproj.io") and "/applications/" in path:
                name = path.rsplit("/", 1)[1]
                return httpx.Response(200, json=next(a for a in self.apps if a["metadata"]["name"] == name))
            if path.endswith("/clusters"):
                return httpx.Response(200, json={"items": self.cnpg})
            if path.endswith("/log"):
                return httpx.Response(200, text=self.logs_text)
            if path == "/api/v1/namespaces":
                names = sorted({*self.pods, "kube-system"})
                return httpx.Response(200, json={"items": [{"metadata": {"name": n}} for n in names]})
            if path == "/api/v1/pods":
                return httpx.Response(200, json={"items": [p for ps in self.pods.values() for p in ps]})
            if path.endswith("/pods"):
                ns = path.split("/")[4]
                return httpx.Response(200, json={"items": self.pods.get(ns, [])})
            if path.endswith("/events"):
                return httpx.Response(200, json={"items": [
                    {"metadata": {"creationTimestamp": "2026-01-01T00:00:00Z"}, "type": "Warning",
                     "reason": "BackOff", "message": "back-off, password=hunter2 restarting",
                     "involvedObject": {"kind": "Pod", "name": "x"}}]})
            return httpx.Response(404, json={"message": "not found: " + path})
        if host == "api.github.com":
            if "/contents/" in path:
                return httpx.Response(200, text=self.images_yaml)
            if path.endswith("/runs"):
                return httpx.Response(200, json={"workflow_runs": self.runs})
            return httpx.Response(200, json=[])
        return httpx.Response(self.health_status, text='{"status":"ok"}')


@pytest.fixture
def cluster() -> FakeCluster:
    c = FakeCluster()
    c.images_yaml = (
        "images:\n  tags:\n"
        f'    backend: "{DIGEST_NEW}"  # sha-1\n    worker: "{DIGEST_NEW}"\n'
        f'    workerPods: "{DIGEST_NEW}"\n    frontend: "{DIGEST_NEW}"\n'
    )
    ns = "appstore-staging"
    c.pods[ns] = [
        pod("api-1", ns, "backend", DIGEST_NEW), pod("api-2", ns, "backend", DIGEST_NEW),
        pod("exec-1", ns, "worker", DIGEST_NEW), pod("deployer-1", ns, "worker-pods", DIGEST_NEW),
        pod("front-1", ns, "frontend", DIGEST_NEW),
    ]  # fmt: skip
    c.apps = [argo_app("staging-root"), argo_app("staging-appstore"), argo_app("prod-appstore")]
    c.cnpg = [{"metadata": {"namespace": ns, "name": "postgres-cluster"},
               "status": {"phase": "Cluster in healthy state", "instances": 1, "readyInstances": 1}}]  # fmt: skip
    c.runs = [{"id": 1, "name": "K8s - roll out an image", "head_branch": "dev", "head_sha": "abcdef123",
               "status": "completed", "conclusion": "success", "html_url": "https://x", "event": "workflow_dispatch",
               "created_at": "2026-01-01T00:00:00Z", "display_title": "bump"}]  # fmt: skip
    return c


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings.from_env({
        "MCP_PUBLIC_URL": "https://mcp.example.org", "ZONE": "zone.example.org", "DATA_DIR": str(tmp_path),
        "GITHUB_CLIENT_ID": "cid", "GITHUB_CLIENT_SECRET": "csecret",
        "TOKEN_SIGNING_KEY": Fernet.generate_key().decode(),
    })  # fmt: skip


@pytest.fixture
def toolbox(cluster: FakeCluster, settings: Settings) -> Toolbox:
    def client(base: str | None = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(cluster.handler), base_url=base or "")

    http = client()
    return Toolbox(settings, KubeClient(client("https://kube")), GitHub(http, settings.github_org), http)


def jsonrpc(method: str, params: dict | None = None, id_: int = 1) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}})


Factory = Callable[..., Any]
