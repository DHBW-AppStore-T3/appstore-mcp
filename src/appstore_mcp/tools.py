"""The read-only tools. Every method returns plain JSON-able data, bounded in size."""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import httpx
import yaml

from .config import DEP_PREFIX, NAME_RE, Env, Settings
from .github import GitHub
from .kube import KubeClient, KubeError

IMAGE_REGISTRY = "ghcr.io/dhbw-appstore-t3/"
# key in k8s/images/<env>.yaml -> image name on ghcr.io
COMPONENT_IMAGES = {
    "backend": "backend",
    "worker": "worker",
    "workerPods": "worker-pods",
    "frontend": "frontend",
    "appstoreMcp": "appstore-mcp",
}
MAX_LOG_LINES = 300
MAX_LOG_BYTES = 64 * 1024
MAX_EVENTS = 100
BAD_WAITING = {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
               "CreateContainerError", "InvalidImageName", "RunContainerError"}  # fmt: skip


class ToolError(Exception):
    """A problem with the request (shown to the agent as the tool error)."""


def _digest(image_ref: str) -> str:
    return image_ref.split("@", 1)[1] if "@" in image_ref else ""


def _image_name(image_ref: str) -> str:
    ref = image_ref.split("@", 1)[0]
    if not ref.startswith(IMAGE_REGISTRY):
        return ""
    return ref[len(IMAGE_REGISTRY):].split(":", 1)[0]


def summarize_pod(pod: dict[str, Any]) -> dict[str, Any]:
    status = pod.get("status", {})
    containers = []
    problems: list[str] = []
    restarts = 0
    for cs in status.get("containerStatuses", []) or []:
        state = cs.get("state", {})
        waiting = state.get("waiting", {}).get("reason")
        terminated = state.get("terminated", {})
        restarts += cs.get("restartCount", 0)
        if waiting in BAD_WAITING:
            problems.append(f"{cs['name']}: {waiting}")
        containers.append({
            "name": cs["name"], "ready": cs.get("ready", False), "restarts": cs.get("restartCount", 0),
            "image": cs.get("image", ""), "imageID": cs.get("imageID", ""),
            "state": waiting or (terminated.get("reason") if terminated else None) or next(iter(state), "unknown"),
            "lastTerminated": (cs.get("lastState", {}).get("terminated") or {}).get("reason"),
        })  # fmt: skip
    phase = status.get("phase", "Unknown")
    ready = all(c["ready"] for c in containers) if containers else False
    if phase not in ("Succeeded",) and not ready and not problems:
        for c in status.get("conditions", []) or []:
            if c.get("type") == "PodScheduled" and c.get("status") == "False":
                problems.append(f"unschedulable: {c.get('message', '')[:200]}")
    return {
        "name": pod["metadata"]["name"],
        "phase": phase,
        "ready": ready or phase == "Succeeded",
        "restarts": restarts,
        "node": pod.get("spec", {}).get("nodeName"),
        "startTime": status.get("startTime"),
        "containers": containers,
        "problems": problems,
        "deleting": bool(pod["metadata"].get("deletionTimestamp")),
    }


def _app_summary(app: dict[str, Any]) -> dict[str, Any]:
    st = app.get("status", {})
    op = st.get("operationState", {}) or {}
    return {
        "name": app["metadata"]["name"],
        "sync": st.get("sync", {}).get("status"),
        "health": st.get("health", {}).get("status"),
        "targetRevision": app.get("spec", {}).get("source", {}).get("targetRevision"),
        "revision": (st.get("sync", {}).get("revision") or "")[:12],
        "operation": {"phase": op.get("phase"), "message": (op.get("message") or "")[:300],
                      "finishedAt": op.get("finishedAt")} if op else None,
        "conditions": [{"type": c.get("type"), "message": (c.get("message") or "")[:300]}
                       for c in st.get("conditions", []) or []],
        "unhealthyResources": [
            {"kind": r.get("kind"), "name": r.get("name"), "health": r.get("health", {}).get("status"),
             "sync": r.get("status")}
            for r in st.get("resources", []) or []
            if r.get("health", {}).get("status") not in (None, "Healthy") or r.get("status") == "OutOfSync"
        ][:20],
    }  # fmt: skip


class Toolbox:
    def __init__(self, settings: Settings, kube: KubeClient, gh: GitHub, http: httpx.AsyncClient):
        self.s = settings
        self.kube = kube
        self.gh = gh
        self.http = http

    # ------------------------------------------------------------ helpers
    def _env(self, env: str | None) -> Env:
        name = env or self.s.default_env
        if name not in self.s.environments:
            raise ToolError(f"unknown environment {name!r}; use one of {sorted(self.s.environments)}")
        return self.s.environments[name]

    def _check_ns(self, namespace: str, *, allow_dep: bool = False) -> None:
        if not NAME_RE.match(namespace):
            raise ToolError("invalid namespace name")
        if namespace.startswith(DEP_PREFIX):
            if not allow_dep:
                raise ToolError("dep-* namespaces hold student apps: only counts and status are available "
                                "(use dep_namespaces)")
            return
        if namespace not in self.s.readable_namespaces:
            raise ToolError(f"namespace not readable; allowed: {', '.join(self.s.readable_namespaces)}, "
                            "dep-* (status only)")

    # ------------------------------------------------------------ Argo CD
    async def argocd_apps(self, env: str | None = None) -> dict[str, Any]:
        """Argo CD Applications with sync status, health, revision and unhealthy resources.
        env: staging | prod (default: all applications)."""
        apps = await self.kube.items(
            f"/apis/argoproj.io/v1alpha1/namespaces/{self.s.argocd_namespace}/applications")
        out = [_app_summary(a) for a in apps]
        if env:
            prefix = self._env(env).argo_prefix
            out = [a for a in out if a["name"].startswith(prefix)]
        return {"applications": sorted(out, key=lambda a: a["name"])}

    async def argocd_app(self, name: str) -> dict[str, Any]:
        """One Argo CD Application in detail: sync/health, last operation, deployment history."""
        if not NAME_RE.match(name):
            raise ToolError("invalid application name")
        app = await self.kube.get(
            f"/apis/argoproj.io/v1alpha1/namespaces/{self.s.argocd_namespace}/applications/{name}")
        st = app.get("status", {})
        history = [{"id": h.get("id"), "revision": (h.get("revision") or "")[:12],
                    "deployedAt": h.get("deployedAt"), "startedAt": h.get("deployStartedAt")}
                   for h in (st.get("history") or [])[-10:]]  # fmt: skip
        return {**_app_summary(app), "history": history, "reconciledAt": st.get("reconciledAt"),
                "summaryImages": (st.get("summary") or {}).get("images", [])}  # fmt: skip

    # ------------------------------------------------------------ workloads
    async def dep_namespaces(self) -> dict[str, Any]:
        """Student app namespaces dep-*: counts and status only (no names of pods, logs or events)."""
        namespaces = await self.kube.items("/api/v1/namespaces")
        deps = [n["metadata"]["name"] for n in namespaces if n["metadata"]["name"].startswith(DEP_PREFIX)]
        pods = await self.kube.items("/api/v1/pods")
        per: dict[str, dict[str, int]] = {d: {"pods": 0, "ready": 0, "restarts": 0, "problems": 0}
                                          for d in deps}  # fmt: skip
        for p in pods:
            ns = p["metadata"]["namespace"]
            if ns in per:
                s = summarize_pod(p)
                per[ns]["pods"] += 1
                per[ns]["ready"] += int(s["ready"])
                per[ns]["restarts"] += s["restarts"]
                per[ns]["problems"] += int(bool(s["problems"]))
        return {
            "namespaces": len(deps),
            "pods": sum(v["pods"] for v in per.values()),
            "podsNotReady": sum(v["pods"] - v["ready"] for v in per.values()),
            "podsWithProblems": sum(v["problems"] for v in per.values()),
            "perNamespace": per,
        }

    async def pods(self, namespace: str) -> dict[str, Any]:
        """Pods of a namespace (phase, readiness, restarts, container states, problems).
        For dep-* namespaces only the aggregate is returned."""
        self._check_ns(namespace, allow_dep=True)
        items = await self.kube.items(f"/api/v1/namespaces/{namespace}/pods")
        summaries = [summarize_pod(p) for p in items]
        if namespace.startswith(DEP_PREFIX):
            return {"namespace": namespace, "pods": len(summaries),
                    "ready": sum(s["ready"] for s in summaries),
                    "restarts": sum(s["restarts"] for s in summaries),
                    "problems": sum(bool(s["problems"]) for s in summaries)}  # fmt: skip
        for s in summaries:  # image IDs are long; keep names and digests only
            for c in s["containers"]:
                c["imageID"] = _digest(c["imageID"]) or c["imageID"][-80:]
        return {"namespace": namespace, "pods": summaries}

    async def deployments(self, namespace: str) -> dict[str, Any]:
        """Deployments, StatefulSets and DaemonSets of a namespace: replicas, availability, images."""
        self._check_ns(namespace)
        out = []
        for kind, path in (("Deployment", "deployments"), ("StatefulSet", "statefulsets"),
                           ("DaemonSet", "daemonsets")):  # fmt: skip
            for d in await self.kube.items(f"/apis/apps/v1/namespaces/{namespace}/{path}"):
                st, spec = d.get("status", {}), d.get("spec", {})
                want = spec.get("replicas", st.get("desiredNumberScheduled", 1))
                ready = st.get("readyReplicas", st.get("numberReady", 0)) or 0
                updated = st.get("updatedReplicas", st.get("updatedNumberScheduled", 0)) or 0
                conds = {c["type"]: c for c in st.get("conditions", []) or []}
                out.append({
                    "kind": kind, "name": d["metadata"]["name"], "desired": want, "ready": ready,
                    "updated": updated, "generation": d["metadata"].get("generation"),
                    "observedGeneration": st.get("observedGeneration"),
                    "images": [c["image"] for c in spec["template"]["spec"]["containers"]],
                    "rolloutComplete": ready == want == updated
                    and st.get("observedGeneration") == d["metadata"].get("generation"),
                    "progressing": (conds.get("Progressing") or {}).get("reason"),
                    "failure": next((c.get("message", "")[:300] for c in conds.values()
                                     if c["type"] in ("ReplicaFailure",) and c["status"] == "True"), None),
                })  # fmt: skip
        return {"namespace": namespace, "workloads": out}

    async def events(self, namespace: str, warnings_only: bool = True, limit: int = 40) -> dict[str, Any]:
        """Recent Kubernetes events of a namespace (newest first, bounded). Not available for dep-*."""
        self._check_ns(namespace)
        params: dict[str, Any] = {}
        if warnings_only:
            params["fieldSelector"] = "type=Warning"
        items = await self.kube.items(f"/api/v1/namespaces/{namespace}/events", **params)

        def when(e: dict[str, Any]) -> str:
            return e.get("lastTimestamp") or e.get("eventTime") or e["metadata"].get("creationTimestamp", "")

        items.sort(key=when, reverse=True)
        limit = max(1, min(limit, MAX_EVENTS))
        return {"namespace": namespace, "events": [{
            "time": when(e), "type": e.get("type"), "reason": e.get("reason"), "count": e.get("count", 1),
            "object": f"{e.get('involvedObject', {}).get('kind')}/{e.get('involvedObject', {}).get('name')}",
            "message": (e.get("message") or "")[:400],
        } for e in items[:limit]]}  # fmt: skip

    async def logs(self, namespace: str, pod: str, container: str | None = None, tail: int = 100,
                   previous: bool = False) -> dict[str, Any]:
        """Last log lines of a pod container (bounded, secrets redacted). Not available for dep-*."""
        self._check_ns(namespace)
        if not NAME_RE.match(pod) or (container and not NAME_RE.match(container)):
            raise ToolError("invalid pod or container name")
        params: dict[str, Any] = {"tailLines": max(1, min(tail, MAX_LOG_LINES)), "limitBytes": MAX_LOG_BYTES,
                                  "timestamps": "true"}  # fmt: skip
        if container:
            params["container"] = container
        if previous:
            params["previous"] = "true"
        text = await self.kube.text(f"/api/v1/namespaces/{namespace}/pods/{pod}/log", **params)
        return {"namespace": namespace, "pod": pod, "container": container, "lines": text.splitlines()}

    # ------------------------------------------------------------ platform
    async def cnpg_clusters(self, namespace: str | None = None) -> dict[str, Any]:
        """CloudNativePG clusters: phase, instances, primary, replication and backup state."""
        base = "/apis/postgresql.cnpg.io/v1"
        if namespace:
            self._check_ns(namespace)
            path = f"{base}/namespaces/{namespace}/clusters"
        else:
            path = f"{base}/clusters"
        out = []
        for c in await self.kube.items(path):
            st = c.get("status", {})
            out.append({
                "namespace": c["metadata"]["namespace"], "name": c["metadata"]["name"],
                "phase": st.get("phase"), "phaseReason": st.get("phaseReason"),
                "instances": st.get("instances"), "readyInstances": st.get("readyInstances"),
                "currentPrimary": st.get("currentPrimary"), "image": st.get("image"),
                "lastSuccessfulBackup": st.get("lastSuccessfulBackup"),
                "conditions": [{"type": x.get("type"), "status": x.get("status"), "message": (x.get("message") or "")[:200]}
                               for x in st.get("conditions", []) or []],
            })  # fmt: skip
        return {"clusters": out}

    async def ingress_and_certificates(self, namespace: str | None = None) -> dict[str, Any]:
        """Ingresses (hosts, address) and cert-manager Certificates (ready, expiry) incl. pending orders."""
        ing_path = f"/apis/networking.k8s.io/v1/namespaces/{namespace}/ingresses" if namespace \
            else "/apis/networking.k8s.io/v1/ingresses"  # fmt: skip
        cert_path = f"/apis/cert-manager.io/v1/namespaces/{namespace}/certificates" if namespace \
            else "/apis/cert-manager.io/v1/certificates"  # fmt: skip
        if namespace:
            self._check_ns(namespace)
        ingresses = [{
            "namespace": i["metadata"]["namespace"], "name": i["metadata"]["name"],
            "class": i["spec"].get("ingressClassName"),
            "hosts": [r.get("host") for r in i["spec"].get("rules", [])],
            "address": [a.get("ip") or a.get("hostname")
                        for a in i.get("status", {}).get("loadBalancer", {}).get("ingress", []) or []],
        } for i in await self.kube.items(ing_path) if not i["metadata"]["namespace"].startswith(DEP_PREFIX)]  # fmt: skip
        certs = []
        try:
            for c in await self.kube.items(cert_path):
                if c["metadata"]["namespace"].startswith(DEP_PREFIX):
                    continue
                st = c.get("status", {})
                ready = next((x for x in st.get("conditions", []) or [] if x.get("type") == "Ready"), {})
                certs.append({
                    "namespace": c["metadata"]["namespace"], "name": c["metadata"]["name"],
                    "ready": ready.get("status"), "message": (ready.get("message") or "")[:200],
                    "notAfter": st.get("notAfter"), "renewalTime": st.get("renewalTime"),
                    "dnsNames": c.get("spec", {}).get("dnsNames", [])[:10],
                })  # fmt: skip
        except KubeError as e:
            certs = [{"error": str(e)}]
        return {"ingresses": ingresses, "certificates": certs}

    async def nodes(self) -> dict[str, Any]:
        """Nodes: conditions, capacity/allocatable and current usage (metrics-server)."""
        usage: dict[str, Any] = {}
        try:
            for m in await self.kube.items("/apis/metrics.k8s.io/v1beta1/nodes"):
                usage[m["metadata"]["name"]] = m.get("usage", {})
        except KubeError:
            pass
        out = []
        for n in await self.kube.items("/api/v1/nodes"):
            st = n.get("status", {})
            conds = {c["type"]: c["status"] for c in st.get("conditions", []) or []}
            out.append({
                "name": n["metadata"]["name"],
                "ready": conds.get("Ready") == "True",
                "pressure": [k for k in ("MemoryPressure", "DiskPressure", "PIDPressure")
                             if conds.get(k) == "True"],  # fmt: skip
                "capacity": {k: st.get("capacity", {}).get(k) for k in ("cpu", "memory", "pods", "ephemeral-storage")},
                "allocatable": {k: st.get("allocatable", {}).get(k) for k in ("cpu", "memory", "pods")},
                "usage": usage.get(n["metadata"]["name"]),
                "kubelet": st.get("nodeInfo", {}).get("kubeletVersion"),
            })  # fmt: skip
        return {"nodes": out}

    # ------------------------------------------------------------ rollout
    async def desired_images(self, env: Env) -> dict[str, str]:
        text = await self.gh.raw("deployment", env.branch, f"k8s/images/{env.name}.yaml")
        tags = (yaml.safe_load(text) or {}).get("images", {}).get("tags", {})
        return {k: str(v) for k, v in tags.items() if k in COMPONENT_IMAGES}

    async def rollout_status(self, env: str | None = None) -> dict[str, Any]:
        """Per component (backend, worker, workerPods, frontend, appstoreMcp): the digest committed in
        deployment k8s/images/<env>.yaml vs the digests the pods run. state: converged | rolling |
        stale (nothing runs the committed digest) | absent."""
        e = self._env(env)
        desired = await self.desired_images(e)
        raw_items = await self.kube.items(f"/api/v1/namespaces/{e.namespace}/pods")
        pods = [summarize_pod(p) for p in raw_items]
        raw_pods = {p["metadata"]["name"]: p for p in raw_items}
        comps: dict[str, Any] = {}
        for key, image in COMPONENT_IMAGES.items():
            want = desired.get(key, "")
            running = []
            for s in pods:
                if s["phase"] not in ("Running", "Pending"):
                    continue
                for c in raw_pods[s["name"]]["spec"]["containers"]:
                    if _image_name(c["image"]) == image:
                        cs = next((x for x in s["containers"] if x["name"] == c["name"]), {})
                        running.append({"pod": s["name"], "specDigest": _digest(c["image"]),
                                        "runningDigest": _digest(cs.get("imageID", "")),
                                        "ready": cs.get("ready", False)})  # fmt: skip
            if not want.startswith("sha256:"):
                state = "no-digest-committed"
            elif not running:
                state = "absent"
            elif all(r["specDigest"] == want and r["ready"] for r in running):
                state = "converged"
            elif any(r["specDigest"] == want for r in running):
                state = "rolling"
            else:
                state = "stale"
            comps[key] = {"image": IMAGE_REGISTRY + image, "committedDigest": want, "state": state,
                          "pods": running}  # fmt: skip
        return {"env": e.name, "branch": e.branch, "components": comps}

    # ------------------------------------------------------------ health
    async def health(self, env: str | None = None) -> dict[str, Any]:
        """Probe the public endpoints: AppStore frontend, API /health, Keycloak realm dhbw."""
        e = self._env(env)
        targets = {
            "frontend": f"{e.app_url}/",
            "api": f"{e.app_url}/api/health",
            "keycloak": f"{e.sso_url}/realms/dhbw/.well-known/openid-configuration",
        }

        async def probe(url: str) -> dict[str, Any]:
            try:
                t0 = time.monotonic()
                r = await self.http.get(url, timeout=8.0, follow_redirects=False)
                return {"url": url, "status": r.status_code, "ok": 200 <= r.status_code < 400,
                        "ms": int((time.monotonic() - t0) * 1000), "body": r.text[:200] if "health" in url else ""}  # fmt: skip
            except httpx.HTTPError as ex:
                return {"url": url, "ok": False, "error": type(ex).__name__ + ": " + str(ex)[:150]}

        results = await asyncio.gather(*(probe(u) for u in targets.values()))
        return {"env": e.name, "endpoints": dict(zip(targets, results, strict=True))}

    # ------------------------------------------------------------ GitHub
    def _repo(self, repo: str) -> str:
        if repo not in self.s.repos:
            raise ToolError(f"repo not allowed; use one of {', '.join(self.s.repos)}")
        return repo

    async def github_runs(self, repo: str, branch: str | None = None, workflow: str | None = None,
                          limit: int = 8) -> dict[str, Any]:
        """Recent GitHub Actions runs of a repo of the org (component CI, k8s-bump.yml in deployment, ...).
        workflow: optional file name such as ci.yml or k8s-bump.yml."""
        repo = self._repo(repo)
        if workflow and not re.fullmatch(r"[\w.\-]+\.ya?ml", workflow):
            raise ToolError("invalid workflow file name")
        base = f"/repos/{self.gh.org}/{repo}/actions"
        path = f"{base}/workflows/{workflow}/runs" if workflow else f"{base}/runs"
        params: dict[str, Any] = {"per_page": max(1, min(limit, 30))}
        if branch:
            if not re.fullmatch(r"[\w./\-]{1,100}", branch):
                raise ToolError("invalid branch")
            params["branch"] = branch
        data = await self.gh.api(path, **params)
        return {"repo": repo, "runs": [{
            "id": r["id"], "workflow": r.get("name"), "title": (r.get("display_title") or "")[:120],
            "event": r.get("event"), "branch": r.get("head_branch"), "sha": (r.get("head_sha") or "")[:7],
            "status": r.get("status"), "conclusion": r.get("conclusion"),
            "createdAt": r.get("created_at"), "url": r.get("html_url"),
        } for r in data.get("workflow_runs", [])]}  # fmt: skip

    async def github_open_prs(self, repo: str | None = None) -> dict[str, Any]:
        """Open pull requests of one repo, or of all configured repos."""
        repos = [self._repo(repo)] if repo else list(self.s.repos)

        async def one(r: str) -> list[dict[str, Any]]:
            try:
                prs = await self.gh.api(f"/repos/{self.gh.org}/{r}/pulls", state="open", per_page=20)
            except httpx.HTTPError:
                return []
            return [{"repo": r, "number": p["number"], "title": p["title"][:120], "author": p["user"]["login"],
                     "base": p["base"]["ref"], "head": p["head"]["ref"], "draft": p.get("draft", False),
                     "updatedAt": p["updated_at"], "url": p["html_url"]} for p in prs]  # fmt: skip

        return {"pullRequests": [pr for batch in await asyncio.gather(*(one(r) for r in repos)) for pr in batch]}

    # ------------------------------------------------------------ verdict
    async def staging_verdict(self, env: str | None = None) -> dict[str, Any]:
        """One call to judge an automatic rollout: Argo apps, rollout convergence, pods, CNPG, public
        health and the latest CI/bump runs, folded into verdict healthy | progressing | unhealthy with the
        reasons. Use after a push to dev (staging) before reporting success."""
        e = self._env(env)
        parts = await asyncio.gather(
            self.argocd_apps(e.name), self.rollout_status(e.name), self.pods(e.namespace),
            self.cnpg_clusters(e.namespace), self.health(e.name),
            self.github_runs("deployment", branch=e.branch, workflow="k8s-bump.yml", limit=3),
            return_exceptions=True,
        )  # fmt: skip
        names = ["argocd", "rollout", "pods", "cnpg", "health", "bumpRuns"]
        data = dict(zip(names, parts, strict=True))
        bad: list[str] = []
        rolling: list[str] = []
        for n, v in data.items():
            if isinstance(v, BaseException):
                bad.append(f"{n}: could not be read ({type(v).__name__})")
                data[n] = {"error": str(v)[:200]}
        if not isinstance(data["argocd"], dict) or "applications" not in data["argocd"]:
            pass
        else:
            for a in data["argocd"]["applications"]:
                if a["health"] == "Progressing" or (a["operation"] or {}).get("phase") == "Running":
                    rolling.append(f"{a['name']} is progressing")
                elif a["health"] != "Healthy" or a["sync"] != "Synced":
                    bad.append(f"{a['name']}: sync={a['sync']} health={a['health']}")
        if "components" in data["rollout"]:
            for k, c in data["rollout"]["components"].items():
                if c["state"] == "rolling":
                    rolling.append(f"{k} is rolling out")
                elif c["state"] in ("stale", "absent"):
                    rolling.append(f"{k}: {c['state']} (committed digest not running yet)")
        if "pods" in data["pods"]:
            for p in data["pods"]["pods"]:
                if p["problems"]:
                    bad.append(f"pod {p['name']}: {'; '.join(p['problems'])}")
                elif not p["ready"] and p["phase"] != "Succeeded" and not p["deleting"]:
                    rolling.append(f"pod {p['name']} not ready ({p['phase']})")
        if "clusters" in data["cnpg"]:
            for c in data["cnpg"]["clusters"]:
                if not (c["phase"] or "").lower().startswith("cluster in healthy"):
                    bad.append(f"cnpg {c['name']}: {c['phase']}")
        if "endpoints" in data["health"]:
            for k, ep in data["health"]["endpoints"].items():
                if not ep["ok"]:
                    bad.append(f"{k} endpoint {ep.get('status') or ep.get('error')}")
        if "runs" in data["bumpRuns"] and data["bumpRuns"]["runs"]:
            last = data["bumpRuns"]["runs"][0]
            if last["conclusion"] == "failure":
                bad.append(f"last k8s-bump.yml run failed: {last['url']}")
        verdict = "unhealthy" if bad else "progressing" if rolling else "healthy"
        return {"env": e.name, "verdict": verdict, "problems": bad, "inProgress": rolling,
                "details": data}  # fmt: skip
