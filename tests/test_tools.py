import pytest

from appstore_mcp.tools import ToolError

from .conftest import DIGEST_NEW, DIGEST_OLD, pod


async def test_verdict_healthy(toolbox):
    v = await toolbox.staging_verdict("staging")
    assert v["verdict"] == "healthy", v["problems"] + v["inProgress"]
    assert v["details"]["rollout"]["components"]["backend"]["state"] == "converged"


async def test_verdict_unhealthy_on_crashloop_and_argo_degraded(toolbox, cluster):
    cluster.pods["appstore-staging"].append(
        pod("api-3", "appstore-staging", "backend", DIGEST_NEW, ready=False, waiting="CrashLoopBackOff", restarts=5))
    cluster.apps[1] = {**cluster.apps[1], "status": {**cluster.apps[1]["status"], "health": {"status": "Degraded"}}}
    v = await toolbox.staging_verdict("staging")
    assert v["verdict"] == "unhealthy"
    text = " ".join(v["problems"])
    assert "CrashLoopBackOff" in text and "staging-appstore" in text


async def test_verdict_progressing_while_old_digest_still_runs(toolbox, cluster):
    ns = "appstore-staging"
    cluster.pods[ns][0] = pod("api-1", ns, "backend", DIGEST_OLD)
    v = await toolbox.staging_verdict("staging")
    assert v["verdict"] == "progressing"
    assert v["details"]["rollout"]["components"]["backend"]["state"] == "rolling"


async def test_rollout_stale_when_nothing_runs_committed_digest(toolbox, cluster):
    ns = "appstore-staging"
    cluster.pods[ns] = [pod("api-1", ns, "backend", DIGEST_OLD)]
    r = await toolbox.rollout_status("staging")
    assert r["components"]["backend"]["state"] == "stale"
    assert r["components"]["worker"]["state"] == "absent"


async def test_verdict_unhealthy_when_public_api_down(toolbox, cluster):
    cluster.health_status = 502
    v = await toolbox.staging_verdict("staging")
    assert v["verdict"] == "unhealthy" and any("502" in p for p in v["problems"])


async def test_failed_bump_run_is_reported(toolbox, cluster):
    cluster.runs[0]["conclusion"] = "failure"
    v = await toolbox.staging_verdict("staging")
    assert any("k8s-bump" in p for p in v["problems"])


async def test_dep_namespaces_are_aggregated_only(toolbox, cluster):
    cluster.pods["dep-1234abcd"] = [pod("secret-app-pod", "dep-1234abcd", "x", DIGEST_NEW, restarts=2)]
    summary = await toolbox.pods("dep-1234abcd")
    assert summary == {"namespace": "dep-1234abcd", "pods": 1, "ready": 1, "restarts": 2, "problems": 0}
    overview = await toolbox.dep_namespaces()
    assert overview["namespaces"] == 1 and "secret-app-pod" not in str(overview)
    for call in (toolbox.events("dep-1234abcd"), toolbox.logs("dep-1234abcd", "secret-app-pod"),
                 toolbox.deployments("dep-1234abcd")):  # fmt: skip
        with pytest.raises(ToolError):
            await call


async def test_unlisted_namespace_and_bad_names_are_refused(toolbox):
    for ns in ("default", "../etc", "kube-public"):
        with pytest.raises(ToolError):
            await toolbox.pods(ns)
    with pytest.raises(ToolError):
        await toolbox.logs("appstore-staging", "pod/../../secrets")


async def test_logs_are_bounded(toolbox, cluster):
    cluster.logs_text = "line\n" * 5
    await toolbox.logs("appstore-staging", "api-1", tail=100000)
    req = [r for r in cluster.requests if r.url.path.endswith("/log")][0]
    assert req.url.params["tailLines"] == "300" and req.url.params["limitBytes"] == str(64 * 1024)


async def test_events_limit_and_kind(toolbox):
    out = await toolbox.events("appstore-staging", limit=1000)
    assert len(out["events"]) == 1 and out["events"][0]["reason"] == "BackOff"


async def test_argocd_app_has_history(toolbox):
    app = await toolbox.argocd_app("staging-appstore")
    assert app["history"][0]["id"] == 1 and app["sync"] == "Synced"
    with pytest.raises(ToolError):
        await toolbox.argocd_app("../x")


async def test_argocd_apps_filters_by_env(toolbox):
    assert {a["name"] for a in (await toolbox.argocd_apps("staging"))["applications"]} == {
        "staging-root", "staging-appstore"}
    with pytest.raises(ToolError):
        await toolbox.argocd_apps("qa")


async def test_github_repo_allowlist(toolbox):
    with pytest.raises(ToolError):
        await toolbox.github_runs("some-other-org-repo")
    runs = await toolbox.github_runs("deployment", branch="dev", workflow="k8s-bump.yml")
    assert runs["runs"][0]["conclusion"] == "success"
    with pytest.raises(ToolError):
        await toolbox.github_runs("deployment", workflow="../x")


async def test_no_request_ever_touches_secrets_or_writes(toolbox, cluster):
    await toolbox.staging_verdict("staging")
    await toolbox.dep_namespaces()
    assert cluster.requests and all(r.method == "GET" for r in cluster.requests)
