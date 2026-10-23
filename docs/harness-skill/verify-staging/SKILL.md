---
name: verify-staging
description: "Use after a push or merged PR to a component's dev branch (backend, worker, frontend, deployment, appstore-mcp) to judge whether the automatic rollout to staging worked, using the appstore MCP server. Triggers on: verify staging, did staging deploy, check rollout, staging health."
---

# /verify-staging

Needs the MCP server `appstore` (see the appstore-mcp README: `claude mcp add --transport http appstore <url>/mcp`).
If its tools are missing, say so; do not guess the state and do not use kubectl or SSH.

Pipeline: push to `dev` -> component CI (lint, test, scan, build, push) -> `k8s-bump.yml` commits the digest
to `deployment` `k8s/images/staging.yaml` -> Argo CD `staging-appstore` rolls it out. Takes about 5-15 minutes.

## Steps

1. **CI and bump.** `github_runs(repo=<component>, branch="dev")` -> the push's CI run must be `completed/success`
   (`in_progress`: wait). Then `github_runs(repo="deployment", branch="dev", workflow="k8s-bump.yml")`: the
   newest run must be `success`.
2. **Verdict.** `staging_verdict(env="staging")`.
   - `healthy`: report success (step 5).
   - `progressing`: a rollout is in flight (see `inProgress`). Wait about 60 s and call again; up to 10 times.
   - `unhealthy`: step 3.
3. **Diagnose** (only on `unhealthy`, or `progressing` that never settles after ~15 min):
   - `rollout_status("staging")`: component `stale` means the new digest never reached the pods
     (bump failed, Argo not synced, ImagePull); `rolling` with old pods means the new pod is not ready.
   - `argocd_app("staging-appstore")`: sync/health message, unhealthy resources, history.
   - `pods("appstore-staging")` then `events("appstore-staging")` and `logs("appstore-staging", <pod>, previous=true)`
     for the pod in `problems` (CrashLoopBackOff: previous logs show why).
   - `health("staging")` for what users see; `cnpg_clusters()` if the database is involved.
4. Decide: a failure caused by your change -> fix forward on `dev` (or revert) and verify again. A failure that
   is not yours (CI infrastructure, cluster, another agent's PR in `github_open_prs`) -> report it and stop.
5. **Report** in the PR or to the human: verdict, the commit/digest verified (`rollout_status` shows the
   committed digest), and the evidence (run URLs, pod states). Never claim staging is fine from one
   `progressing` answer.

## Rules

- Promotion to `main`/prod is a human decision (`k8s/promote.sh`); this skill never triggers it.
- The tools are read-only. Output is bounded and secrets are redacted; do not try to work around that.
- `dep-*` namespaces (student apps) are status-only on purpose.
