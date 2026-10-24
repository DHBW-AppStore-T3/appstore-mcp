# appstore-mcp

A **remote, read-only MCP server** (streamable HTTP) for the DHBW AppStore T3 team. It lets Claude Code
agents judge an automatic staging rollout: Argo CD state, pods and rollout digests, events and logs
(bounded, redacted), CloudNativePG, public health endpoints, GitHub Actions runs and open pull requests,
certificates and nodes. It replaces the retired Hermes agent.

- **Read-only by construction.** The server only issues `GET`s, its ServiceAccount has `get/list/watch`
  and no access to `secrets` or `pods/exec`, and every tool is annotated `readOnlyHint`.
- **Student apps stay private.** `dep-*` namespaces expose counts and status only: no pod names, logs or events.
- **Secrets never leave.** A redaction filter scrubs tokens, passwords, URLs with credentials and keys from
  all output and from our own logs.
- **Auth:** OAuth 2.1 (authorization code + PKCE, dynamic client registration) with **GitHub** as identity
  provider, restricted to members of the org `DHBW-AppStore-T3`; plus **static tokens** for CI and agents.

## Connect (everyone on the team)

```bash
# staging cluster namespace (the one agents check after a push to dev)
claude mcp add --transport http appstore https://appstore-mcp-staging.t3-k8s.s242437-at-student-dhbw-mannheim-de.users.dhbw.site/mcp
# then, in Claude Code:  /mcp  ->  appstore  ->  Authenticate   (GitHub login opens in the browser)
```

Prod instance (same tools, same data, separate deployment): replace the host by
`appstore-mcp.t3-k8s.s242437-at-student-dhbw-mannheim-de.users.dhbw.site`. Both can read both
environments; pass `env: "prod"` to the tools.

To share the server with the whole repo checkout, commit a `.mcp.json`:

```json
{ "mcpServers": { "appstore": { "type": "http",
  "url": "https://appstore-mcp-staging.t3-k8s.s242437-at-student-dhbw-mannheim-de.users.dhbw.site/mcp" } } }
```

### CI and unattended agents (static token)

A teammate with `kubectl` access to the cluster mints a token (see [docs/OPERATIONS.md](docs/OPERATIONS.md)),
then:

```bash
claude mcp add --transport http appstore https://<host>/mcp --header "Authorization: Bearer $APPSTORE_MCP_TOKEN"
```

Only the SHA-256 of a token is stored in the cluster; revoke it by deleting its line from the Secret.

## Tools

| Tool | What it answers |
| --- | --- |
| `staging_verdict(env)` | **Start here.** Folds everything below into `healthy` / `progressing` / `unhealthy` with reasons |
| `rollout_status(env)` | digest committed in `deployment` `k8s/images/<env>.yaml` vs digests the pods run, per component (`converged`, `rolling`, `stale`, `absent`) |
| `argocd_apps(env)`, `argocd_app(name)` | sync, health, last operation, unhealthy resources, deployment history |
| `pods(ns)`, `deployments(ns)` | readiness, restarts, container states, CrashLoop/ImagePull problems, rollout completeness |
| `events(ns)`, `logs(ns, pod)` | Warning events; last <= 300 log lines (64 KiB), redacted |
| `dep_namespaces()` | counts and status of the student namespaces `dep-*` |
| `cnpg_clusters()` | CloudNativePG phase, instances, primary, backups |
| `health(env)` | public frontend, `/api/health`, Keycloak realm `dhbw` |
| `ingress_and_certificates()` | ingress hosts and cert-manager certificates (ready, expiry) |
| `nodes()` | node conditions, capacity, allocatable, current usage |
| `github_runs(repo, branch, workflow)`, `github_open_prs(repo)` | component CI, `k8s-bump.yml`, open PRs |

Readable namespaces: `appstore-staging`, `appstore-prod`, `argocd`, `cert-manager`, `cnpg-system`,
`kube-system` (and `dep-*` as aggregates). Configurable with `READABLE_NAMESPACES`.

## For the harness

[docs/harness-skill/verify-staging/SKILL.md](docs/harness-skill/verify-staging/SKILL.md) is the skill
the agents use after a push (copy it to `.claude/skills/verify-staging/` of a repo), and
[docs/CLAUDE-snippet.md](docs/CLAUDE-snippet.md) a short block for `CLAUDE.md`.

## Operating it

[docs/OPERATIONS.md](docs/OPERATIONS.md): the one-time human steps (GitHub OAuth app, `kubectl create secret`),
token minting and rotation. Deployed by Argo CD from `deployment` (`k8s/charts/appstore-mcp`).

## Develop

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && pytest
```

Tests mock the Kubernetes API, GitHub and the public endpoints with `httpx.MockTransport` (the fakes assert
that no request is anything but a `GET` and nothing touches `/secrets`) and drive the whole OAuth flow
through the real ASGI app.

Configuration is by environment variables, see `src/appstore_mcp/config.py`. The chart in `deployment`
sets them; the secret ones come from the Secret `appstore-mcp`.

## Design notes

- Tokens are stateless where possible: access tokens are Fernet-sealed (1 h); refresh tokens (7 d, rotated),
  authorization codes (5 min, single use), pending logins and registered clients live in a small SQLite
  file on the volume `/data`. Losing it only forces a fresh login.
- The GitHub user token (`read:org`) checks the org membership at the login and again at every refresh, so
  leaving the org ends the access within the hour. It is stored Fernet-sealed with the refresh token, never
  in plain text.
- Clients may only send a login back to a loopback address (local MCP clients) or to one of
  `ALLOWED_REDIRECT_URIS` (default: the hosted Claude clients' callbacks). There is no consent page, so a
  client with any other https redirect could collect an org member's login.
- The Kubernetes client is a small `httpx` wrapper (GET only) instead of the official `kubernetes`
  package: smaller image, trivially mockable, and incapable of writing.
