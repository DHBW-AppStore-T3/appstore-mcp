# Snippet for CLAUDE.md of the component repos and the harness

```markdown
## Checking staging after a push

Staging (`appstore-staging`, branch `dev`) deploys itself: CI -> `k8s-bump.yml` -> Argo CD. Before you call a
change to `dev` done, verify it with the `appstore` MCP server (`claude mcp add --transport http appstore
https://appstore-mcp-staging.t3-k8s.s242437-at-student-dhbw-mannheim-de.users.dhbw.site/mcp`, then `/mcp` ->
Authenticate): `staging_verdict` must say `healthy` (`progressing`: wait and ask again; `unhealthy`: diagnose with
`rollout_status`, `argocd_app`, `pods`, `events`, `logs`). Use the `verify-staging` skill. The tools are read-only;
promotion to `main` stays a human decision. Never paste tokens or log excerpts with credentials into PRs.
```
