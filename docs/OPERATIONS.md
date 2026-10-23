# Operating appstore-mcp (human steps)

Nothing secret is in git. The server reads these from the Secret `appstore-mcp` in its namespace
(`appstore-staging` / `appstore-prod`). `deployment/k8s/bootstrap.sh <env>` creates the Secret with the
generated key and empty placeholders; you fill in the rest once.

## 1. Create the GitHub OAuth app (once per environment)

GitHub: org **DHBW-AppStore-T3** -> Settings -> Developer settings -> OAuth Apps -> *New OAuth App*
(an org owner does this; use a separate app per environment).

| Field | staging | prod |
| --- | --- | --- |
| Application name | `appstore-mcp (staging)` | `appstore-mcp` |
| Homepage URL | `https://appstore-mcp-staging.<zone>` | `https://appstore-mcp.<zone>` |
| Authorization callback URL | `https://appstore-mcp-staging.<zone>/github/callback` | `https://appstore-mcp.<zone>/github/callback` |

`<zone>` = `t3-k8s.s242437-at-student-dhbw-mannheim-de.users.dhbw.site`. Do **not** enable device flow.
Generate a client secret. Then make sure the org lets the app read membership: Org settings -> Third-party
access -> OAuth app policy: approve `appstore-mcp`, otherwise `read:org` is denied for members.

## 2. Put the credentials into the cluster

Use a shell without history, or read the values from files; do not paste secrets into chat or git.

```bash
export KUBECONFIG=/path/to/kubeconfig-ma_wwi_24sea_appstore_g3.yaml
NS=appstore-staging   # or appstore-prod
kubectl -n "$NS" patch secret appstore-mcp --type merge -p \
  "{\"stringData\":{\"github-client-id\":\"<CLIENT_ID>\",\"github-client-secret\":\"<CLIENT_SECRET>\"}}"
# optional: a fine-grained PAT with read-only access to the org's repos (Actions: read, Pull requests: read,
# Contents: read) lifts the 60 requests/hour limit of unauthenticated GitHub calls and shows private repos
kubectl -n "$NS" patch secret appstore-mcp --type merge -p \
  "{\"stringData\":{\"github-api-token\":\"<READ_ONLY_PAT>\"}}"
kubectl -n "$NS" rollout restart deploy/appstore-mcp
```

`token-signing-key` (a Fernet key) and the empty `static-tokens` key are created by `bootstrap.sh`;
re-running the script never rotates them. Rotating `token-signing-key` logs everybody out.

## 3. Mint a static token for a CI job or unattended agent

```bash
python -m appstore_mcp.mint ci-staging-checker      # prints the token on stdout, "name:sha256" on stderr
```

Store the token (stdout) in the consumer's secret store. Append the `name:sha256` line (stderr) to the
Secret, keeping existing lines:

```bash
CUR=$(kubectl -n "$NS" get secret appstore-mcp -o jsonpath='{.data.static-tokens}' | base64 -d)
kubectl -n "$NS" patch secret appstore-mcp --type merge -p \
  "$(python3 -c 'import json,sys;print(json.dumps({"stringData":{"static-tokens":sys.argv[1]+"\n"+sys.argv[2]}}))' "$CUR" "<name:sha256>")"
kubectl -n "$NS" rollout restart deploy/appstore-mcp
```

Revoke: delete the line the same way. Only hashes are stored, so a leaked Secret does not leak tokens.

## 4. Checks

```bash
curl -s https://appstore-mcp-staging.<zone>/healthz
curl -s https://appstore-mcp-staging.<zone>/.well-known/oauth-authorization-server | head -c 300
kubectl -n appstore-staging logs deploy/appstore-mcp --tail=20
```

Then `claude mcp add ...`, `/mcp` -> Authenticate. A GitHub account outside the org is refused with
`access_denied`.
