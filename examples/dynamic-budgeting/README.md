# Dynamic monetary budgets with ext_authz

> **Advanced integration example:** this setup combines JWT validation,
> UserInfo, an external budget lookup, Envoy ext_authz, dynamic metadata,
> BackendTrafficPolicy, the Envoy rate-limit service, Redis, and AI Gateway
> response-cost accounting. Use the simpler `token_ratelimit` example when
> static limits or request-based rate limiting are sufficient.

This example demonstrates how a budget is selected for each request:

```text
JWT
  -> Envoy ext_authz gRPC Check
  -> /userinfo + budget lookup
  -> trusted scope headers and dynamic metadata
  -> BackendTrafficPolicy user/project daily + monthly limit.fromMetadata rules
  -> Envoy rate-limit service + Redis
  -> AI Gateway response dollar cost
```

The ext_authz service is the `testextauthserver` binary running in the
`envoy-ai-gateway-dynamic-budgeting-extauth` Deployment. The UserInfo endpoint is
the `testuserinfoserver` binary running in the
`envoy-ai-gateway-dynamic-budgeting-userinfo` Deployment. They are separate
services so the example matches the production boundary.

The user tier selects the regular user budget. Supplying a project selects a
shared project budget after ext_authz verifies membership. The client-provided
project ID is never used as the rate-limit key directly.

### “Tier” is an example label

This example uses `tier` only as a convenient name for the value returned by
UserInfo. It is not a required product or organizational concept. The lookup
key could represent a team, department, user group, subscription, environment,
or a special allocation such as a large incident-response budget for engineers
working on an outage. Replace `UserInfo.Tier` and the tier store with whatever
identity or entitlement model determines the budget in your system.

Projects demonstrate a second, shared scope: several users can select the same
authorized allocation and consume one shared budget. The same mechanism can
represent any other shared resource or delegation boundary.

The binaries are local-development fixtures, not an identity provider or a
production authorization service. Replace them with your JWT verifier,
`/userinfo` client, and tier/project budget stores when adapting the example.

The fixture ext_authz implementation is intentionally minimal: every request
performs JWT validation and makes a synchronous `/userinfo` call, and it does
not cache UserInfo or budget lookups. That makes the request flow easy to
inspect locally, but it adds latency and identity-service load at high volume.
A production implementation should use an appropriately bounded and
invalidation-aware cache, scalable identity and budget lookups, and deployment
resilience while preserving token validation and authorization correctness.

## Files

- `dynamic-budgeting.yaml`: Gateway, AI Gateway route, ext_authz, UserInfo,
  test upstream, and dynamic `BackendTrafficPolicy`.
- `token.go`: creates a local HS256 token accepted by the fixture.

## Prerequisites

- Docker with a running daemon.
- `kind`, `kubectl`, `helm`, Go, and `make`.
- A kind cluster and Envoy Gateway `v0.0.0-latest`.

The `fromMetadata` field requires an Envoy Gateway build containing
`envoyproxy/gateway#9216`; released versions that predate that change will
use the static `requests` and `unit` values in the policy instead. This
example's JWT/UserInfo authorization path emits metadata for every allowed
request, so it does not demonstrate missing-metadata fallback behavior.

## Quick start: automated validation

Most users should start here. From the repository root, run the complete
example test:

```bash
make test-dynamic-budgeting
```

This builds the local fixture images, creates a kind cluster, installs Envoy
Gateway and AI Gateway, deploys Redis and the example, and verifies regular
user budgets, user/project isolation, shared project counters, and rejected
project membership. Set `TEST_KEEP_CLUSTER=true` to retain the cluster and
exported logs for debugging after a failure.

## Why this is advanced

Use this pattern when the limit depends on authenticated identity or other
request-time state, such as a tier, subscription, or shared project
allocation. It introduces a security boundary: ext_authz must validate the
request, emit trusted scope headers, and provide correctly shaped metadata
before BackendTrafficPolicy evaluates the limit.

For static per-client limits, start with the
[Token Rate Limiting](../token_ratelimit/) example instead. For cumulative
token quotas that do not need Envoy Gateway rate-limit service integration,
consider [QuotaPolicy](../../site/docs/capabilities/traffic/quota-policy.md).

## Manual setup and walkthrough

Use this optional path when you want to inspect or modify each component
individually. It performs the same setup as the automated test, but leaves the
cluster running so you can send requests and inspect the generated resources.

Create the cluster used by this example:

```bash
kind create cluster --name envoy-ai-gateway
```

Install Envoy Gateway with global rate limiting enabled:

```bash
helm upgrade -i eg oci://docker.io/envoyproxy/gateway-helm \
  --version v0.0.0-latest \
  --namespace envoy-gateway-system \
  --create-namespace \
  -f ../../manifests/envoy-gateway-values.yaml \
  -f ../token_ratelimit/envoy-gateway-values-addon.yaml
```

Install AI Gateway and its CRDs:

```bash
helm upgrade -i aieg-crd oci://docker.io/envoyproxy/ai-gateway-crds-helm \
  --version v0.0.0-latest \
  --namespace envoy-ai-gateway-system \
  --create-namespace
helm upgrade -i aieg oci://docker.io/envoyproxy/ai-gateway-helm \
  --version v0.0.0-latest \
  --namespace envoy-ai-gateway-system \
  --create-namespace
kubectl wait --timeout=2m -n envoy-ai-gateway-system \
  deployment/ai-gateway-controller --for=condition=Available
```

Deploy Redis:

```bash
kubectl apply -f ../token_ratelimit/redis.yaml
```

Build and load the three local fixture images:

```bash
make build-dynamic-budgeting

kind load docker-image docker.io/envoyproxy/ai-gateway-testextauthserver:latest \
  --name envoy-ai-gateway
kind load docker-image docker.io/envoyproxy/ai-gateway-testuserinfoserver:latest \
  --name envoy-ai-gateway
kind load docker-image docker.io/envoyproxy/ai-gateway-testupstream:latest \
  --name envoy-ai-gateway
```

Apply the example:

```bash
kubectl apply -f dynamic-budgeting.yaml
kubectl wait --for=condition=Available deployment/envoy-ai-gateway-dynamic-budgeting-extauth
kubectl wait --for=condition=Available deployment/envoy-ai-gateway-dynamic-budgeting-userinfo
```

Create a local token and port-forward the generated Gateway service:

```bash
TOKEN="$(go run ./examples/dynamic-budgeting/token.go)"
EXPECTED_PATH_B64="$(printf '%s' '/v1/chat/completions' | base64 | tr -d '\n')"
kubectl get svc -A \
  -l gateway.envoyproxy.io/owning-gateway-name=envoy-ai-gateway-dynamic-budgeting
```

Use the service name and namespace returned by the previous command to create
the port-forward:

```bash
kubectl port-forward -n envoy-gateway-system \
  service/<generated-gateway-service> 8080:80
```

The default UserInfo fixture returns `local-user` in the `premium` tier. The
example uses fixed-point monetary accounting: `1,000` millidollars equals
`$1.00`. Its CEL expression prices each input token at `$0.20` and each output
token at `$0.80`, intentionally inflated so the deterministic response below
costs exactly `$1.00`:

```bash
RESPONSE='{"choices":[{"message":{"content":"ok","role":"assistant"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}'
RESPONSE_B64="$(printf '%s' "$RESPONSE" | base64 | tr -d '\n')"

curl -i http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Host: openai.com' \
  -H 'x-ai-eg-model: dynamic-budgeting-model' \
  -H "x-expected-path: ${EXPECTED_PATH_B64}" \
  -H "x-response-body: ${RESPONSE_B64}" \
  -d '{"model":"dynamic-budgeting-model","messages":[{"role":"user","content":"hello"}]}'
```

The premium limits are `$6.00` per day and `$60.00` per month. The policy has
two independent counters, so a request must fit both windows. Change the
fixture tier and restart it to observe a different dollar budget:

```bash
kubectl set env deployment/envoy-ai-gateway-dynamic-budgeting-userinfo \
  USERINFO_DEFAULT='{"sub":"local-user","tier":"basic","projects":["project-123"]}'
```

The `basic` tier has `$2.00` per day and `$20.00` per month. The `suspended`
tier has zero in both windows. The `monthly-first` fixture has a `$100.00`
daily budget and a `$2.00` monthly budget; the E2E test uses a fresh user to
verify that the monthly rule can reject a request before the daily rule. Since
response usage is charged after the response and request cost is zero, the
request that reaches the exact limit is admitted; the following request is
rejected.

Because request cost is zero and response usage is charged after the upstream
response, a zero budget admits the first request and rejects the next one.

## Shared project allocations

The default UserInfo response makes `local-user` a member of `project-123`.
Passing that project selects the shared project budget instead of the regular
user budget:

```bash
curl -i http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Host: openai.com' \
  -H 'x-ai-eg-model: dynamic-budgeting-model' \
  -H 'x-project-id: project-123' \
  -H "x-expected-path: ${EXPECTED_PATH_B64}" \
  -H "x-response-body: ${RESPONSE_B64}" \
  -d '{"model":"dynamic-budgeting-model","messages":[{"role":"user","content":"hello"}]}'
```

`project-123` has a `$10.00` daily and `$100.00` monthly budget. Every
authorized member receives the same trusted `x-quota-scope-id: project-123`,
so the daily and monthly counters are shared. A project that is not listed by
UserInfo is rejected by ext_authz; the client cannot select an arbitrary
project by changing the request header.

The policy has four rules: user daily/monthly and project daily/monthly. To
exercise multiple members, configure `USERINFO_USERS` as a JSON map from
bearer tokens to UserInfo objects whose `projects` include `project-123`,
generate tokens for those subjects, and send the same `x-project-id`.

## What to replace

The example uses `EXT_AUTH_JWT_SECRET` and the local HS256 verifier for
repeatability. A real deployment should replace that with issuer/JWKS
validation, call the real `/userinfo` endpoint, and replace the in-memory
`EXT_AUTH_TIER_LIMITS` and `EXT_AUTH_PROJECT_LIMITS` maps with database or
policy-service lookups. The Envoy-facing contract remains the same: return an
allow response, trusted request headers, and metadata shaped as:

```json
{
  "user_millidollar_daily_limit": {
    "requests_per_unit": 6000,
    "unit": "DAY"
  },
  "user_millidollar_monthly_limit": {
    "requests_per_unit": 60000,
    "unit": "MONTH"
  },
  "project_millidollar_daily_limit": {
    "requests_per_unit": 10000,
    "unit": "DAY"
  },
  "project_millidollar_monthly_limit": {
    "requests_per_unit": 100000,
    "unit": "MONTH"
  }
}
```

Only the selected scope's two metadata fields are emitted. A production
implementation should authorize project membership against its own database
and keep the project ID out of the rate-limit key until ext_authz has replaced
it with a trusted scope header.

## Cleanup

```bash
kubectl delete -f dynamic-budgeting.yaml
kubectl delete -f ../token_ratelimit/redis.yaml
```
