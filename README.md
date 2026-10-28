# review-kit

A first-pass toolkit for reviewing pull requests on Next.js + Supabase codebases, built for reviewing AI-written code where login, permissions and the database matter most.

It does three things, in this order, before the human reads the diff:

1. **`scan.mjs`** — scans a unified diff for the patterns that are wrong often enough to check every time: secret fallbacks, `NEXT_PUBLIC_` secrets, service-role usage, `with check (true)`, UPDATE policies without `WITH CHECK`, `SECURITY DEFINER` without `search_path`, views without `security_invoker`, grants to `anon`, `Math.random()` tokens, signature comparison with `===`, CSV built with `join(',')`, removed tests. Every hit is a candidate with a *why* and a *what to check*. No dependencies.
2. **`rls-audit.sql`** — twelve read-only queries for the Supabase SQL Editor: tables without RLS, policies with their `USING` / `WITH CHECK`, always-true policies, definer functions and who can execute them, views without `security_invoker`, what `anon` can do, storage policies.
3. **`commands/review-pr.md`** — a Claude Code slash command that produces a map of the diff, a table of every authorization decision and what it is based on, a policy matrix, and candidates for the reviewer to verify. It never gives a verdict.

Plus `REVIEW_TEMPLATE.md`, the shape of the written review.

## What it is not

A scanner finds pattern bugs. It does not find an admin route that exports another tenant's data because it trusts `?orgId=`, or an `accept_invite` function that never checks the invite was addressed to the caller. Those are found by reading. The scanner's job is to make the first ten minutes fast so the remaining fifty go to reading.

## Usage

```bash
git diff main...feature/branch | node scan.mjs
node scan.mjs pr.diff
node scan.mjs pr.diff --json
node --test            # scanner tests
```

Install the slash command for every project:

```bash
cp commands/review-pr.md ~/.claude/commands/review-pr.md
```

Then in Claude Code: `/review-pr main...feature/branch`.

## Rules

| id | severity | looks for |
|---|---|---|
| secret-fallback | critical | `SECRET \|\| '...'`, `?? process.env.OTHER` in auth code |
| public-secret | critical | `NEXT_PUBLIC_*SERVICE_ROLE*`, `*SECRET*`, `*PRIVATE*` |
| service-role-in-client | critical | `SERVICE_ROLE` outside server-only files |
| rls-not-enabled | critical | `create table` with no `enable row level security` in the diff |
| policy-true | critical | `using (true)` / `with check (true)` |
| service-role-route | high | `SERVICE_ROLE` in a route: authorization is now the route's job |
| id-from-request | high | `orgId`, `userId`, `tenantId`… taken from params or body |
| update-without-check | high | `for update` / `for all` policy without `with check` |
| definer-without-search-path | high | `security definer` without `set search_path` |
| definer-no-caller-check | high | definer function that writes without reading the caller's JWT |
| view-without-invoker | high | `create view` without `security_invoker` |
| grant-anon | high | `grant … to anon / public` |
| weak-random | high | `Math.random()` outside tests |
| user-metadata | high | `user_metadata` next to role/tenant/admin |
| test-removed | high | an `it(` / `test(` line deleted |
| test-env-loosened | high | tests deleting a secret from `process.env` |
| sig-compare | medium | signature / digest compared with `===` |
| csv-join | medium | `.join(',')` |
| raw-html | medium | `dangerouslySetInnerHTML`, `innerHTML =` |
| error-leak | low | `{ error: error.message }` returned to the client |

Severities are starting points for the reviewer, not verdicts.
