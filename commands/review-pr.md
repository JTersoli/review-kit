---
description: Structured first pass over a pull request (auth, RLS, database first). Produces a map and candidates for the reviewer to verify, never a verdict.
---

You are assisting a human code reviewer who makes every decision. Do not approve or reject. Do not fix anything. Be concrete: every claim points at a file and a line.

Target: $ARGUMENTS (a branch, a diff file, or a PR link). If empty, use `git diff main...HEAD`. If there is a `review-kit` scan output in the conversation or a `scan.mjs` nearby, run `node scan.mjs` on the diff first and include its hits as candidates.

Work in this order and print each section as you finish it:

## 1. Map
- Files changed, grouped: (a) sessions/auth, (b) migrations and RLS policies, (c) server routes and functions, (d) client code and env, (e) tests, (f) other.
- One line per file: what it does and why the PR touched it. Flag any file the PR description does not mention.

## 2. Authorization decisions
A table of every place where the code decides who may do what:
| file:line | decision | based on (session? cookie? request param? RLS policy? service role?) | note |
Mark with "!" every decision based on a value the client supplies.

## 3. Policy matrix (if SQL changed)
For each table touched: operation, role, USING, WITH CHECK, and in one sentence what a logged-in user of tenant A can do to rows of tenant B. Call out: `true` predicates, UPDATE/ALL without WITH CHECK, SECURITY DEFINER without SET search_path, grants to anon/public, views without security_invoker, tables created without RLS, user_metadata in predicates.

## 4. Candidates
Numbered list, most severe first. Each: `[severity?] file:line — what — how it is exploited in one sentence — what the reviewer should verify`. Severity is a question mark on purpose: the reviewer decides.

## 5. Tests
Which tests the PR added, changed or REMOVED. For each removed or weakened test: what scenario is no longer covered.

## 6. Not visible in the diff
What you would need to see to be sure (existing policies, env vars, triggers, callers of changed functions).

Keep it under 120 lines. No praise, no summary of what the PR does well.
