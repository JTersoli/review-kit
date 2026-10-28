#!/usr/bin/env node
// review-kit: first-pass scanner for pull request diffs (Next.js + Supabase).
//
// It reads a unified diff and points at lines that match patterns that are
// often wrong in auth, RLS and database code. Every hit is a CANDIDATE: the
// reviewer reads the code and decides. Logic bugs (an admin exporting another
// tenant's data, a missing ownership check) are not pattern-shaped and will
// not show up here. Read the diff.
//
// Usage:
//   git diff main...feature | node scan.mjs
//   node scan.mjs pr.diff
//   node scan.mjs pr.diff --json

import { readFileSync } from 'node:fs'

// ----------------------------------------------------------------- diff parsing

export function parseDiff(text) {
  const files = new Map() // path -> { added: [{line, text}], removed: [text] }
  let current = null
  let newLine = 0
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '')
    if (line.startsWith('diff --git ')) {
      const m = line.match(/ b\/(.+)$/)
      current = { path: m ? m[1] : line, added: [], removed: [] }
      files.set(current.path, current)
      continue
    }
    if (!current) continue
    if (line.startsWith('+++ ') || line.startsWith('--- ')) continue
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
    if (hunk) { newLine = Number(hunk[1]); continue }
    if (line.startsWith('+')) { current.added.push({ line: newLine, text: line.slice(1) }); newLine++; continue }
    if (line.startsWith('-')) { current.removed.push(line.slice(1)); continue }
    if (line.startsWith('\\')) continue // "\ No newline at end of file"
    newLine++
  }
  return [...files.values()]
}

// Splits SQL made of added lines into statements, respecting $$ bodies.
// Returns [{ text, line }] where line is the diff line of the first character.
export function splitSql(added) {
  const statements = []
  let buf = ''
  let startLine = null
  let inDollar = false
  for (const { line, text } of added) {
    let i = 0
    while (i < text.length) {
      const two = text.slice(i, i + 2)
      if (two === '$$') { inDollar = !inDollar; buf += two; i += 2; if (startLine === null) startLine = line; continue }
      const ch = text[i]
      if (ch === ';' && !inDollar) {
        buf += ch
        if (buf.trim()) statements.push({ text: buf, line: startLine ?? line })
        buf = ''; startLine = null
      } else {
        if (startLine === null && ch.trim()) startLine = line
        buf += ch
      }
      i++
    }
    buf += '\n'
  }
  if (buf.trim()) statements.push({ text: buf, line: startLine ?? (added.at(-1)?.line ?? 0) })
  return statements
}

// ----------------------------------------------------------------- rules

const isCode = (p) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(p)
const isSql = (p) => /\.sql$/.test(p)
const isTest = (p) => /(\.|\/|^)(test|spec)s?[./]/.test(p) || /__tests__\//.test(p)
const isServerOnly = (p) => /(\/api\/|\/server\/|middleware\.|\.server\.|supabase-server|supabase\/admin)/.test(p)

const lineRules = [
  {
    id: 'secret-fallback', severity: 'critical',
    when: (p) => isCode(p),
    test: (t) => /(secret|signing|session_key|jwt)/i.test(t) && /(\|\||\?\?|=\s*['"`][^'"`]{4,}['"`]\s*$)/.test(t) && !/^\s*\/\//.test(t),
    why: 'A fallback for a secret means the code keeps working without it. In auth, that is "anyone can sign a session". It must fail closed.',
    check: 'What happens when the env var is missing? Is there a minimum length? Is the fallback value in the repo?',
  },
  {
    id: 'public-secret', severity: 'critical',
    when: () => true,
    test: (t) => /NEXT_PUBLIC_[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE|SERVICE_KEY)/.test(t),
    why: 'Everything prefixed NEXT_PUBLIC_ is shipped to the browser. A service role or private key there makes RLS irrelevant.',
    check: 'Remove the variable. Anything that needs to bypass RLS belongs in a server route that authorizes first.',
  },
  {
    id: 'service-role-in-client', severity: 'critical',
    when: (p) => isCode(p) && !isServerOnly(p) && !isTest(p),
    test: (t) => /SERVICE_ROLE/.test(t),
    why: 'The service role key bypasses RLS. Outside server-only code it is either leaked or used without an authorization check.',
    check: 'Is this file ever bundled for the browser? Who checks permissions before the query?',
  },
  {
    id: 'service-role-route', severity: 'high',
    when: (p) => isCode(p) && isServerOnly(p),
    test: (t) => /SERVICE_ROLE/.test(t),
    why: 'This route bypasses RLS. Authorization is now entirely the route\'s job.',
    check: 'Which session/role check runs before the query, and is the tenant id taken from the session or from the request?',
  },
  {
    id: 'id-from-request', severity: 'high',
    when: (p) => isCode(p) && isServerOnly(p),
    test: (t) => /(searchParams\.get\(|params\.|body\.|json\(\)\)?\.)\s*['"]?(org_?[iI]d|user_?[iI]d|tenant_?[iI]d|account_?[iI]d|customer_?[iI]d|owner_?[iI]d)/.test(t),
    why: 'A tenant or user id supplied by the client is a request, not a proof of membership.',
    check: 'If the query runs under RLS, the policy decides; if it runs with the service role, the route must verify membership itself.',
  },
  {
    id: 'sig-compare', severity: 'medium',
    when: (p) => isCode(p),
    test: (t) => /(sig|signature|hmac|digest|hash)\w*\s*(===|!==)|(===|!==)\s*(sig|signature|expected|hmac|digest)\w*/i.test(t),
    why: 'Comparing signatures with === leaks timing information.',
    check: 'Use crypto.timingSafeEqual on equal-length buffers.',
  },
  {
    id: 'weak-random', severity: 'high',
    when: (p) => isCode(p) && !isTest(p),
    test: (t) => /Math\.random\(\)/.test(t),
    why: 'Math.random is not cryptographic. Fine for a UI key, wrong for tokens, invite links, codes or ids that grant access.',
    check: 'What is the value used for? Tokens need crypto.randomBytes / randomUUID or gen_random_uuid() in SQL.',
  },
  {
    id: 'policy-true', severity: 'critical',
    when: (p) => isSql(p),
    test: (t) => /(with\s+check|using)\s*\(\s*true\s*\)/i.test(t),
    why: 'A policy that is always true grants the operation to everyone the policy targets (usually every logged-in user).',
    check: 'Which role does the policy target, and which operation? Is "everyone" really intended?',
  },
  {
    id: 'grant-anon', severity: 'high',
    when: (p) => isSql(p),
    test: (t) => /grant\s+[^;]*\bto\b[^;]*\b(anon|public)\b/i.test(t),
    why: 'anon is every unauthenticated visitor; public is every role. Grants to them are rarely intended for functions that write.',
    check: 'Does an anonymous caller have any business running this? If not, revoke.',
  },
  {
    id: 'user-metadata', severity: 'high',
    when: (p) => isSql(p) || isCode(p),
    test: (t) => /user_metadata/.test(t) && /(role|admin|tenant|org|plan|is_)/i.test(t),
    why: 'user_metadata is editable by the user through the client SDK. Roles and tenants belong in app_metadata or in a table.',
    check: 'Is any authorization decision based on this value?',
  },
  {
    id: 'csv-join', severity: 'medium',
    when: (p) => isCode(p),
    test: (t) => /\.join\(\s*['"],['"]\s*\)/.test(t),
    why: 'Joining with commas is not CSV. Commas and quotes break columns; cells starting with = + - @ run as formulas in Excel.',
    check: 'Quote and escape every cell, prefix dangerous leading characters, or use a CSV library.',
  },
  {
    id: 'error-leak', severity: 'low',
    when: (p) => isCode(p) && isServerOnly(p),
    test: (t) => /json\(\s*\{\s*error:\s*(error|err|e)\.message/.test(t),
    why: 'Database error messages tell the client about tables, columns and constraints.',
    check: 'Log the detail, return a generic message.',
  },
  {
    id: 'raw-html', severity: 'medium',
    when: (p) => isCode(p),
    test: (t) => /dangerouslySetInnerHTML|innerHTML\s*=/.test(t),
    why: 'Raw HTML from data is XSS unless sanitized.',
    check: 'Where does the HTML come from, and is it sanitized?',
  },
  {
    id: 'test-env-loosened', severity: 'high',
    when: (p) => isTest(p),
    test: (t) => /delete\s+process\.env\.[A-Z_]+|process\.env\.[A-Z_]*(SECRET|KEY)[A-Z_]*\s*=\s*['"]{2}/.test(t),
    why: 'A test that removes a secret and still expects success is documenting a fail-open path.',
    check: 'Should this scenario throw or return null instead?',
  },
]

const statementRules = [
  {
    id: 'update-without-check', severity: 'high',
    test: (s) => /create\s+policy/i.test(s) && /\bfor\s+(update|all)\b/i.test(s) && !/with\s+check/i.test(s),
    why: 'Without WITH CHECK, Postgres reuses USING for the new row. A member can move a row to another tenant by updating org_id.',
    check: 'Add WITH CHECK with the same tenant condition, or restrict the columns that can change.',
  },
  {
    id: 'definer-without-search-path', severity: 'high',
    test: (s) => /security\s+definer/i.test(s) && !/set\s+search_path/i.test(s),
    why: 'SECURITY DEFINER runs as the owner and bypasses RLS. Without SET search_path, unqualified names can be hijacked.',
    check: 'Add SET search_path = public (or empty), revoke EXECUTE from anon/public, and check permissions inside the function.',
  },
  {
    id: 'definer-no-caller-check', severity: 'high',
    test: (s) => /security\s+definer/i.test(s) && /\b(insert|update|delete)\s+(into\s+)?[\w.]+/i.test(s) && !/auth\.jwt\(\)|auth\.email\(\)|current_setting\(['"]request\.jwt/i.test(s),
    why: 'A definer function that writes rows needs its own check of who is calling and what they are allowed to touch.',
    check: 'What stops a different user from calling this with someone else\'s token or id?',
  },
  {
    id: 'view-without-invoker', severity: 'high',
    test: (s) => /create\s+(or\s+replace\s+)?view/i.test(s) && !/security_invoker/i.test(s),
    why: 'Views run as their owner and bypass RLS by default. Every authenticated user sees every tenant through them.',
    check: 'Add WITH (security_invoker = true) (Postgres 15+) or replace with a function that filters by tenant.',
  },
]

// ----------------------------------------------------------------- scan

export function scan(diffText) {
  const files = parseDiff(diffText)
  const findings = []
  const push = (f) => findings.push(f)

  // Tables created vs RLS enabled, across the whole diff.
  const created = new Map()
  const enabled = new Set()
  const norm = (n) => n.replace(/^public\./, '').replace(/"/g, '').toLowerCase()
  for (const f of files) {
    if (!isSql(f.path)) continue
    for (const { line, text } of f.added) {
      const c = text.match(/create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."]+)/i)
      if (c) created.set(norm(c[1]), { file: f.path, line })
      const e = text.match(/alter\s+table\s+(?:only\s+)?([\w."]+)\s+enable\s+row\s+level\s+security/i)
      if (e) enabled.add(norm(e[1]))
    }
  }
  for (const [table, where] of created) {
    if (!enabled.has(table)) push({
      id: 'rls-not-enabled', severity: 'critical', file: where.file, line: where.line,
      snippet: `create table ${table}`,
      why: 'A table without RLS is readable and writable by anyone holding the anon key.',
      check: 'Is RLS enabled for this table somewhere outside this diff? If not, enable it and add policies.',
    })
  }

  for (const f of files) {
    for (const { line, text } of f.added) {
      for (const r of lineRules) {
        if (r.when(f.path) && r.test(text)) {
          push({ id: r.id, severity: r.severity, file: f.path, line, snippet: text.trim(), why: r.why, check: r.check })
        }
      }
    }
    if (isSql(f.path)) {
      for (const s of splitSql(f.added)) {
        for (const r of statementRules) {
          if (r.test(s.text)) push({
            id: r.id, severity: r.severity, file: f.path, line: s.line,
            snippet: (s.text.split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('--')) ?? '').slice(0, 100),
            why: r.why, check: r.check,
          })
        }
      }
    }
    if (isTest(f.path)) {
      const removedTests = f.removed.filter((t) => /^\s*(it|test)\s*\(\s*['"`]/.test(t))
      for (const t of removedTests) push({
        id: 'test-removed', severity: 'high', file: f.path, line: 0,
        snippet: t.trim(), why: 'The PR deleted a test. The behaviour it protected may be gone too.',
        check: 'Why was it removed? Does the new code still fail closed in that scenario?',
      })
    }
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3 }
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line)
  return { files: files.map((f) => ({ path: f.path, added: f.added.length, removed: f.removed.length })), findings }
}

// ----------------------------------------------------------------- report

const NOT_COVERED = [
  'Authorization logic: does the route check that THIS user may touch THIS tenant? (ids from the request, admins of several orgs)',
  'Ownership checks inside SECURITY DEFINER functions (does the invite email match the caller?)',
  'Values returned to the client that should not be (tokens, hashes, other users\' emails)',
  'Business rules: prices, stock, status transitions, idempotency of webhooks',
  'Anything the diff does not show: existing policies, triggers, env vars in Vercel',
]

export function report({ files, findings }) {
  const lines = []
  lines.push(`review-kit scan: ${files.length} file(s), ${findings.length} candidate(s) to verify`)
  lines.push('')
  for (const f of files) lines.push(`  ${f.path}  (+${f.added} -${f.removed})`)
  lines.push('')
  if (!findings.length) lines.push('No pattern hits. That is not a verdict: read the diff.')
  let last = ''
  for (const h of findings) {
    if (h.severity !== last) { lines.push(`== ${h.severity.toUpperCase()} candidates ==`); last = h.severity }
    lines.push(`[${h.id}] ${h.file}${h.line ? ':' + h.line : ''}`)
    lines.push(`    ${h.snippet}`)
    lines.push(`    why:   ${h.why}`)
    lines.push(`    check: ${h.check}`)
    lines.push('')
  }
  lines.push('Not covered by this scanner (read for these):')
  for (const n of NOT_COVERED) lines.push(`  - ${n}`)
  return lines.join('\n')
}

// ----------------------------------------------------------------- cli

if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}` || process.argv[1]?.endsWith('scan.mjs')) {
  const args = process.argv.slice(2)
  const json = args.includes('--json')
  const file = args.find((a) => !a.startsWith('--'))
  const input = file ? readFileSync(file, 'utf8') : readFileSync(0, 'utf8')
  const result = scan(input)
  process.stdout.write(json ? JSON.stringify(result, null, 2) : report(result) + '\n')
}
