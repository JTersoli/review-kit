import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseDiff, splitSql, scan } from './scan.mjs'

const diff = (path, added, removed = []) =>
  [
    `diff --git a/${path} b/${path}`,
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -1,${removed.length} +1,${added.length} @@`,
    ...removed.map((l) => '-' + l),
    ...added.map((l) => '+' + l),
    '',
  ].join('\n')

const ids = (text) => scan(text).findings.map((f) => f.id)

test('parseDiff tracks new-file line numbers', () => {
  const [f] = parseDiff(diff('a.ts', ['one', 'two']))
  assert.deepEqual(f.added.map((a) => a.line), [1, 2])
})

test('splitSql keeps $$ bodies together', () => {
  const added = [
    { line: 1, text: 'create function f() returns void language plpgsql security definer as $$' },
    { line: 2, text: 'begin perform 1; end;' },
    { line: 3, text: '$$;' },
    { line: 4, text: 'grant execute on function f() to anon;' },
  ]
  const s = splitSql(added)
  assert.equal(s.length, 2)
  assert.equal(s[0].line, 1)
  assert.equal(s[1].line, 4)
})

test('flags a secret fallback and a plain comparison', () => {
  const found = ids(diff('src/lib/session.ts', [
    "const secret = process.env.SESSION_SECRET || 'dev-secret'",
    'if (sig !== expected) return null',
  ]))
  assert.ok(found.includes('secret-fallback'))
  assert.ok(found.includes('sig-compare'))
})

test('flags NEXT_PUBLIC service role but not the anon key', () => {
  assert.ok(ids(diff('.env.example', ['NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY='])).includes('public-secret'))
  assert.ok(!ids(diff('.env.example', ['NEXT_PUBLIC_SUPABASE_ANON_KEY='])).includes('public-secret'))
})

test('flags SQL policy and function patterns', () => {
  const found = ids(diff('supabase/migrations/0001.sql', [
    'create table public.things (id uuid primary key);',
    'create policy "p" on public.things for insert to authenticated with check (true);',
    'create policy "u" on public.things for update to authenticated using (true);',
    'create function public.f(t text) returns void language plpgsql security definer as $$',
    'begin insert into public.m values (t); end;',
    '$$;',
    'grant execute on function public.f(text) to anon;',
    'create view public.v as select 1;',
  ]))
  for (const id of ['rls-not-enabled', 'policy-true', 'update-without-check', 'definer-without-search-path', 'definer-no-caller-check', 'grant-anon', 'view-without-invoker']) {
    assert.ok(found.includes(id), `missing ${id}`)
  }
})

test('does not flag a correct policy, a definer with search_path, or an invoker view', () => {
  const found = ids(diff('supabase/migrations/0002.sql', [
    'alter table public.things enable row level security;',
    'create policy "u" on public.things for update to authenticated using (owner = (select auth.uid())) with check (owner = (select auth.uid()));',
    'create function public.f() returns void language sql security definer set search_path = public as $$ select 1 $$;',
    'create view public.v with (security_invoker = true) as select 1;',
  ]))
  assert.deepEqual(found, [])
})

test('flags removed tests and loosened env in tests', () => {
  const found = ids(diff('tests/session.test.ts', ['delete process.env.SESSION_SECRET'], ["it('fails closed', () => {"]))
  assert.ok(found.includes('test-removed'))
  assert.ok(found.includes('test-env-loosened'))
})

test('flags client-supplied tenant ids and service role in routes', () => {
  const found = ids(diff('src/app/api/export/route.ts', [
    "const orgId = req.nextUrl.searchParams.get('orgId') ?? session.orgId",
    'createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)',
    "const csv = rows.map((r) => r.join(','))",
  ]))
  assert.ok(found.includes('id-from-request'))
  assert.ok(found.includes('service-role-route'))
  assert.ok(found.includes('csv-join'))
})

test('sorts findings by severity', () => {
  const { findings } = scan(diff('src/app/api/x/route.ts', [
    "return NextResponse.json({ error: error.message })",
    'createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)',
  ]))
  assert.equal(findings[0].severity, 'high')
  assert.equal(findings.at(-1).severity, 'low')
})
