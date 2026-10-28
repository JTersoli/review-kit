-- review-kit: RLS and privilege audit for a Supabase project.
-- Paste into the SQL Editor (as postgres) or run with psql. Read-only.
-- Each block answers one question. Empty result = nothing to flag for that block.

-- 1. Tables in public without row level security. Readable with the anon key.
select n.nspname as schema, c.relname as table
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r' and n.nspname = 'public' and not c.relrowsecurity
order by 1, 2;

-- 2. Tables with RLS enabled but no policy at all (RLS on + no policy = nobody but service role).
select c.relname as table
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
left join pg_policy p on p.polrelid = c.oid
where c.relkind = 'r' and n.nspname = 'public' and c.relrowsecurity
group by c.relname
having count(p.oid) = 0
order by 1;

-- 3. Every policy with its operation, roles, USING and WITH CHECK.
--    Look for: with_check null on UPDATE/ALL, "true" anywhere, roles containing anon or public.
select schemaname, tablename, policyname, cmd, roles, permissive, qual as using_expr, with_check
from pg_policies
where schemaname = 'public'
order by tablename, cmd, policyname;

-- 4. Policies that are always true.
select tablename, policyname, cmd, roles
from pg_policies
where schemaname = 'public' and (qual = 'true' or with_check = 'true')
order by 1, 2;

-- 5. UPDATE / ALL policies without WITH CHECK (USING is reused for the new row).
select tablename, policyname, cmd
from pg_policies
where schemaname = 'public' and cmd in ('UPDATE', 'ALL') and with_check is null
order by 1, 2;

-- 6. SECURITY DEFINER functions, with whether search_path is set and who can execute them.
select n.nspname as schema,
       p.proname as function,
       pg_get_function_identity_arguments(p.oid) as args,
       coalesce(array_to_string(p.proconfig, ', '), '(no search_path)') as config,
       (select string_agg(grantee::text, ', ')
          from information_schema.routine_privileges rp
         where rp.specific_schema = n.nspname and rp.specific_name = p.proname || '_' || p.oid
           and rp.privilege_type = 'EXECUTE') as execute_grants
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname in ('public', 'auth', 'storage')
order by 1, 2;

-- 7. Views in public without security_invoker (they run as the owner and bypass RLS).
select c.relname as view,
       coalesce(array_to_string(c.reloptions, ', '), '(owner rights)') as options
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'v' and n.nspname = 'public'
  and not coalesce(array_to_string(c.reloptions, ','), '') ilike '%security_invoker=true%'
order by 1;

-- 8. What anon can do on public tables and views (should be read-only on very few things).
select table_name, string_agg(privilege_type, ', ' order by privilege_type) as privileges
from information_schema.role_table_grants
where grantee = 'anon' and table_schema = 'public'
group by table_name
order by 1;

-- 9. Functions anon is allowed to execute.
select rp.routine_name, rp.privilege_type
from information_schema.routine_privileges rp
where rp.grantee = 'anon' and rp.specific_schema = 'public'
order by 1;

-- 10. Policies that read user_metadata (editable by the user from the client SDK).
select tablename, policyname, cmd
from pg_policies
where schemaname = 'public'
  and (coalesce(qual, '') ilike '%user_metadata%' or coalesce(with_check, '') ilike '%user_metadata%')
order by 1, 2;

-- 11. Columns used in policies that have no index (performance, not security).
--     Manual: compare the columns in block 3 with the indexes below.
select tablename, indexname, indexdef
from pg_indexes
where schemaname = 'public'
order by tablename, indexname;

-- 12. Storage buckets and their policies.
select id as bucket, public as is_public, file_size_limit, allowed_mime_types
from storage.buckets
order by 1;

select policyname, cmd, roles, qual as using_expr, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by 1;
