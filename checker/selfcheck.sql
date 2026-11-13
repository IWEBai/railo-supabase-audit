-- Five read-only checks for a Supabase project. Paste into the SQL editor of a project you own.
-- Each query returns rows only when something needs a look. Query 5 lists security-definer
-- functions; the ones to fix are those where anon_can_call is true.
-- Tested on the TripNest sample: every check fires on the insecure version, none on the fixed one.

-- 1. Tables anyone can reach with row-level security off
select c.relname as table_without_rls
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity;

-- 2. Policies that allow every row
select tablename, policyname, cmd, roles
from pg_policies
where schemaname = 'public' and (qual = 'true' or with_check = 'true');

-- 3. Policies and functions that trust user_metadata
select 'policy' as kind, tablename as name from pg_policies
where schemaname = 'public' and (qual ilike '%user_metadata%' or with_check ilike '%user_metadata%')
union all
select 'function', p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prokind = 'f' and pg_get_functiondef(p.oid) ilike '%''user_metadata''%';

-- 4. Public storage buckets
select id as public_bucket from storage.buckets where public;

-- 5. Security-definer functions the public API can call
select p.proname as function_name,
       has_function_privilege('anon', p.oid, 'execute') as anon_can_call
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prosecdef and p.prorettype <> 'trigger'::regtype;
