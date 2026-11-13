-- Railo fixes for the TripNest sample audit.
-- Each block names the finding it closes. Applied as a new migration, so the history stays readable.

-- SB001: bookings had row-level security off. Only the advisor and the client on a booking see it.
alter table public.bookings enable row level security;

create policy "Advisors and clients see their own bookings"
  on public.bookings for select
  to authenticated
  using ((select auth.uid()) in (advisor_id, client_id));

create policy "Advisors create their own bookings"
  on public.bookings for insert
  to authenticated
  with check ((select auth.uid()) = advisor_id);

create policy "Advisors update their own bookings"
  on public.bookings for update
  to authenticated
  using ((select auth.uid()) = advisor_id)
  with check ((select auth.uid()) = advisor_id);

-- SB002: every profile, with email and phone, was readable by anyone.
-- Users see their own profile and the people they share a booking with.
drop policy "Profiles are viewable by everyone" on public.profiles;

create policy "Users see their own profile and their booking contacts"
  on public.profiles for select
  to authenticated
  using (
    id = (select auth.uid())
    or exists (
      select 1 from public.bookings b
      where (b.advisor_id = (select auth.uid()) and b.client_id = profiles.id)
         or (b.client_id = (select auth.uid()) and b.advisor_id = profiles.id)
    )
  );

-- SB004: users could update their own `role` and make themselves admin.
-- Only name and phone are editable by users; role changes go through the service role.
drop policy "Users can update their own profile" on public.profiles;

revoke update on public.profiles from anon, authenticated;
grant update (full_name, phone) on public.profiles to authenticated;

create policy "Users can update their own profile"
  on public.profiles for update
  to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- SB002 + SB003: any signed-in user could read every message and post as anyone.
drop policy "Signed-in users can read messages" on public.messages;
drop policy "Signed-in users can send messages" on public.messages;

create policy "Booking participants read its messages"
  on public.messages for select
  to authenticated
  using (
    exists (
      select 1 from public.bookings b
      where b.id = booking_id and (select auth.uid()) in (b.advisor_id, b.client_id)
    )
  );

create policy "Booking participants send messages as themselves"
  on public.messages for insert
  to authenticated
  with check (
    sender_id = (select auth.uid())
    and exists (
      select 1 from public.bookings b
      where b.id = booking_id and (select auth.uid()) in (b.advisor_id, b.client_id)
    )
  );

-- SB005: the admin check read user_metadata, which every user can set for themselves.
-- app_metadata can only be set with the service role.
create or replace function public.is_admin()
returns boolean
language sql
stable
set search_path = ''
as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'is_admin')::boolean, false)
$$;

-- SB006 + SB007: anyone could call advisor_revenue for any advisor, bypassing RLS.
-- It now answers only for the calling advisor, and anonymous callers are refused.
create or replace function public.advisor_revenue(advisor uuid)
returns bigint
language sql
security definer
set search_path = ''
as $$
  select coalesce(sum(total_cents), 0)
  from public.bookings
  where advisor_id = advisor and advisor = (select auth.uid())
$$;

revoke execute on function public.advisor_revenue(uuid) from public, anon;
grant execute on function public.advisor_revenue(uuid) to authenticated;

-- SB008: the passports bucket was public. Each client reads and uploads only their own folder.
update storage.buckets set public = false where id = 'passports';

create policy "Clients read their own passport files"
  on storage.objects for select
  to authenticated
  using (bucket_id = 'passports' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "Clients upload to their own passport folder"
  on storage.objects for insert
  to authenticated
  with check (bucket_id = 'passports' and (storage.foldername(name))[1] = (select auth.uid())::text);
