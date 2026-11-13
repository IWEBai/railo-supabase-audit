-- TripNest: a small booking app for travel advisors and their clients.
-- Written for Railo's sample audit in the style an AI app builder generates.
-- It is deliberately insecure. Every mistake here is one that appears in real
-- Lovable/Supabase audit requests. Do not deploy it.

-- Profiles, one per signed-up user.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  email text,
  phone text,
  role text not null default 'client', -- 'client' | 'advisor' | 'admin'
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Profiles are viewable by everyone"
  on public.profiles for select
  using (true);

create policy "Users can update their own profile"
  on public.profiles for update
  using (auth.uid() = id);

-- Create a profile row whenever a user signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, email)
  values (new.id, new.raw_user_meta_data ->> 'full_name', new.email);
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Bookings an advisor makes for a client.
create table public.bookings (
  id bigint generated always as identity primary key,
  advisor_id uuid not null references public.profiles (id),
  client_id uuid not null references public.profiles (id),
  destination text not null,
  passport_number text,
  total_cents integer not null default 0,
  created_at timestamptz not null default now()
);

-- Messages between an advisor and a client about a booking.
create table public.messages (
  id bigint generated always as identity primary key,
  booking_id bigint not null references public.bookings (id) on delete cascade,
  sender_id uuid not null references public.profiles (id),
  body text not null,
  created_at timestamptz not null default now()
);

alter table public.messages enable row level security;

create policy "Signed-in users can read messages"
  on public.messages for select
  to authenticated
  using (true);

create policy "Signed-in users can send messages"
  on public.messages for insert
  to authenticated
  with check (true);

-- Admin check used by the admin dashboard.
create or replace function public.is_admin()
returns boolean
language sql
stable
as $$
  select coalesce((auth.jwt() -> 'user_metadata' ->> 'is_admin')::boolean, false)
$$;

create policy "Admins can delete messages"
  on public.messages for delete
  to authenticated
  using (public.is_admin());

-- Revenue figure for the advisor dashboard.
create or replace function public.advisor_revenue(advisor uuid)
returns bigint
language sql
security definer
as $$
  select coalesce(sum(total_cents), 0) from public.bookings where advisor_id = advisor
$$;

-- Passport scans uploaded by clients.
insert into storage.buckets (id, name, public)
values ('passports', 'passports', true);
