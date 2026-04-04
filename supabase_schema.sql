-- Supabase Initial Schema Setup for VulnScout Pro
-- Run this code exactly as-is in your Supabase project's SQL Editor!

-- 1. Create a public profiles table that links to Supabase's internal auth.users table
create table public.profiles (
  id uuid references auth.users not null primary key,
  email text not null,
  full_name text,
  role text default 'analyst' not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- 2. Turn on Row Level Security (RLS) to keep data secure natively
alter table public.profiles enable row level security;

-- 3. Setup RLS Policies 
-- Policy: Users can view their own profile.
create policy "Users can view their own profile."
  on profiles for select
  using ( auth.uid() = id );

-- Policy: Users can update their own profile.
create policy "Users can update their own profile."
  on profiles for update
  using ( auth.uid() = id );

-- Optional Admin Policy: Admins can view/edit all profiles
-- create policy "Admins can view all profiles"
--   on profiles for all
--   using ( (select role from profiles where id = auth.uid()) = 'admin' );

-- 4. Create a Postgres function to automatically handle new signups
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, role)
  values (
    new.id,
    new.email,
    new.raw_user_meta_data->>'full_name',
    coalesce(new.raw_user_meta_data->>'role', 'analyst')
  );
  return new;
end;
$$;

-- 5. Create a trigger that calls the function whenever a new user registers across the system
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- 6. Keep 'updated_at' synced automatically
create or replace function public.handle_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger auto_update_profiles_timestamp
  before update on public.profiles
  for each row execute procedure public.handle_updated_at();
