-- BUTDETAL shared workspace: run in Supabase SQL Editor.
-- Create the first auth user in Supabase Auth, then promote it to admin with the UPDATE below.

create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'colleague' check (role in ('admin','colleague')),
  display_name text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles(user_id, role, display_name)
  values (new.id, 'colleague', coalesce(new.raw_user_meta_data->>'display_name',''));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_butdetal on auth.users;
create trigger on_auth_user_created_butdetal
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_butdetal_admin()
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where user_id = auth.uid() and role = 'admin'
  );
$$;

create table if not exists public.shared_records (
  id text primary key,
  record_type text not null check (record_type in ('product','standard','formula','table')),
  data jsonb not null,
  updated_by uuid not null references auth.users(id),
  updated_by_name text not null default '',
  updated_at timestamptz not null default now()
);

create table if not exists public.shared_files (
  id text primary key,
  folder text not null check (folder in ('products','drawings')),
  storage_path text not null unique,
  title text not null default '',
  notes text not null default '',
  linked_record_id text,
  updated_by uuid not null references auth.users(id),
  updated_by_name text not null default '',
  updated_at timestamptz not null default now()
);

create table if not exists public.change_log (
  id bigint generated always as identity primary key,
  table_name text not null,
  record_id text not null,
  action text not null check (action in ('INSERT','UPDATE','DELETE')),
  actor_user_id uuid,
  actor_name text not null default '',
  changed_at timestamptz not null default now(),
  old_data jsonb,
  new_data jsonb
);

alter table public.profiles enable row level security;
alter table public.shared_records enable row level security;
alter table public.shared_files enable row level security;
alter table public.change_log enable row level security;

drop policy if exists "profile self or admin read" on public.profiles;
create policy "profile self or admin read" on public.profiles
for select to authenticated using (user_id = auth.uid() or public.is_butdetal_admin());

drop policy if exists "admin updates profiles" on public.profiles;
create policy "admin updates profiles" on public.profiles
for update to authenticated using (public.is_butdetal_admin()) with check (public.is_butdetal_admin());

drop policy if exists "authenticated read shared records" on public.shared_records;
create policy "authenticated read shared records" on public.shared_records
for select to authenticated using (true);
drop policy if exists "authenticated insert shared records" on public.shared_records;
create policy "authenticated insert shared records" on public.shared_records
for insert to authenticated with check (updated_by = auth.uid());
drop policy if exists "authenticated update shared records" on public.shared_records;
create policy "authenticated update shared records" on public.shared_records
for update to authenticated using (true) with check (updated_by = auth.uid());
drop policy if exists "authenticated delete shared records" on public.shared_records;
create policy "authenticated delete shared records" on public.shared_records
for delete to authenticated using (true);

drop policy if exists "authenticated read shared files" on public.shared_files;
create policy "authenticated read shared files" on public.shared_files
for select to authenticated using (true);
drop policy if exists "authenticated insert shared files" on public.shared_files;
create policy "authenticated insert shared files" on public.shared_files
for insert to authenticated with check (updated_by = auth.uid());
drop policy if exists "authenticated update shared files" on public.shared_files;
create policy "authenticated update shared files" on public.shared_files
for update to authenticated using (true) with check (updated_by = auth.uid());
drop policy if exists "authenticated delete shared files" on public.shared_files;
create policy "authenticated delete shared files" on public.shared_files
for delete to authenticated using (true);

drop policy if exists "authenticated read change log" on public.change_log;
create policy "authenticated read change log" on public.change_log
for select to authenticated using (true);

create or replace function public.log_shared_record_change()
returns trigger language plpgsql security definer set search_path = public
as $$
declare
  row_data jsonb;
  who uuid;
  who_name text;
  rid text;
begin
  if TG_OP = 'DELETE' then
    row_data := to_jsonb(OLD);
    who := auth.uid();
    who_name := coalesce(row_data->>'updated_by_name','');
    rid := OLD.id;
    insert into public.change_log(table_name,record_id,action,actor_user_id,actor_name,old_data)
    values (TG_TABLE_NAME,rid,TG_OP,who,who_name,row_data);
    return OLD;
  else
    row_data := to_jsonb(NEW);
    who := auth.uid();
    who_name := coalesce(row_data->>'updated_by_name','');
    rid := NEW.id;
    insert into public.change_log(table_name,record_id,action,actor_user_id,actor_name,old_data,new_data)
    values (TG_TABLE_NAME,rid,TG_OP,who,who_name,case when TG_OP='UPDATE' then to_jsonb(OLD) else null end,row_data);
    return NEW;
  end if;
end;
$$;

drop trigger if exists shared_records_audit on public.shared_records;
create trigger shared_records_audit after insert or update or delete on public.shared_records
for each row execute procedure public.log_shared_record_change();
drop trigger if exists shared_files_audit on public.shared_files;
create trigger shared_files_audit after insert or update or delete on public.shared_files
for each row execute procedure public.log_shared_record_change();

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('butdetal-shared','butdetal-shared',false,26214400,array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

drop policy if exists "BUTDETAL members read files" on storage.objects;
create policy "BUTDETAL members read files" on storage.objects
for select to authenticated using (bucket_id = 'butdetal-shared');
drop policy if exists "BUTDETAL members upload files" on storage.objects;
create policy "BUTDETAL members upload files" on storage.objects
for insert to authenticated with check (bucket_id = 'butdetal-shared');
drop policy if exists "BUTDETAL members update files" on storage.objects;
create policy "BUTDETAL members update files" on storage.objects
for update to authenticated using (bucket_id = 'butdetal-shared') with check (bucket_id = 'butdetal-shared');
drop policy if exists "BUTDETAL members delete files" on storage.objects;
create policy "BUTDETAL members delete files" on storage.objects
for delete to authenticated using (bucket_id = 'butdetal-shared');

-- After creating the administrator account in Supabase Auth, run:
-- update public.profiles set role = 'admin', display_name = 'Адміністратор'
-- where user_id = (select id from auth.users where email = 'ADMIN_LOGIN_EMAIL');
