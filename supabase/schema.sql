-- Ecole9: initial secure data model for Supabase PostgreSQL
-- Apply in Supabase SQL Editor. Review policies before using real student data.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null,
  role text not null check (role in ('director','counselor','intendant','supervisor','teacher','parent')),
  created_at timestamptz not null default now()
);

create table if not exists public.students (
  id uuid primary key default gen_random_uuid(),
  student_code text unique,
  full_name text not null,
  class_name text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.teacher_assignments (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references public.profiles(id) on delete cascade,
  class_name text not null,
  created_at timestamptz not null default now(),
  unique (teacher_id, class_name)
);

create table if not exists public.parent_students (
  id uuid primary key default gen_random_uuid(),
  parent_id uuid not null references public.profiles(id) on delete cascade,
  student_id uuid not null references public.students(id) on delete cascade,
  relationship text,
  created_at timestamptz not null default now(),
  unique (parent_id, student_id)
);

create table if not exists public.attendance_records (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  record_date date not null default current_date,
  status text not null check (status in ('present','absent','late','excused')),
  note text,
  created_by uuid not null references public.profiles(id),
  created_at timestamptz not null default now()
);

create index if not exists idx_students_class on public.students(class_name);
create index if not exists idx_teacher_assignments_teacher on public.teacher_assignments(teacher_id);
create index if not exists idx_parent_students_parent on public.parent_students(parent_id);
create index if not exists idx_parent_students_student on public.parent_students(student_id);
create index if not exists idx_attendance_student_date on public.attendance_records(student_id, record_date desc);

-- Security-definer helpers prevent recursive RLS policy evaluation.
create or replace function public.current_user_role()
returns text
language sql stable security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.is_school_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select coalesce(public.current_user_role() = 'director', false)
$$;

create or replace function public.can_access_student(target_student uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select
    public.is_school_admin()
    or exists (
      select 1 from public.parent_students ps
      where ps.parent_id = auth.uid() and ps.student_id = target_student
    )
    or exists (
      select 1
      from public.students s
      join public.teacher_assignments ta on ta.class_name = s.class_name
      where s.id = target_student and ta.teacher_id = auth.uid()
    )
    or public.current_user_role() in ('counselor','intendant','supervisor')
$$;

alter table public.profiles enable row level security;
alter table public.students enable row level security;
alter table public.teacher_assignments enable row level security;
alter table public.parent_students enable row level security;
alter table public.attendance_records enable row level security;

-- Profiles: users can see their own profile; director can administer all profiles.
drop policy if exists "profiles_select_self_or_director" on public.profiles;
create policy "profiles_select_self_or_director" on public.profiles
for select to authenticated
using (id = auth.uid() or public.is_school_admin());

drop policy if exists "profiles_director_manage" on public.profiles;
create policy "profiles_director_manage" on public.profiles
for all to authenticated
using (public.is_school_admin())
with check (public.is_school_admin());

-- Students: parents see linked children; teachers see assigned classes;
-- designated school staff and director can see school student records.
drop policy if exists "students_read_scoped" on public.students;
create policy "students_read_scoped" on public.students
for select to authenticated
using (public.can_access_student(id));

drop policy if exists "students_director_manage" on public.students;
create policy "students_director_manage" on public.students
for all to authenticated
using (public.is_school_admin())
with check (public.is_school_admin());

-- Assignments and family links are administered by director.
drop policy if exists "teacher_assignments_read_scoped" on public.teacher_assignments;
create policy "teacher_assignments_read_scoped" on public.teacher_assignments
for select to authenticated
using (teacher_id = auth.uid() or public.is_school_admin());

drop policy if exists "teacher_assignments_director_manage" on public.teacher_assignments;
create policy "teacher_assignments_director_manage" on public.teacher_assignments
for all to authenticated
using (public.is_school_admin())
with check (public.is_school_admin());

drop policy if exists "parent_students_read_scoped" on public.parent_students;
create policy "parent_students_read_scoped" on public.parent_students
for select to authenticated
using (parent_id = auth.uid() or public.is_school_admin());

drop policy if exists "parent_students_director_manage" on public.parent_students;
create policy "parent_students_director_manage" on public.parent_students
for all to authenticated
using (public.is_school_admin())
with check (public.is_school_admin());

-- Attendance: visible only to people allowed to see that student.
drop policy if exists "attendance_read_scoped" on public.attendance_records;
create policy "attendance_read_scoped" on public.attendance_records
for select to authenticated
using (public.can_access_student(student_id));

drop policy if exists "attendance_insert_scoped" on public.attendance_records;
create policy "attendance_insert_scoped" on public.attendance_records
for insert to authenticated
with check (
  created_by = auth.uid()
  and public.can_access_student(student_id)
  and public.current_user_role() in ('director','counselor','intendant','supervisor','teacher')
);

drop policy if exists "attendance_update_scoped" on public.attendance_records;
create policy "attendance_update_scoped" on public.attendance_records
for update to authenticated
using (
  public.can_access_student(student_id)
  and public.current_user_role() in ('director','counselor','teacher')
)
with check (
  public.can_access_student(student_id)
  and public.current_user_role() in ('director','counselor','teacher')
);

drop policy if exists "attendance_delete_director" on public.attendance_records;
create policy "attendance_delete_director" on public.attendance_records
for delete to authenticated
using (public.is_school_admin());

-- Do not grant anon access. Authenticated access is constrained by RLS.
revoke all on public.profiles, public.students, public.teacher_assignments,
  public.parent_students, public.attendance_records from anon;
grant select, insert, update, delete on public.profiles, public.students,
  public.teacher_assignments, public.parent_students, public.attendance_records
  to authenticated;
