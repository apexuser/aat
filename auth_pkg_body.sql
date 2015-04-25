create or replace package body auth_pkg is

  ic_default_admin_name constant apex_user.username%type := 'ADMIN';
  ic_admin_role      constant apex_role.role_name%type   := 'ADMIN';
  ic_admin_role_desc constant apex_role.description%type := 'Pre-installed administration role.';

  ic_admin_permission      constant permission.permission_name%type := 'Administration';
  ic_admin_permission_desc constant permission.description%type     := 'Pre-installed permission to administrative section.';

/* function for encode password. If you decide to change the encode method, 
   you just need to change this function. By default it uses 
   dbms_obfuscation_toolkit.md5 function. */
function encode(p_pwd in varchar2, p_salt in varchar2 default null) return varchar2 is
begin
  write_to_log('ENCODE', ' p_pwd = ' || p_pwd || ' p_salt = ' || p_salt || ' hash = ' || dbms_obfuscation_toolkit.md5(input_string => p_pwd || p_salt));
  return dbms_obfuscation_toolkit.md5(input_string => p_pwd || p_salt);
end;

/* function checks strength of password. Basic check is quite weak
   and simply checks that user's name, email, birth date and phone number don't
   included into a passwrd. */
function is_password_weak(    
    p_username       in varchar2,
    p_password       in varchar2,
    p_email          in varchar2,
    p_phone          in varchar2,
    p_birth_date     in date) return boolean is

begin
  return instr(upper(p_password), upper(p_username)) > 0 or
         instr(upper(p_password), upper(p_email)) > 0 or
         instr(upper(p_password), upper(p_phone)) > 0 or
         instr(upper(p_password), upper(to_char(p_birth_date, 'dd.mm.yyyy'))) > 0;
end;

function new_user(
    p_username       in varchar2, 
    p_password       in varchar2, 
    p_user_full_name in nvarchar2 default null,
    p_email          in varchar2  default null,
    p_phone          in varchar2  default null,
    p_birth_date     in date      default null,
    p_app_id         in number    default v('APP_ID')) return number is

  en_pwd apex_user.pwd%type;
  new_user_id number;
  db_username apex_user.username%type;
begin
  db_username := upper(p_username);

  if p_password is null then
     raise_application_error(-20901, 'Password is empty');
  end if;

  if is_password_weak( db_username, p_password, p_email, p_phone, p_birth_date) then
     raise_application_error(-20902, 'Password too weak');
  end if;
  
  write_to_log('NEW_USER', 'p_username = ' || db_username || ' p_password = ' || p_password);

  en_pwd := encode(p_password, db_username);
  new_user_id := auth_seq.nextval;
  insert into apex_user(user_id, username, user_full_name, pwd, email, phone, birth_date)
  values (new_user_id, db_username, p_user_full_name, en_pwd, p_email, p_phone, p_birth_date);

  insert into user_application (user_application_id, user_id, application_id)
  values (auth_seq.nextval, new_user_id, p_app_id);
  
  return new_user_id;
  exception
    when dup_val_on_index then
      raise_application_error(-20900, 'User "' || db_username || '" already exists');
end;

function check_user(
    p_username in varchar2,
    p_password in varchar2) return boolean is

  cnt    number;
  en_pwd apex_user.pwd%type;
  db_username apex_user.username%type;
begin
  db_username := upper(p_username);
  write_to_log('CHECK_USER', 'p_username = ' || db_username || ' p_password = ' || p_password);
  en_pwd := encode(p_password, db_username);
  
  select count(*)
    into cnt
    from apex_user
   where username = db_username
     and pwd = en_pwd
     and is_active = 1;
  
  return cnt > 0;
end;

procedure recover_password(p_username in varchar2) is
  tmp_pwd     varchar2(8);
  en_pwd      apex_user.pwd%type;
  db_username apex_user.username%type;
begin
  tmp_pwd := dbms_random.value(8, 'X');
  db_username := upper(p_username);
  en_pwd := encode(tmp_pwd, db_username);
  
  update apex_user 
     set pwd = en_pwd,
         change_pwd = 1
   where username = db_username;
  
end;

procedure block_user(p_username in varchar2) is
  db_username apex_user.username%type;
begin
  db_username := upper(p_username);
  update apex_user set is_active = 0 where username = db_username;
end;

procedure unlock_user(p_username in varchar2) is
  db_username apex_user.username%type;
begin
  db_username := upper(p_username);
  update apex_user set is_active = 1 where username = db_username;
end;

procedure change_password(
    p_username     in varchar2,
    p_old_password in varchar2, 
    p_new_password in varchar2) is

  user_email  apex_user.email%type;
  user_phone  apex_user.phone%type;
  user_bdate  apex_user.birth_date%type;
  en_pwd      apex_user.pwd%type;
  db_username apex_user.username%type;
begin
  db_username := upper(p_username);
  en_pwd := encode(p_old_password, db_username);

  select email, phone, birth_date
    into user_email, user_phone, user_bdate
    from apex_user
   where username = db_username
     and pwd = en_pwd
     and is_active = 1;

  if is_password_weak(db_username, p_new_password, user_email, user_phone, user_bdate) then
     raise_application_error(-20902, 'Password too weak');
  else
     update apex_user
        set pwd = en_pwd,
            change_pwd = 0
      where username = db_username;
  end if;
  
  exception
    when no_data_found then
      raise_application_error(-20903, 'Incorrect password');
end;

/* date_check */
function date_check(
    p_start_date in date,
    p_end_date   in date) return number is
begin
  return case when sysdate > nvl(p_start_date, sysdate - 1)
               and sysdate < nvl(p_end_date,   sysdate + 1) 
           then 1
           else 0 end;
end;

procedure init_new_app(
    p_apex_id    in number, 
    p_app_name   in varchar2,
    p_admin_name in varchar2 default null,
    p_admin_pwd  in varchar2 default '987654') is

  admin_id   apex_user.user_id%type;
  admin_name apex_user.username%type;

  default_permission_id permission.permission_id%type;
  default_role_id       apex_role.role_id%type;
begin
  admin_name := upper(nvl(p_admin_name, ic_default_admin_name || '_' || p_apex_id));
  
  insert into application (application_id, application_name)
  values (p_apex_id, p_app_name);
  
  write_to_log('INIT_NEW_APP', 'admin_name = ' || admin_name || ' p_admin_pwd = ' || p_admin_pwd);
  
  admin_id := new_user(
                p_username => admin_name, 
                p_password => p_admin_pwd, 
                p_app_id   => p_apex_id);
    
  insert into apex_role (role_id, role_name, description, application_id)
  values (auth_seq.nextval, ic_admin_role, ic_admin_role_desc, p_apex_id)
  returning role_id into default_role_id;
  
  insert into permission (permission_id, permission_name, description, application_id)
  values (auth_seq.nextval, ic_admin_permission, ic_admin_permission_desc, p_apex_id)
  returning permission_id into default_permission_id;
  
  insert into user_permission (user_permission_id, user_id, permission_id)
  values (auth_seq.nextval, admin_id, default_permission_id);
  
  insert into user_role (user_role_id, user_id, role_id)
  values (auth_seq.nextval, admin_id, default_role_id);
  
  insert into role_permission (role_permission_id, role_id, permission_id)
  values (auth_seq.nextval, default_role_id, default_permission_id);
end;

procedure write_to_log(
    p_message_group in varchar2,
    p_message       in varchar2) is
  pragma autonomous_transaction;
begin
  insert into debug_log(app_user, app_id, app_page_id, message_group, message)
  values (v('APP_USER'), nv('APP_ID'), nv('APP_PAGE_ID'), p_message_group, p_message);
  commit;
end;

function authorization_scheme_check(p_authorization_scheme in varchar2) return boolean is
  res number;
begin
  with simple_scheme as (
       -- subquery #1 - direct connection users to permissions
       select username, permission_name
         from apex_user au,
              permission p,
              user_permission up
        where au.user_id = up.user_id
          and up.permission_id = p.permission_id
          and date_check(up.start_date, up.end_date) = 1
          and p.application_id = nv('APP_ID')
          and au.username = v('APP_USER')
          and p.permission_name = p_authorization_scheme),
       rbac_scheme as (
       -- subquery #2 - connection through roles
       select username, permission_name
         from apex_user au,
              user_role ur,
              role_permission rp,
              permission p,
              apex_role ar
        where au.user_id = ur.user_id
          and ur.role_id = rp.role_id
          and ar.role_id = ur.role_id
          and rp.permission_id = p.permission_id
          and date_check(ur.start_date, ur.end_date) = 1
          and date_check(rp.start_date, rp.end_date) = 1
          and ar.application_id = nv('APP_ID')
          and  p.application_id = nv('APP_ID')
          and au.username = v('APP_USER')
          and p.permission_name = p_authorization_scheme),
       simple_deputy as (
       -- subquery #3 - direct connection users to permissions
       -- check when user is someone's deputy
       select username, permission_name
         from apex_user au,
              permission p,
              user_permission up,
              deputy d
        where au.user_id = d.user_id
          and d.deputy_of = up.user_id
          and up.permission_id = p.permission_id
          and date_check(up.start_date, up.end_date) = 1
          and p.application_id = nv('APP_ID')
          and au.username = v('APP_USER')
          and p.permission_name = p_authorization_scheme),
       -- subquery #4 - connection through roles
       -- check when user is someone's deputy
       rbac_deputy as (
       select username, permission_name
         from apex_user au,
              user_role ur,
              role_permission rp,
              permission p,
              apex_role ar,
              deputy d
        where au.user_id = d.user_id
          and ur.user_id = d.deputy_of
          and ur.role_id = rp.role_id
          and ar.role_id = ur.role_id
          and rp.permission_id = p.permission_id
          and date_check(ur.start_date, ur.end_date) = 1
          and date_check(rp.start_date, rp.end_date) = 1
          and ar.application_id = nv('APP_ID')
          and  p.application_id = nv('APP_ID')
          and au.username = v('APP_USER')
          and p.permission_name = p_authorization_scheme)
  select count(*)
    into res
    from (select *
            from simple_scheme
           union all
          select *
            from rbac_scheme
           union all
          select username, permission_name
            from simple_deputy
           union all
          select username, permission_name
            from rbac_deputy);
    
  return res > 0;
end;

function is_option_included(p_option_name in varchar2) return boolean is

  cnt number;
begin
  select count(*)
    into cnt
    from apex_application_build_options
   where application_id = nv('APP_ID')
     and build_option_name = p_option_name
     and upper(build_option_status) = 'INCLUDE';

  return cnt > 0;
end;

end auth_pkg;