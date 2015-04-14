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

  en_pwd varchar2(16);
  new_user_id number;
begin
  if p_password is null then
     raise_application_error(-20901, 'Password is empty');
  end if;

  if is_password_weak( p_username, p_password, p_email, p_phone, p_birth_date) then
     raise_application_error(-20902, 'Password too weak');
  end if;
  
  en_pwd := encode(p_password, p_username);
  new_user_id := auth_seq.nextval;
  insert into apex_user(user_id, username, user_full_name, pwd, email, phone, birth_date)
  values (new_user_id, p_username, p_user_full_name, en_pwd, p_email, p_phone, p_birth_date);

  insert into user_application (user_application_id, user_id, application_id)
  values (auth_seq.nextval, new_user_id, p_app_id);
  
  return new_user_id;
  exception
    when dup_val_on_index then
      raise_application_error(-20900, 'User "' || p_username || '" already exists');
end;

function check_user(
    p_username in varchar2,
    p_password in varchar2) return boolean is

  cnt    number;
  en_pwd varchar2(16);
begin
  en_pwd := encode(p_password, p_username);
  
  select count(*)
    into cnt
    from apex_user
   where username = p_username
     and pwd = en_pwd
     and is_active = 1;
  
  return cnt > 0;
end;

procedure recover_password(p_username in varchar2) is
  tmp_pwd varchar2(8);
  en_pwd  varchar2(16);
begin
  tmp_pwd := dbms_random.value(8, 'X');
  en_pwd := encode(tmp_pwd);
  
  update apex_user 
     set pwd = en_pwd,
         change_pwd = 1
   where username = p_username;
  
end;

procedure block_user(p_username in varchar2) is
begin
  update apex_user set is_active = 0 where username = p_username;
end;

procedure unlock_user(p_username in varchar2) is
begin
  update apex_user set is_active = 1 where username = p_username;
end;

procedure change_password(
    p_username     in varchar2,
    p_old_password in varchar2, 
    p_new_password in varchar2) is

  user_email apex_user.email%type;
  user_phone apex_user.phone%type;
  user_bdate apex_user.birth_date%type;
  en_pwd     varchar2(16);
begin
  en_pwd := encode(p_old_password);

  select email, phone, birth_date
    into user_email, user_phone, user_bdate
    from apex_user
   where username = p_username
     and pwd = en_pwd
     and is_active = 1;

  if is_password_weak(p_username, p_new_password, user_email, user_phone, user_bdate) then
     raise_application_error(-20902, 'Password too weak');
  else
     update apex_user
        set pwd = en_pwd,
            change_pwd = 0
      where username = p_username;
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
  admin_name := nvl(p_admin_name, ic_default_admin_name || '_' || p_apex_id);
  
  insert into application (application_id, application_name)
  values (p_apex_id, p_app_name);
  
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

end auth_pkg;
/