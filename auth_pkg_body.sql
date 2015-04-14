create or replace package body auth_pkg is

/* function for encode password. If you decide to change the ecode method, 
   you just need to change this function. By default it uses 
   dbms_obfuscation_toolkit.md5 function. */
function encode(p_pwd in varchar2) return varchar is
begin
  return dbms_obfuscation_toolkit.md5(input_string => p_pwd);
end;

/* function checks strength of password. Basic check is quite weak
   and simply checks that user's name, email and phone number don't
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

procedure new_user(
    p_username       in varchar2, 
    p_password       in varchar2, 
    p_user_full_name in nvarchar2,
    p_email          in varchar2 default null,
    p_phone          in varchar2 default null,
    p_birth_date     in date default null) is

  en_pwd varchar2(16);
begin
  if p_password is null then
     raise_application_error(-20901, 'Password is empty');
  end if;

  if is_password_weak( p_username, p_password, p_email, p_phone, p_birth_date) then
     raise_application_error(-20902, 'Password too weak');
  end if;
  
  en_pwd := encode(p_password);
  insert into auth_user(user_id, username, user_full_name, pwd, email, phone, birth_date)
  values (auth_seq.nextval, p_username, p_user_full_name, en_pwd, p_email, p_phone, p_birth_date);

  exception
    when dup_val_on_index then
      raise_application_error(-20900, 'User already exists');
end;

function check_user(
    p_username in varchar2,
    p_password in varchar2) return boolean is

  cnt    number;
  en_pwd varchar2(16);
begin
  en_pwd := encode(p_password);
  
  select count(*)
    into cnt
    from auth_user
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
  
  update auth_user 
     set pwd = en_pwd,
         change_pwd = 1
   where username = p_username;
  
end;

procedure block_user(p_username in varchar2) is
begin
  update auth_user set is_active = 0 where username = p_username;
end;

procedure unlock_user(p_username in varchar2) is
begin
  update auth_user set is_active = 1 where username = p_username;
end;

procedure change_password(
    p_username     in varchar2,
    p_old_password in varchar2, 
    p_new_password in varchar2) is

  user_email auth_user.email%type;
  user_phone auth_user.phone%type;
  user_bdate auth_user.birth_date%type;
  en_pwd     varchar2(16);
begin
  en_pwd := encode(p_old_password);

  select email, phone, birth_date
    into user_email, user_phone, user_bdate
    from auth_user
   where username = p_username
     and pwd = en_pwd
     and is_active = 1;

  if is_password_weak(p_username, p_new_password, user_email, user_phone, user_bdate) then
     raise_application_error(-20902, 'Password too weak');
  else
     update auth_user
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

end auth_pkg;
/