-- sequence for authentication
create sequence auth_seq;

-- table for applications
create table application(
application_id   number,
application_name varchar2(100));

alter table application add constraint application_pk primary key (application_id);
alter table application add constraint application_name_uq unique (application_name);

comment on table  application                  is 'list of installed applications';
comment on column application.application_id   is 'primary key, equal to application ID in APEX';
comment on column application.application_name is 'name of application';

-- table for users
create table apex_user(
  user_id        number,
  username       varchar2(100),
  user_full_name nvarchar2(200),
  pwd            varchar2(16),
  email          varchar2(255),
  phone          varchar2(20),
  birth_date     date,
  change_pwd     number default 0,
  is_active      number default 1);

alter table apex_user add constraint user_pk primary key (user_id);
alter table apex_user add constraint username_uq unique (username);
alter table apex_user add constraint user_activity check (is_active in (0, 1));
alter table apex_user add constraint change_pwd_after_login check (change_pwd in (0, 1));

comment on table  apex_user                is 'users with permission to APEX application';
comment on column apex_user.user_id        is 'primary key';
comment on column apex_user.username       is 'user''s name for login';
comment on column apex_user.user_full_name is 'full user''s name for output';
comment on column apex_user.pwd            is 'MD5 encripted password';
comment on column apex_user.email          is 'email for subscription';
comment on column apex_user.phone          is 'user''s phone number';
comment on column apex_user.birth_date     is 'user''s birth date';
comment on column apex_user.change_pwd     is '0 - do not change login; 1 - change after next login';
comment on column apex_user.is_active      is '0 - user is blocked; 1 - user is active';

create or replace trigger bi_apex_user
before insert on apex_user
for each row
begin
  if :new.user_id is null then
     :new.user_id := auth_seq.nextval;
  end if;
end;
/

-- table for deputies
create table deputy(
  deputy_id  number,
  user_id    number,
  deputy_of  number,
  start_date date,
  end_date   date);

alter table deputy add constraint deputy_pk primary key (deputy_id);
alter table deputy add constraint user_fk       foreign key (user_id)   references apex_user (user_id);
alter table deputy add constraint replaced_user foreign key (deputy_of) references apex_user (user_id);

comment on table  deputy is 'Table allows users to temporarily get privileges of another user';
comment on column deputy.deputy_id  is 'primary key';
comment on column deputy.user_id    is 'User who temporarily got privileges of another user';
comment on column deputy.deputy_of  is 'User who is temporarily replaced';
comment on column deputy.start_date is 'Start date of having privileges of another user';
comment on column deputy.end_date   is 'End date of having privileges of another user';

create or replace trigger bi_deputy
before insert on deputy
for each row
begin
  if :new.deputy_id is null then
     :new.deputy_id := auth_seq.nextval;
  end if;
end;
/

-- table for roles
create table apex_role(
  role_id        number,
  parent_id      number,
  role_name      nvarchar2(100),
  application_id number,
  description    varchar2(1000));

alter table apex_role add constraint role_pk          primary key (role_id);
alter table apex_role add constraint role_name_uq     unique (role_name, application_id);
alter table apex_role add constraint parent_role      foreign key (parent_id)      references apex_role (role_id);
alter table apex_role add constraint r_application_fk foreign key (application_id) references application (application_id);

comment on table  apex_role                is 'hierarchical table of roles for RBAC model';
comment on column apex_role.role_id        is 'primary key';
comment on column apex_role.parent_id      is 'parent role (higher level for combine multiple roles)';
comment on column apex_role.role_name      is 'name of role for displaying in interface';
comment on column apex_role.application_id is 'number of application where this role is used';
comment on column apex_role.description    is 'description of a role';

create or replace trigger bi_role
before insert on apex_role
for each row
begin
  if :new.role_id is null then
     :new.role_id := auth_seq.nextval;
  end if;
end;
/

-- table for permissions
create table permission(
  permission_id   number,
  permission_name nvarchar2(100),
  application_id  number,
  description     varchar2(1000));

alter table permission add constraint permission_pk      primary key (permission_id);
alter table permission add constraint permission_name_uq unique (permission_name, application_id);
alter table permission add constraint application_id     foreign key (application_id) references application (application_id);

comment on table  permission                 is 'table of permissions for RBAC model';
comment on column permission.permission_id   is 'primary key';
comment on column permission.permission_name is 'name of permission for displaying in interface';
comment on column permission.application_id  is 'number of application where this permission is used';
comment on column permission.description     is 'description of a permission';

create or replace trigger bi_permission
before insert on permission
for each row
begin
  if :new.permission_id is null then
     :new.permission_id := auth_seq.nextval;
  end if;
end;
/

-- table for joining users and roles
create table user_role(
  user_role_id number,
  user_id      number,
  role_id      number,
  start_date   date,
  end_date     date);

alter table user_role add constraint user_role_pk primary key (user_role_id);
alter table user_role add constraint ur_user_fk   foreign key (user_id) references apex_user (user_id);
alter table user_role add constraint ur_role_fk   foreign key (role_id) references apex_role (role_id);

comment on table  user_role is 'joining users and roles';
comment on column user_role.user_role_id is 'primary key';
comment on column user_role.user_id      is 'reference to user';
comment on column user_role.role_id      is 'reference to role';
comment on column user_role.start_date   is 'date when user receives role';
comment on column user_role.end_date     is 'date when role revokes from user';

create or replace trigger bi_user_role
before insert on user_role
for each row
begin
  if :new.user_role_id is null then
     :new.user_role_id := auth_seq.nextval;
  end if;
end;
/

-- table for joining permissions and roles
create table role_permission(
  role_permission_id number,
  role_id            number,
  permission_id      number,
  start_date         date,
  end_date           date);

alter table role_permission add constraint role_permission_pk primary key (role_permission_id);
alter table role_permission add constraint rp_role_fk         foreign key (role_id)       references apex_role (role_id);
alter table role_permission add constraint rp_permission_fk   foreign key (permission_id) references permission (permission_id);

comment on table  role_permission                    is 'joining roles and permissions';
comment on column role_permission.role_permission_id is 'primary key';
comment on column role_permission.role_id            is 'reference to role';
comment on column role_permission.permission_id      is 'reference to permission';
comment on column role_permission.start_date         is 'date when role receives permission';
comment on column role_permission.end_date           is 'date when permission revokes from role';

create or replace trigger bi_role_permission
before insert on role_permission
for each row
begin
  if :new.role_permission_id is null then
     :new.role_permission_id := auth_seq.nextval;
  end if;
end;
/

-- table for joining permissions and users
create table user_permission(
  user_permission_id number,
  user_id            number,
  permission_id      number,
  start_date         date,
  end_date           date);

alter table user_permission add constraint user_permission_pk primary key (user_permission_id);
alter table user_permission add constraint up_user_fk         foreign key (user_id)       references apex_user (user_id);
alter table user_permission add constraint up_permission_fk   foreign key (permission_id) references permission (permission_id);

comment on table  user_permission                    is 'joining users and roles';
comment on column user_permission.user_permission_id is 'primary key';
comment on column user_permission.user_id            is 'reference to user';
comment on column user_permission.permission_id      is 'reference to permission';
comment on column role_permission.start_date         is 'date when role receives permission';
comment on column role_permission.end_date           is 'date when permission revokes from role';

create or replace trigger bi_user_permission
before insert on user_permission
for each row
begin
  if :new.user_permission_id is null then
     :new.user_permission_id := auth_seq.nextval;
  end if;
end;
/

-- table for joining users and applications
create table user_application(
  user_application_id number,
  user_id             number,
  application_id      number,
  start_date          date,
  end_date            date);

alter table user_application add constraint user_application_pk primary key (user_application_id);
alter table user_application add constraint ua_user_fk          foreign key (user_id) references apex_user(user_id);
alter table user_application add constraint ua_application_id   foreign key (application_id) references application (application_id);

comment on table  user_application                     is 'table defines which user has access to which application';
comment on column user_application.user_application_id is 'primary key';
comment on column user_application.user_id             is 'reference to user';
comment on column user_application.application_id      is 'reference to application';
comment on column user_application.start_date          is 'date when user receive access to an allication';
comment on column user_application.end_date            is 'date when user''s access to application stops';

create or replace trigger bi_user_application
before insert on user_application
for each row
begin
  if :new.user_application_id is null then
     :new.user_application_id := auth_seq.nextval;
  end if;
end;
/

create table attribute(
  attribute_id   number,
  attribute_name varchar2(100),
  description    varchar2(1000),
  application_id number);

alter table attribute add constraint attribute_pk        primary key (attribute_id);
alter table attribute add constraint attribute_uq        unique (attribute_name, application_id);
alter table attribute add constraint attr_application_fk foreign key (application_id) references application (application_id);

comment on table  attribute                is 'table for attributes for ABAC model';
comment on column attribute.attribute_id   is 'primary key';
comment on column attribute.attribute_name is 'name of an attribute';
comment on column attribute.description    is 'description of an attribute';
comment on column attribute.application_id is 'application where an attribute is used';

create or replace trigger bi_attribute
before insert on attribute
for each row
begin
  if :new.attribute_id is null then
     :new.attribute_id := auth_seq.nextval;
  end if;
end;
/

create table permission_attribute(
  permission_attribute_id number,
  permission_id           number,
  attribute_id            number,
  start_date              date,
  end_date                date);

alter table permission_attribute add constraint permission_attribute_pk primary key (permission_attribute_id);
alter table permission_attribute add constraint pa_permission_fk        foreign key (permission_id) references permission (permission_id);
alter table permission_attribute add constraint pa_attribute_fk         foreign key (attribute_id)  references attribute (attribute_id);

comment on table  permission_attribute                         is 'table defines attributes for permissions';
comment on column permission_attribute.permission_attribute_id is 'primary key';
comment on column permission_attribute.permission_id           is 'reference to a permission';
comment on column permission_attribute.attribute_id            is 'reference to an attribute';
comment on column permission_attribute.start_date              is 'necessity is disputed';
comment on column permission_attribute.end_date                is 'necessity is disputed';

create or replace trigger bi_permission_attribute
before insert on permission_attribute
for each row
begin
  if :new.permission_attribute_id is null then
     :new.permission_attribute_id := auth_seq.nextval;
  end if;
end;
/

create table debug_log(
  log_date      date default sysdate,
  app_user      varchar2(30),
  app_id        number,
  app_page_id   number,
  message_group varchar2(100),
  message       varchar2(4000));

create or replace package auth_pkg is

user_already_exists exception;
password_is_empty   exception;
password_too_weak   exception;
incorrect_password  exception;

pragma exception_init(user_already_exists, -20900);
pragma exception_init(password_is_empty,   -20901);
pragma exception_init(password_too_weak,   -20902);
pragma exception_init(incorrect_password,  -20903);

letter_text constant varchar2(1000) :=
'Dear %user%!

Someone (may be you) asked as to change your password.
Your new password is: %new_pwd%.
This password is temporary and must be changed after successful login.

With best regards, 
%mail_sender_name%';

/* Function creates new user.
   Checks and raises exceptions if:
   - such user already exists;
   - password is null;
   - password contents login, email or phone number 
   Returns ID of new user
   */
function new_user(
    p_username       in varchar2, 
    p_password       in varchar2, 
    p_user_full_name in nvarchar2 default null,
    p_email          in varchar2  default null,
    p_phone          in varchar2  default null,
    p_birth_date     in date      default null,
    p_app_id         in number    default v('APP_ID')) return number;

/* Function checks login and password. */
function check_user(
    p_username in varchar2,
    p_password in varchar2) return boolean;

/* Procedure for password recovery. User will receive 
   new password on email. */
procedure recover_password(p_username in varchar2);

/* this can be understood without explanations */
procedure block_user(p_username in varchar2);

procedure unlock_user(p_username in varchar2);

procedure change_password(
    p_username     in varchar2,
    p_old_password in varchar2, 
    p_new_password in varchar2);

/* Function checks is current date in desired interval
   a border with NULL value is considered as "no border".
   Returns 1 if current date is inside a given time interval and 0 if not. */
function date_check(
    p_start_date in date,
    p_end_date   in date) return number; 

/* initiates new application and creates:
     - admin user for this application 
     - administration role
     - administration permission
   All default roles and permissions have no time limit. */
procedure init_new_app(
    p_apex_id    in number, 
    p_app_name   in varchar2,
    p_admin_name in varchar2 default null,
    p_admin_pwd  in varchar2 default '987654');

/* logging procedure */
procedure write_to_log(
    p_message_group in varchar2,
    p_message       in varchar2);

/* function checks access for authorization schemes in APEX application */
function authorization_scheme_check(p_authorization_scheme in varchar2) return boolean;

/* function checks build options */
function is_option_included(p_option_name in varchar2) return boolean;

end auth_pkg;
/

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
/