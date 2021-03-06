-- Oracle Application Express 4.2
-- Database objects for custom authentication scheme
-- script for objects generation

create user &&USER identified by &&PASSWORD default tablespace &&tablespace;

grant connect to &&USER;
grant resource to &&USER;
grant create view to &&USER;
grant create procedure to &&USER;
grant unlimited tablespace to &&USER;

connect &&USER/&&PASSWORD

-- sequence for authentication
create sequence auth_seq;

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

comment on table  deputy            is 'Table allows users to temporarily get privileges of another user';
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
  description    varchar2(1000));

alter table apex_role add constraint role_pk      primary key (role_id);
alter table apex_role add constraint role_name_uq unique (role_name);
alter table apex_role add constraint parent_role  foreign key (parent_id) references apex_role (role_id);

comment on table  apex_role             is 'hierarchical table of roles for RBAC model';
comment on column apex_role.role_id     is 'primary key';
comment on column apex_role.parent_id   is 'parent role (higher level for combine multiple roles)';
comment on column apex_role.role_name   is 'name of role for displaying in interface';
comment on column apex_role.description is 'description of a role';

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
  description     varchar2(1000));

alter table permission add constraint permission_pk      primary key (permission_id);
alter table permission add constraint permission_name_uq unique (permission_name);

comment on table  permission                 is 'table of permissions for RBAC model';
comment on column permission.permission_id   is 'primary key';
comment on column permission.permission_name is 'name of permission for displaying in interface';
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

comment on table  user_role              is 'joining users and roles';
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

create table attribute(
  attribute_id   number,
  attribute_name varchar2(100),
  description    varchar2(1000));

alter table attribute add constraint attribute_pk primary key (attribute_id);
alter table attribute add constraint attribute_uq unique (attribute_name);

comment on table  attribute                is 'table for attributes for ABAC model';
comment on column attribute.attribute_id   is 'primary key';
comment on column attribute.attribute_name is 'name of an attribute';
comment on column attribute.description    is 'description of an attribute';

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

create table application_settings(
  code varchar2(50),
  text_val varchar2(4000),
  date_val date,
  numb_val number
);

alter table application_settings add constraint code_pk primary key (code);

comment on table  application_settings                is 'table stores a number of text lines used in application';
comment on column application_settings.code           is 'setting name';
comment on column application_settings.text_val       is 'setting text value';
comment on column application_settings.date_val       is 'setting date value';
comment on column application_settings.numb_val       is 'setting number value';

@auth_pkg.sql;

@auth_pkg_body.sql;

@app_init.sql;

show errors
quit
/