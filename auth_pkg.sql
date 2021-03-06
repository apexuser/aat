create or replace package auth_pkg is

user_already_exists exception;
password_is_empty   exception;
password_too_weak   exception;
incorrect_password  exception;

pragma exception_init(user_already_exists, -20900);
pragma exception_init(password_is_empty,   -20901);
pragma exception_init(password_too_weak,   -20902);
pragma exception_init(incorrect_password,  -20903);

ic_default_admin_name    constant apex_user.username%type := 'ADMIN';
ic_admin_role            constant apex_role.role_name%type   := 'ADMIN';
ic_admin_role_desc       constant apex_role.description%type := 'Pre-installed administration role.';
ic_admin_permission      constant permission.permission_name%type := 'Administration';
ic_admin_permission_desc constant permission.description%type     := 'Pre-installed permission to administrative section.';

/* Function creates new user.
   Checks and raises exceptions if:
   - such user already exists;
   - password is null;
   - password contents login, email or phone number 
   Returns ID of new user
   */
function new_user (
    p_username       in varchar2, 
    p_password       in varchar2, 
    p_user_full_name in nvarchar2 default null,
    p_email          in varchar2  default null,
    p_phone          in varchar2  default null,
    p_birth_date     in date      default null) return number;

/* Function checks login and password. */
function check_user (
    p_username in varchar2,
    p_password in varchar2) return boolean;

/* Procedure for password recovery. User will receive 
   new password on email. */
procedure recover_password (p_username in varchar2);

/* this can be understood without explanations */
procedure block_user (p_username in varchar2);

procedure unlock_user (p_username in varchar2);

procedure change_password (
    p_username     in varchar2,
    p_old_password in varchar2, 
    p_new_password in varchar2);

/* Function checks is current date in desired interval
   a border with NULL value is considered as "no border".
   Returns 1 if current date is inside a given time interval and 0 if not. */
function date_check (
    p_start_date in date,
    p_end_date   in date) return number; 

/* initiates new application and creates:
     - admin user for this application 
     - administration role
     - administration permission
   All default roles and permissions have no time limit. */
procedure init_new_app (
    p_admin_name in varchar2 default ic_default_admin_name,
    p_admin_pwd  in varchar2 default '987654');

/* logging procedure */
procedure write_to_log (
    p_message_group in varchar2,
    p_message       in varchar2);

/* function checks access for authorization schemes in APEX application */
function authorization_scheme_check (p_authorization_scheme in varchar2) return boolean;

/* function checks build options */
function is_option_included (p_option_name in varchar2) return boolean;

end auth_pkg;
/