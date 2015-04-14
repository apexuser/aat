-- -- package for procedures and functions related to authentication and access management
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

/* Procedure creates new user.
   Checks and raises exceptions if:
   - such user already exists;
   - password is null;
   - password contents login, email or phone number */
procedure new_user(
    p_username       in varchar2, 
    p_password       in varchar2, 
    p_user_full_name in nvarchar2,
    p_email          in varchar2 default null,
    p_phone          in varchar2 default null,
    p_birth_date     in date     default null);

/* Function checks login and password. */
function check_user(
    p_username in varchar2,
    p_password in varchar2) return boolean;

/* Procedure for password recovery. User will receive 
   new password on email. */
procedure recover_password(p_username in varchar2);

/* this cen be understood without explanations */
procedure block_user(p_username in varchar2);

procedure unlock_user(p_username in varchar2);

procedure change_password(
    p_username     in varchar2,
    p_old_password in varchar2, 
    p_new_password in varchar2);

/* function checks is current date in desired interval
   a border with NULL value is considered as "no border" */
function date_check(
    p_start_date in date,
    p_end_date   in date) return number; 

end auth_pkg;
/