declare
  new_app_admin apex_user.username%type := '&&NEW_APPLICATION_ADMIN';
  new_admin_pwd varchar2(100) := '&&NEW_ADMIN_PASSWORD';
begin
  auth_pkg.init_new_app(new_app_admin, new_admin_pwd);
  commit;
end;
/
