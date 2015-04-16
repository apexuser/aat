declare
  new_app_id number := &&NEW_APPLICATION_ID;
  new_app_name application.application_name%type := &&NEW_APPLICATION_NAME;
  new_app_admin apex_user.username%type := &&NEW_APPLICATION_ADMIN;
  new_admin_pwd varchar2(100) := &&NEW_ADMIN_PASSWORD;
begin
  auth_pkg.init_new_app(new_app_id, new_app_name, new_app_admin, new_admin_pwd);
end;
/